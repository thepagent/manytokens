use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{self, Write};

const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
const AUTHORIZE_URL: &str = "https://auth.openai.com/oauth/authorize";
const TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
const REDIRECT_URI: &str = "http://localhost:1455/auth/callback";
const SCOPE: &str = "openid profile email offline_access";
const JWT_CLAIM_PATH: &str = "https://api.openai.com/auth";



// ── auth-profiles.json schema ────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Default)]
struct AuthProfiles {
    version: u32,
    profiles: HashMap<String, Profile>,
    #[serde(rename = "lastGood")]
    last_good: HashMap<String, String>,
    #[serde(rename = "usageStats")]
    usage_stats: HashMap<String, UsageStat>,
}

#[derive(Serialize, Deserialize)]
struct Profile {
    #[serde(rename = "type")]
    kind: String,
    provider: String,
    // oauth fields
    #[serde(skip_serializing_if = "Option::is_none")]
    access: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires: Option<u64>,
    // api_key fields
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "baseUrl")]
    base_url: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
struct UsageStat {
    #[serde(rename = "lastUsed")]
    last_used: u64,
    #[serde(rename = "errorCount")]
    error_count: u32,
}

// ── OAuth helpers ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
}

fn random_bytes_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

fn generate_pkce() -> (String, String) {
    let mut bytes = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let verifier = URL_SAFE_NO_PAD.encode(&bytes);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

fn build_authorize_url(challenge: &str, state: &str) -> String {
    let params = [
        ("response_type", "code"),
        ("client_id", CLIENT_ID),
        ("redirect_uri", REDIRECT_URI),
        ("scope", SCOPE),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
        ("state", state),
        ("id_token_add_organizations", "true"),
        ("codex_cli_simplified_flow", "true"),
        ("originator", "pi"),
    ];
    let qs = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");
    format!("{}?{}", AUTHORIZE_URL, qs)
}

fn parse_callback(input: &str) -> Option<(String, Option<String>)> {
    let input = input.trim();
    if let Ok(url) = url::Url::parse(input) {
        let code = url.query_pairs().find(|(k, _)| k == "code").map(|(_, v)| v.to_string());
        let state = url.query_pairs().find(|(k, _)| k == "state").map(|(_, v)| v.to_string());
        return code.map(|c| (c, state));
    }
    Some((input.to_string(), None))
}

fn decode_jwt_claim(token: &str, claim: &str) -> Option<serde_json::Value> {
    use serde_json::Value;
    let parts: Vec<&str> = token.split('.').collect();
    let payload = parts.get(1)?;
    // JWT uses standard base64url; pad manually
    let padded = {
        let mut s = payload.to_string();
        while s.len() % 4 != 0 { s.push('='); }
        s
    };
    let decoded = base64::engine::general_purpose::URL_SAFE.decode(&padded).ok()?;
    let json: Value = serde_json::from_slice(&decoded).ok()?;
    json.get(claim).cloned()
}

fn get_account_id(access: &str) -> Option<String> {
    let auth = decode_jwt_claim(access, JWT_CLAIM_PATH)?;
    auth.get("chatgpt_account_id")?.as_str().map(|s| s.to_string())
}

fn get_email(access: &str) -> Option<String> {
    let profile = decode_jwt_claim(access, "https://api.openai.com/profile")?;
    profile.get("email")?.as_str().map(|s| s.to_string())
}

fn exchange_code(client: &Client, code: &str, verifier: &str) -> anyhow::Result<TokenResponse> {
    let params = [
        ("grant_type", "authorization_code"),
        ("client_id", CLIENT_ID),
        ("code", code),
        ("code_verifier", verifier),
        ("redirect_uri", REDIRECT_URI),
    ];
    let resp = client.post(TOKEN_URL).form(&params).send()?;
    if !resp.status().is_success() {
        anyhow::bail!("Token exchange failed: {}", resp.text().unwrap_or_default());
    }
    Ok(resp.json()?)
}

fn prompt_line(msg: &str) -> String {
    print!("{}", msg);
    io::stdout().flush().unwrap();
    let mut s = String::new();
    io::stdin().read_line(&mut s).unwrap();
    s.trim().to_string()
}

// ── single OAuth round ────────────────────────────────────────────────────────

struct OAuthResult {
    access: String,
    refresh: String,
    expires: u64,
    account_id: String,
    email: String,
}

fn do_oauth_flow(client: &Client) -> anyhow::Result<OAuthResult> {
    let (verifier, challenge) = generate_pkce();
    let state = random_bytes_hex(16);
    let url = build_authorize_url(&challenge, &state);

    println!("\nOpen this URL in your browser:\n\n{}\n", url);
    let input = prompt_line("Paste the callback URL (or authorization code): ");

    let (code, returned_state) =
        parse_callback(&input).ok_or_else(|| anyhow::anyhow!("Could not parse input"))?;

    if let Some(s) = returned_state {
        if s != state {
            anyhow::bail!("State mismatch — possible CSRF");
        }
    }

    let tok = exchange_code(client, &code, &verifier)?;
    let expires = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        + tok.expires_in * 1000;

    let account_id = get_account_id(&tok.access_token)
        .ok_or_else(|| anyhow::anyhow!("Failed to extract accountId from token"))?;
    let email = get_email(&tok.access_token)
        .ok_or_else(|| anyhow::anyhow!("Failed to extract email from token"))?;

    Ok(OAuthResult {
        access: tok.access_token,
        refresh: tok.refresh_token,
        expires,
        account_id,
        email,
    })
}

// ── load / save auth-profiles.json ───────────────────────────────────────────

fn load_profiles(path: &std::path::Path) -> AuthProfiles {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(AuthProfiles { version: 1, ..Default::default() })
}

fn save_profiles(profiles: &AuthProfiles, path: &std::path::Path) -> anyhow::Result<()> {
    let bak = path.with_extension("json.bak");

    // backup existing
    if path.exists() {
        std::fs::copy(&path, &bak)?;
        println!("Backed up to {}", bak.display());
    }

    let json = serde_json::to_string_pretty(profiles)?;
    std::fs::write(&path, json)?;
    println!("Saved to {}", path.display());
    Ok(())
}

fn refresh_flow(output: &std::path::Path) -> anyhow::Result<()> {
    let client = Client::new();
    let mut profiles = load_profiles(output);
    let mut updated = 0usize;

    for (key, profile) in profiles.profiles.iter_mut() {
        let Some(ref refresh_token) = profile.refresh.clone() else { continue };

        eprint!("Refreshing {} … ", key);
        let params = [
            ("grant_type", "refresh_token"),
            ("client_id", CLIENT_ID),
            ("refresh_token", refresh_token.as_str()),
        ];
        let resp = client.post(TOKEN_URL).form(&params).send()?;
        if !resp.status().is_success() {
            eprintln!("FAILED: {}", resp.text().unwrap_or_default());
            continue;
        }
        let tok: TokenResponse = resp.json()?;
        let expires = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + tok.expires_in * 1000;

        profile.access  = Some(tok.access_token);
        profile.refresh = Some(tok.refresh_token);
        profile.expires = Some(expires);
        eprintln!("OK (expires in {}s)", tok.expires_in);
        updated += 1;
    }

    if updated > 0 {
        save_profiles(&profiles, output)?;
        println!("{} profile(s) refreshed.", updated);
    } else {
        println!("No profiles refreshed.");
    }
    Ok(())
}



fn openai_flow(output: &std::path::Path) -> anyhow::Result<()> {
    let client = Client::new();
    let mut profiles = load_profiles(output);
    let mut added = 0usize;

    loop {
        match do_oauth_flow(&client) {
            Err(e) => eprintln!("OAuth error: {}", e),
            Ok(result) => {
                let key = format!("openai-codex:{}", result.email);
                let is_new = !profiles.profiles.contains_key(&key);

                println!("\n✓ OAuth complete — {} ({})", result.email, result.account_id);
                println!("  profile key: {} ({})", key, if is_new { "new" } else { "updated" });

                profiles.profiles.insert(
                    key.clone(),
                    Profile {
                        kind: "oauth".into(),
                        provider: "openai-codex".into(),
                        access: Some(result.access),
                        refresh: Some(result.refresh),
                        expires: Some(result.expires),
                        key: None,
                        base_url: None,
                    },
                );
                // set as lastGood if first for this provider
                profiles
                    .last_good
                    .entry("openai-codex".into())
                    .or_insert_with(|| key.clone());

                profiles.usage_stats.entry(key).or_default();
                added += 1;
            }
        }

        let ans = prompt_line("\nAdd another token? [y/N]: ");
        if !matches!(ans.to_lowercase().as_str(), "y" | "yes") {
            break;
        }
    }

    if added > 0 {
        save_profiles(&profiles, output)?;
        println!("\nDone. {} profile(s) added.", added);
    } else {
        println!("No profiles added.");
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let output = args.windows(2)
        .find(|w| w[0] == "-o")
        .map(|w| std::path::PathBuf::from(&w[1]))
        .unwrap_or_else(|| std::path::PathBuf::from("auth-profiles.json"));

    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("Usage: manytokens --openai [-o <output>]");
        println!("       manytokens --refresh [-o <input/output>]");
        println!();
        println!("Options:");
        println!("  --openai        Authenticate via OpenAI OAuth (PKCE)");
        println!("  --refresh       Headless token refresh using existing refresh tokens");
        println!("  -o <path>       Path to auth-profiles.json [default: ./auth-profiles.json]");
        println!("  -h, --help      Show this help message");
    } else if args.iter().any(|a| a == "--refresh") {
        if let Err(e) = refresh_flow(&output) {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    } else if args.iter().any(|a| a == "--openai") {
        if let Err(e) = openai_flow(&output) {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    } else {
        eprintln!("Usage: manytokens --openai [-o <output>]");
        eprintln!("       manytokens --refresh [-o <path>]");
        eprintln!("Run with --help for more information.");
        std::process::exit(1);
    }
}
