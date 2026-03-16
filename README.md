# manytokens

A CLI tool to authenticate multiple OpenAI accounts via OAuth (PKCE flow) and store the resulting tokens into an `auth-profiles.json` file used by OpenClaw agents.

## What it does

1. Generates a PKCE challenge and opens an OpenAI OAuth authorization URL in your browser.
2. You paste back the callback URL (or raw authorization code).
3. It exchanges the code for access/refresh tokens, extracts your email and account ID from the JWT, and writes a profile entry to `auth-profiles.json`.
4. Repeat for as many accounts as you need.

## Web UI

A pure client-side version is available at **https://thepagent.github.io/manytokens/**

1. Click "Open OpenAI Login" — a new tab opens the OAuth page
2. Complete login; the browser redirects to `localhost:1455/auth/callback?code=...`
3. Copy the full URL from the address bar and paste it back into the page
4. Click "Exchange Token" — download `auth-profiles.json`

No server required. All token exchange happens in the browser.

## CLI Usage

```bash
cargo build --release
./target/release/manytokens --openai [-o <output>]
./target/release/manytokens --refresh [-o <path>]
./target/release/manytokens --check  [-o <path>] [--warn 24h] [--warn 6h] [--warn 1h]
```

### Authenticate (interactive)

```bash
manytokens --openai -o auth-profiles.json
```

Opens an OpenAI OAuth URL in your browser. Paste the callback URL back into the terminal. Repeat for multiple accounts.

### Headless token refresh

```bash
manytokens --refresh -o auth-profiles.json
```

Non-interactively refreshes all tokens using existing refresh tokens. Suitable for cron/systemd timers.

### Check expiry

```bash
manytokens --check -o auth-profiles.json --warn 24h --warn 6h --warn 1h
```

Prints expiry status for all profiles and warns when within specified thresholds.

Example session:

```
$ manytokens --openai

Open this URL in your browser:

https://auth.openai.com/oauth/authorize?response_type=code&client_id=<redacted...>

Paste the callback URL (or authorization code):
```

Follow the prompts — open the URL, complete login in the browser, paste the callback URL back into the terminal. When done, answer `y` to add another account or press Enter to finish.

## Output

Profiles are written to the path specified by `-o` (default: `./auth-profiles.json`).

A `.bak` backup is created automatically before each save.

Each profile is keyed as `openai-codex:<email>` with `type: oauth` and includes `access`, `refresh`, and `expires` fields.

## Dependencies

- [reqwest](https://crates.io/crates/reqwest) — HTTP client (blocking, rustls)
- [serde / serde_json](https://crates.io/crates/serde) — JSON serialization
- [sha2](https://crates.io/crates/sha2) / [base64](https://crates.io/crates/base64) — PKCE challenge generation
- [rand](https://crates.io/crates/rand) / [hex](https://crates.io/crates/hex) — random state/verifier
- [url](https://crates.io/crates/url) — callback URL parsing
- [anyhow](https://crates.io/crates/anyhow) — error handling
