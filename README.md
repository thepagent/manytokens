# manytokens

A CLI tool to authenticate multiple OpenAI accounts via OAuth (PKCE flow) and store the resulting tokens into an `auth-profiles.json` file used by OpenClaw agents.

## What it does

1. Generates a PKCE challenge and opens an OpenAI OAuth authorization URL in your browser.
2. You paste back the callback URL (or raw authorization code).
3. It exchanges the code for access/refresh tokens, extracts your email and account ID from the JWT, and writes a profile entry to `auth-profiles.json`.
4. Repeat for as many accounts as you need.

## Usage

```bash
cargo build --release
./target/release/manytokens --openai
```

Example session:

```
$ manytokens --openai

Open this URL in your browser:

https://auth.openai.com/oauth/authorize?response_type=code&client_id=<redacted...>

Paste the callback URL (or authorization code):
```

Follow the prompts — open the URL, complete login in the browser, paste the callback URL back into the terminal. When done, answer `y` to add another account or press Enter to finish.

## Output

Profiles are written to:

```
~/.openclaw/agents/main/agent/auth-profiles.json
```

A `.bak` backup is created automatically before each save.

Each profile is keyed as `openai-codex:<email>` with `type: oauth` and includes `access`, `refresh`, and `expires` fields.

## Dependencies

- [reqwest](https://crates.io/crates/reqwest) — HTTP client (blocking, rustls)
- [serde / serde_json](https://crates.io/crates/serde) — JSON serialization
- [sha2](https://crates.io/crates/sha2) / [base64](https://crates.io/crates/base64) — PKCE challenge generation
- [rand](https://crates.io/crates/rand) / [hex](https://crates.io/crates/hex) — random state/verifier
- [url](https://crates.io/crates/url) — callback URL parsing
- [anyhow](https://crates.io/crates/anyhow) — error handling
