# Bash CLI — Device Code Authentication

Pure shell implementation of OAuth 2.0 Device Authorization Grant ([RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628)). No SDK or language runtime required — only `curl` and `jq`.

## OAuth Flow

Uses the **Device Code** flow exclusively. The user authenticates on a separate device (phone, laptop) by visiting a URL and entering a code.

## Prerequisites

- Bash
- `curl` — HTTP client
- `jq` — JSON processor ([install](https://jqlang.github.io/jq/))
- An AuthGate server with a configured OAuth client

## Environment Variables

| Variable       | Required | Description                    |
| -------------- | -------- | ------------------------------ |
| `AUTHGATE_URL` | Yes      | AuthGate server URL            |
| `CLIENT_ID`    | Yes      | OAuth 2.0 client identifier    |

## Usage

```bash
# Option 1 — use a .env file (run from the bash-cli directory):
cp .env.example .env
# edit .env with your values
bash main.sh

# Option 2 — export variables directly:
export AUTHGATE_URL=https://auth.example.com
export CLIENT_ID=your-client-id
bash main.sh
```

## `.env` File Behavior

- The `.env` file is loaded from the **current working directory**, not the script's directory
- Variables already set in the environment are **not overridden** — explicit `export` always takes precedence
- Malformed lines (not matching `KEY=VALUE`) are skipped with a warning

## How It Works

1. Discovers OIDC endpoints via `/.well-known/openid-configuration`
2. Checks for a cached token in `~/.authgate-tokens.json`
   - If valid and not expired, reuses it
   - If expired, attempts a token refresh
3. If no valid token, initiates the Device Code flow:
   - Requests a device code from the authorization server
   - Displays a verification URL and user code
   - Polls the token endpoint until the user completes authorization
4. Validates the token via `/oauth/userinfo` — re-authenticates on 401/403
5. Caches the token for future runs
6. Prints user info and token metadata

## Example Output

```txt
To sign in, open the following URL in a browser:

  https://auth.example.com/device

Then enter the code: ABCD-1234

Waiting for authorization....
User: Jane Doe (jane@example.com)
Subject: user-uuid-1234
Access Token: eyJhbGci...
Refresh Token: dGhpcyBp...
Token Type: Bearer
Expires In: 3600
Expires At: 2025-01-01T12:00:00Z
Scope: profile email
ID Token: eyJ0eXAi...
TokenInfo Active: true
TokenInfo UserID: user-uuid-1234
TokenInfo ClientID: your-client-id
TokenInfo Scope: profile email
TokenInfo SubjectType: user
TokenInfo Issuer: https://auth.example.com
TokenInfo Exp: 1735732800
```

## Security Features

- **Symlink protection** — refuses to read/write token cache files that are symlinks
- **File ownership check** — only operates on cache files owned by the current user
- **stdin-based secret passing** — POST data and headers are passed via stdin to avoid leaking tokens in the process list
- **Curl config injection prevention** — escapes special characters in HTTP headers
- **Safe `.env` parsing** — only accepts `KEY=VALUE` format; skips malformed lines and never overrides existing environment variables
- **File permissions** — cache files are set to `600` (owner-only read/write)

## Cross-Platform Support

Automatically detects GNU vs BSD `date` command at startup for portable date formatting (Linux, macOS, FreeBSD).

## Token Storage

Tokens are cached to `~/.authgate-tokens.json`. This file is shared with the Python CLI example, using the same format for compatibility.
