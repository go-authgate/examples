# Python CLI — Interactive Authentication

Authenticate a human user via browser or device code with automatic environment detection.

## OAuth Flow

- **Local machine** (browser available): Authorization Code + PKCE
- **SSH / headless session**: Device Code flow (RFC 8628)

The SDK auto-detects the environment and selects the appropriate flow.

## Prerequisites

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) package manager
- An AuthGate server with a configured OAuth client

## Environment Variables

| Variable       | Required | Description                    |
| -------------- | -------- | ------------------------------ |
| `AUTHGATE_URL` | Yes      | AuthGate server URL            |
| `CLIENT_ID`    | Yes      | OAuth 2.0 client identifier    |

## Usage

```bash
export AUTHGATE_URL=https://auth.example.com
export CLIENT_ID=your-client-id
uv run python main.py
```

Alternatively, create a `.env` file in the `python-cli/` directory:

```bash
AUTHGATE_URL=https://auth.example.com
CLIENT_ID=your-client-id
```

Then simply run:

```bash
uv run python main.py
```

Environment variables take precedence over `.env` values. The `.env` file is optional — the program works without it.

`uv run` automatically installs dependencies from `pyproject.toml` on first run.

## How It Works

1. Calls `authgate.authenticate()` which performs OIDC discovery and starts the appropriate OAuth flow
2. Requests `profile` and `email` scopes
3. Stores the token in the OS keyring (falls back to `~/.authgate-tokens.json`)
4. Validates the cached token via `/oauth/userinfo` — if the server has revoked it, clears the cache and re-authenticates
5. Prints user info and detailed token metadata from `/oauth/tokeninfo`

## Example Output

```
User: Jane Doe (jane@example.com)
Subject: user-uuid-1234
Access Token: eyJhbGci...
Refresh Token: dGhpcyBp...
Token Type: Bearer
Expires In: 3600
Expires At: 2025-01-01T12:00:00Z
Scope: profile email
ID Token: eyJ0eXAi...
TokenInfo Active: True
TokenInfo UserID: user-uuid-1234
TokenInfo ClientID: your-client-id
TokenInfo Scope: profile email
TokenInfo SubjectType: user
TokenInfo Issuer: https://auth.example.com
TokenInfo Exp: 1735732800
```

## Token Storage

Tokens are persisted in the OS keyring when available. If the keyring is not accessible, they fall back to `~/.authgate-tokens.json` (shared with the bash-cli example).
