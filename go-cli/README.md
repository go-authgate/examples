# Go CLI — Interactive Authentication

Authenticate a human user via browser or device code with automatic environment detection.

## OAuth Flow

- **Local machine** (browser available): Authorization Code + PKCE
- **SSH / headless session**: Device Code flow (RFC 8628)

The SDK auto-detects the environment and selects the appropriate flow.

## Prerequisites

- Go 1.25+
- An AuthGate server with a configured OAuth client

## Environment Variables

| Variable       | Required | Description                 |
| -------------- | -------- | --------------------------- |
| `AUTHGATE_URL` | Yes      | AuthGate server URL         |
| `CLIENT_ID`    | Yes      | OAuth 2.0 client identifier |

## Usage

```bash
export AUTHGATE_URL=https://auth.example.com
export CLIENT_ID=your-client-id
go run main.go
```

## How It Works

1. Calls `authgate.New()` which performs OIDC discovery and starts the appropriate OAuth flow
2. Requests `profile` and `email` scopes
3. Stores the token in the OS keyring (falls back to file-based storage if keyring is unavailable)
4. Fetches user info via the `/oauth/userinfo` endpoint
5. Validates the token via `/oauth/tokeninfo` and prints detailed metadata

On subsequent runs, the cached token is reused automatically. If expired, it is refreshed transparently.

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
TokenInfo Active: true
TokenInfo UserID: user-uuid-1234
TokenInfo ClientID: your-client-id
TokenInfo Scope: profile email
TokenInfo SubjectType: user
TokenInfo Issuer: https://auth.example.com
TokenInfo Exp: 1735732800
```

## Token Storage

Tokens are persisted in the OS keyring:

| Platform | Backend                    |
| -------- | -------------------------- |
| macOS    | Keychain                   |
| Linux    | Secret Service (D-Bus)     |
| Windows  | Windows Credential Manager |

If the keyring is unavailable, tokens fall back to a file-based cache.
