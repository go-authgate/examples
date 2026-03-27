# AuthGate Examples

Multi-language usage examples for AuthGate authentication (Go, Python, Bash).

## Quick Reference

| Example                         | Use Case             | OAuth Flow                   | Language | Prerequisites    |
| ------------------------------- | -------------------- | ---------------------------- | -------- | ---------------- |
| [go-cli](go-cli/)               | CLI login            | Auth Code+PKCE / Device Code | Go       | Go 1.25+         |
| [python-cli](python-cli/)       | CLI login            | Auth Code+PKCE / Device Code | Python   | Python 3.10+, uv |
| [bash-cli](bash-cli/)           | CLI login (headless) | Device Code (RFC 8628)       | Bash     | curl, jq         |
| [go-m2m](go-m2m/)               | Service-to-service   | Client Credentials           | Go       | Go 1.25+         |
| [python-m2m](python-m2m/)       | Service-to-service   | Client Credentials           | Python   | Python 3.10+, uv |
| [go-webservice](go-webservice/) | API protection       | Bearer validation            | Go       | Go 1.25+         |

## Environment Setup

All examples require `AUTHGATE_URL` and `CLIENT_ID`. M2M examples additionally require `CLIENT_SECRET`.

```bash
export AUTHGATE_URL=https://auth.example.com
export CLIENT_ID=your-client-id
export CLIENT_SECRET=your-client-secret  # M2M only
```

## Interactive CLI Authentication

These examples authenticate a human user via browser or device code. Auto-detects browser availability: uses Auth Code + PKCE on local machines, falls back to Device Code in SSH/headless sessions. Tokens are cached for reuse.

### Go CLI

Uses the AuthGate Go SDK. Tokens are stored in the OS keyring.

```bash
cd go-cli
go run main.go
```

### Python CLI

Uses the AuthGate Python SDK. Tokens are stored in the OS keyring when available, with a fallback cache file at `~/.authgate-tokens.json`.

```bash
cd python-cli
uv run python main.py
```

### Bash CLI

Pure shell implementation using only `curl` and `jq` — no SDK or runtime required. Uses the Device Authorization Grant (RFC 8628) exclusively. Tokens are cached to `~/.authgate-tokens.json`.

Features: OIDC discovery, token caching/refresh, expiry handling, cross-platform support (GNU/BSD), and security hardening (symlink protection, stdin-based secret passing to avoid process-list leaks).

```bash
cd bash-cli
bash main.sh
```

## Machine-to-Machine (M2M) Authentication

These examples use the Client Credentials grant for service-to-service authentication. No user interaction needed — requires `CLIENT_SECRET`.

### Go M2M

Uses the AuthGate Go SDK with auto-caching and a pre-authenticated HTTP client.

```bash
cd go-m2m
go run main.go
```

### Python M2M

Uses the AuthGate Python SDK with auto-refreshing `BearerAuth` for httpx.

```bash
cd python-m2m
uv run python main.py
```

## Web Service — API Token Validation

Protects HTTP endpoints with Bearer token middleware and scope-based access control. Works with any Go HTTP framework.

```bash
cd go-webservice
go run main.go

# Test
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/profile
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/data
```

## OAuth 2.0 Flows

- **Authorization Code + PKCE** — Browser-based login, most secure for CLI tools on machines with a browser. The client opens a browser, the user authenticates, and a code is exchanged for tokens.
- **Device Code ([RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628))** — For headless/SSH environments. The user authenticates on a separate device by visiting a URL and entering a code.
- **Client Credentials** — Service-to-service auth with a shared secret. No user involved.
- **Bearer Token Validation** — Server-side introspection of access tokens sent by clients in the `Authorization` header.

## Troubleshooting

- **"Cannot connect to AUTHGATE_URL"** — Verify the URL is correct and the AuthGate server is running.
- **"Device code expired"** — Restart the flow; the default timeout is 300 seconds.
- **Token cache location** — `~/.authgate-tokens.json` is shared by bash-cli and Python examples. Go CLI examples use the OS keyring.
- **OS keyring unavailable** — Go and Python CLI examples fall back to file-based cache automatically.
