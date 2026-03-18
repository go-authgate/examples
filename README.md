# AuthGate Examples

Usage examples for the AuthGate Go SDK.

## Prerequisites

Set environment variables before running:

```bash
export AUTHGATE_URL=https://auth.example.com
export CLIENT_ID=your-client-id
export CLIENT_SECRET=your-client-secret  # only for M2M
```

## Examples

### CLI — Interactive Authentication

Auto-detects browser availability: uses Auth Code + PKCE on local machines, falls back to Device Code in SSH sessions. Tokens are cached in OS keyring.

```bash
cd go-cli
go run main.go
```

### Web Service — API Token Validation

Protects HTTP endpoints with Bearer token middleware. Works with any Go HTTP framework.

```bash
cd go-webservice
go run main.go

# Test
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/profile
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/data
```

### M2M — Service-to-Service Authentication

Uses Client Credentials grant with auto-caching. No user interaction needed.

```bash
cd go-m2m
go run main.go
```
