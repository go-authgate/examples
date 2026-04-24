// Resource server example — validates AuthGate-issued access tokens offline
// using JWKS public keys. No callback/introspection to AuthGate per request.
//
// Flow:
//
//  1. GET {ISSUER_URL}/.well-known/openid-configuration
//     → learn jwks_uri and supported signing algorithms
//  2. GET {jwks_uri}
//     → cache the public keys from JWKS (auto-refreshed on unknown kid)
//  3. For every incoming request with Authorization: Bearer <jwt>:
//     - verify RS256 signature against the cached JWKS
//     - check iss, aud, exp, nbf locally
//     - enforce required OAuth scopes
//
// Trade-off vs. token introspection (see ../go-webservice):
//   - Pro: zero network round-trips per request, horizontally scalable,
//     works in air-gapped regions after first JWKS fetch.
//   - Con: a revoked token stays valid until its `exp`. Keep access-token
//     lifetimes short (minutes) and use introspection when instant
//     revocation is required.
//
// Usage:
//
//	export ISSUER_URL=https://auth.example.com
//	export EXPECTED_AUDIENCE=https://api.example.com  # or SKIP_AUDIENCE_CHECK=1
//	go run main.go
//
// Test:
//
//	curl -H "Authorization: Bearer <token>" http://localhost:8088/api/profile
//	curl -H "Authorization: Bearer <token>" http://localhost:8088/api/data
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/joho/godotenv"
)

type ctxKey struct{}

// extraClaims holds non-standard JWT claims that *oidc.IDToken doesn't
// expose directly. The verifier already validates iss, aud, exp, nbf,
// signature — we only need to pull these out for app-level use.
type extraClaims struct {
	ClientID string `json:"client_id,omitempty"`
	Scope    string `json:"scope,omitempty"`
}

type tokenInfo struct {
	*oidc.IDToken
	Extra  extraClaims
	scopes []string
}

func (t *tokenInfo) hasScope(s string) bool {
	return slices.Contains(t.scopes, s)
}

type validator struct {
	verifier *oidc.IDTokenVerifier
	timeout  time.Duration
}

func (v *validator) verify(ctx context.Context, raw string) (*tokenInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()

	// Verify does signature + iss/aud/exp/nbf checks. It rejects alg=none
	// and algorithms inconsistent with the key type, defending against JWT
	// confusion attacks. nbf has a built-in 5 min leeway; exp is strict.
	// The return type is *oidc.IDToken by library convention, but we're
	// verifying access tokens — same RFC 7519 claims, same signature path.
	tok, err := v.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	var extra extraClaims
	if err := tok.Claims(&extra); err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}
	return &tokenInfo{
		IDToken: tok,
		Extra:   extra,
		scopes:  strings.Fields(extra.Scope),
	}, nil
}

func (v *validator) middleware(requiredScopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := bearerToken(r)
			if raw == "" {
				writeAuthError(w, "invalid_request", "missing Bearer token")
				return
			}
			info, err := v.verify(r.Context(), raw)
			if err != nil {
				// RFC 6750 best practice: log full details server-side, return a
				// generic error_description so verifier internals (expected issuer,
				// audience, parse failures) don't leak to clients.
				log.Printf("token verification failed: %v", err)
				writeAuthError(w, "invalid_token", "invalid token")
				return
			}
			for _, s := range requiredScopes {
				if !info.hasScope(s) {
					writeAuthError(w, "insufficient_scope", "required scope: "+s, s)
					return
				}
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, info)))
		})
	}
}

func bearerToken(r *http.Request) string {
	// Split on any whitespace so the parser is lenient about odd Authorization
	// headers in the wild (extra spaces, tabs) while still enforcing the
	// two-part scheme + token shape and case-insensitive "Bearer".
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}

// writeAuthError emits an RFC 6750 compliant Bearer challenge. The status
// code follows §3.1: 400 for invalid_request, 401 for invalid_token,
// 403 for insufficient_scope. When scopes are supplied they are advertised
// via the `scope` attribute so clients know what to request.
func writeAuthError(w http.ResponseWriter, code, desc string, scopes ...string) {
	var status int
	switch code {
	case "invalid_request":
		status = http.StatusBadRequest
	case "insufficient_scope":
		status = http.StatusForbidden
	default: // invalid_token and anything else
		status = http.StatusUnauthorized
	}
	challenge := fmt.Sprintf(`Bearer error=%q, error_description=%q`, code, desc)
	if len(scopes) > 0 {
		challenge += fmt.Sprintf(`, scope=%q`, strings.Join(scopes, " "))
	}
	w.Header().Set("WWW-Authenticate", challenge)
	http.Error(w, desc, status)
}

func infoFromContext(ctx context.Context) (*tokenInfo, bool) {
	t, ok := ctx.Value(ctxKey{}).(*tokenInfo)
	return t, ok
}

func main() {
	_ = godotenv.Load()

	issuerURL := strings.TrimRight(strings.TrimSpace(os.Getenv("ISSUER_URL")), "/")
	expectedAudience := strings.TrimSpace(os.Getenv("EXPECTED_AUDIENCE"))
	// Audience enforcement is required by default. Operators must either set
	// EXPECTED_AUDIENCE, or opt out explicitly with SKIP_AUDIENCE_CHECK=1 for
	// issuers whose access tokens don't carry `aud` — so accidental deploys
	// never silently disable audience validation.
	skipAudience := strings.TrimSpace(os.Getenv("SKIP_AUDIENCE_CHECK")) == "1"
	if issuerURL == "" {
		log.Fatal("Set ISSUER_URL (e.g. https://auth.example.com)")
	}
	if expectedAudience != "" && skipAudience {
		log.Fatal("Set exactly one of EXPECTED_AUDIENCE or SKIP_AUDIENCE_CHECK=1, not both " +
			"(SkipClientIDCheck wins and EXPECTED_AUDIENCE would be silently ignored)")
	}
	if expectedAudience == "" && !skipAudience {
		log.Fatal("Set EXPECTED_AUDIENCE to enforce the `aud` claim, " +
			"or SKIP_AUDIENCE_CHECK=1 to opt out (some issuers don't emit aud on access tokens)")
	}

	// Bound discovery so a stalled issuer doesn't hang startup forever.
	// NewProvider clones this ctx internally, so the deadline doesn't leak
	// into the long-lived keyset used for future JWKS refreshes.
	discoverCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// NewProvider verifies that the returned `issuer` matches ISSUER_URL —
	// this defeats attackers who control DNS but not the issuer.
	provider, err := oidc.NewProvider(discoverCtx, issuerURL)
	if err != nil {
		log.Fatalf("discover provider: %v", err)
	}

	// OIDC discovery only standardizes `id_token_signing_alg_values_supported`
	// — there's no access-token-specific field — so we log the ID-token set as
	// a reasonable hint at what algorithms the issuer's JWKS will use. Tokens
	// are still validated strictly by the verifier via the cached JWKS.
	var meta struct {
		JWKSURI            string   `json:"jwks_uri"`
		IDTokenSigningAlgs []string `json:"id_token_signing_alg_values_supported"`
	}
	if err := provider.Claims(&meta); err != nil {
		log.Fatalf("read provider metadata: %v", err)
	}

	v := &validator{
		verifier: provider.Verifier(&oidc.Config{
			ClientID:          expectedAudience,
			SkipClientIDCheck: skipAudience,
		}),
		timeout: 5 * time.Second,
	}

	mux := http.NewServeMux()
	mux.Handle("/api/profile", v.middleware()(http.HandlerFunc(profileHandler)))
	mux.Handle("/api/data", v.middleware("email")(http.HandlerFunc(dataHandler)))
	mux.HandleFunc("/health", healthHandler)

	srv := &http.Server{
		Addr:              ":8088",
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("Issuer:   %s", issuerURL)
	log.Printf("JWKS:     %s", meta.JWKSURI)
	log.Printf("ID-token signing algs: %v (access tokens usually share the same set)", meta.IDTokenSigningAlgs)
	if expectedAudience != "" {
		log.Printf("Audience: %s", expectedAudience)
	} else {
		log.Println("Audience: DISABLED (SKIP_AUDIENCE_CHECK=1) — tokens accepted for any audience")
	}
	log.Println("Listening on :8088 — offline JWKS validation (no AuthGate round-trip per request)")
	log.Fatal(srv.ListenAndServe())
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	info, ok := infoFromContext(r.Context())
	if !ok {
		writeAuthError(w, "invalid_request", "missing token context")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"subject":   info.Subject,
		"client_id": info.Extra.ClientID,
		"audience":  info.Audience,
		"scope":     info.Extra.Scope,
		"expires":   info.Expiry.UTC().Format(time.RFC3339),
	})
}

func dataHandler(w http.ResponseWriter, r *http.Request) {
	info, ok := infoFromContext(r.Context())
	if !ok {
		writeAuthError(w, "invalid_request", "missing token context")
		return
	}
	msg := "You have email-only access"
	if info.hasScope("profile") {
		msg = "You have email+profile access"
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": msg,
		"subject": info.Subject,
	})
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
