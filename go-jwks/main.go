// Resource server example — validates AuthGate-issued access tokens offline
// using JWKS public keys. No callback/introspection to AuthGate per request.
//
// Flow:
//
//  1. GET {ISSUER_URL}/.well-known/openid-configuration
//     → learn jwks_uri and supported signing algorithms
//  2. GET {jwks_uri}
//     → cache the RSA public keys (auto-refreshed on unknown kid)
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
//	export EXPECTED_AUDIENCE=https://api.example.com  # optional
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
	idToken, err := v.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	var extra extraClaims
	if err := idToken.Claims(&extra); err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}
	return &tokenInfo{
		IDToken: idToken,
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
				writeAuthError(w, "invalid_token", err.Error())
				return
			}
			for _, s := range requiredScopes {
				if !info.hasScope(s) {
					writeAuthError(w, "insufficient_scope", "required scope: "+s)
					return
				}
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, info)))
		})
	}
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// writeAuthError emits an RFC 6750 compliant Bearer challenge.
func writeAuthError(w http.ResponseWriter, code, desc string) {
	status := http.StatusUnauthorized
	if code == "insufficient_scope" {
		status = http.StatusForbidden
	}
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error=%q, error_description=%q`, code, desc))
	http.Error(w, desc, status)
}

func infoFromContext(ctx context.Context) (*tokenInfo, bool) {
	t, ok := ctx.Value(ctxKey{}).(*tokenInfo)
	return t, ok
}

func main() {
	_ = godotenv.Load()

	issuerURL := strings.TrimRight(os.Getenv("ISSUER_URL"), "/")
	expectedAudience := os.Getenv("EXPECTED_AUDIENCE") // optional
	if issuerURL == "" {
		log.Fatal("Set ISSUER_URL (e.g. https://auth.example.com)")
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

	var meta struct {
		JWKSURI     string   `json:"jwks_uri"`
		SigningAlgs []string `json:"id_token_signing_alg_values_supported"`
	}
	if err := provider.Claims(&meta); err != nil {
		log.Fatalf("read provider metadata: %v", err)
	}

	v := &validator{
		verifier: provider.Verifier(&oidc.Config{
			ClientID:          expectedAudience,
			SkipClientIDCheck: expectedAudience == "",
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
	log.Printf("Signing:  %v", meta.SigningAlgs)
	if expectedAudience != "" {
		log.Printf("Audience: %s", expectedAudience)
	} else {
		log.Println("Audience: (not enforced — set EXPECTED_AUDIENCE to enable)")
	}
	log.Println("Listening on :8088 — offline JWKS validation (no AuthGate round-trip per request)")
	log.Fatal(srv.ListenAndServe())
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	info, _ := infoFromContext(r.Context())
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
	info, _ := infoFromContext(r.Context())
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
