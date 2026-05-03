// Resource server example — validates AuthGate-issued access tokens offline
// using JWKS public keys. The heavy lifting (OIDC discovery, JWKS caching,
// signature + iss/aud/exp/nbf checks, RFC 6750 error formatting) lives in
// the SDK's jwksauth package; this file is intentionally short.
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
//	curl -H "Authorization: Bearer <token>" http://localhost:8088/api/admin
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-authgate/sdk-go/jwksauth"

	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load()

	// Don't strip a trailing slash: OIDC Core §3.1.2.1 compares the issuer
	// byte-for-byte, and some providers legitimately publish it with a
	// trailing "/". Whatever the user sets here must match the `iss` claim.
	issuerURL := strings.TrimSpace(os.Getenv("ISSUER_URL"))
	expectedAudience := strings.TrimSpace(os.Getenv("EXPECTED_AUDIENCE"))
	// Audience enforcement is required by default. Operators must either set
	// EXPECTED_AUDIENCE, or opt out explicitly with SKIP_AUDIENCE_CHECK=1 for
	// issuers whose access tokens don't carry `aud` — so accidental deploys
	// never silently disable audience validation.
	skipAudience := strings.TrimSpace(os.Getenv("SKIP_AUDIENCE_CHECK")) == "1"
	// Optional override of the AuthGate server's JWT_PRIVATE_CLAIM_PREFIX
	// (default "extra"). Server and SDK must agree byte-for-byte; reading
	// with the wrong prefix yields empty Domain/Project/ServiceAccount and
	// the AccessRule below fails closed.
	privateClaimPrefix := strings.TrimSpace(os.Getenv("JWT_PRIVATE_CLAIM_PREFIX"))
	if issuerURL == "" {
		log.Fatal("Set ISSUER_URL (e.g. https://auth.example.com)")
	}
	if expectedAudience != "" && skipAudience {
		log.Fatal("Set exactly one of EXPECTED_AUDIENCE or SKIP_AUDIENCE_CHECK=1, not both")
	}
	if expectedAudience == "" && !skipAudience {
		log.Fatal("Set EXPECTED_AUDIENCE to enforce the `aud` claim, " +
			"or SKIP_AUDIENCE_CHECK=1 to opt out (some issuers don't emit aud on access tokens)")
	}

	v, err := newVerifier(issuerURL, expectedAudience, skipAudience, privateClaimPrefix)
	if err != nil {
		log.Fatalf("build verifier: %v", err)
	}

	mux := http.NewServeMux()
	// AccessRule fields are AND-combined and fail-closed: an empty slice
	// skips that check, a non-empty slice requires the token to match.
	// Domain/ServiceAccount/Project reject reasons are server-logged only —
	// clients see a generic 401. Scope failures are reported separately as
	// 403 insufficient_scope with details in the WWW-Authenticate header.
	mux.Handle("/api/profile", jwksauth.Middleware(v, jwksauth.AccessRule{})(http.HandlerFunc(profileHandler)))
	mux.Handle("/api/data", jwksauth.Middleware(v, jwksauth.AccessRule{
		Scopes: []string{"email"},
	})(http.HandlerFunc(dataHandler)))
	mux.Handle("/api/admin", jwksauth.Middleware(v, jwksauth.AccessRule{
		Domains:         []string{"oa"},
		ServiceAccounts: []string{"sync-bot@oa.local"},
		Projects:        []string{"admin-tools"},
	})(http.HandlerFunc(adminHandler)))
	mux.HandleFunc("/health", healthHandler)

	srv := &http.Server{
		Addr:              ":8088",
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		// Bound the Authorization header — and therefore the JWT — well below
		// the Go default of 1 MiB so the unverified-iss base64 decode in the
		// SDK can't be coerced into large allocations. Real access tokens are
		// typically <2 KiB; 8 KiB leaves generous headroom.
		MaxHeaderBytes: 8 << 10,
	}

	log.Printf("Issuer:   %s", v.Issuer())
	if expectedAudience != "" {
		log.Printf("Audience: %s", expectedAudience)
	} else {
		log.Println("Audience: DISABLED (SKIP_AUDIENCE_CHECK=1) — tokens accepted for any audience")
	}
	if privateClaimPrefix != "" {
		log.Printf("Private claim prefix: %q (overrides SDK default)", privateClaimPrefix)
	} else {
		log.Println("Private claim prefix: \"extra\" (SDK default)")
	}
	log.Println("Listening on :8088 — offline JWKS validation (no AuthGate round-trip per request)")
	log.Fatal(srv.ListenAndServe())
}

func newVerifier(issuerURL, audience string, skipAudience bool, privateClaimPrefix string) (*jwksauth.Verifier, error) {
	// Bound discovery so a stalled issuer doesn't hang startup forever.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// WithPrivateClaimPrefix("") is documented as a no-op that leaves the
	// SDK default in place, so passing the env value through unconditionally
	// is safe.
	opts := []jwksauth.Option{jwksauth.WithPrivateClaimPrefix(privateClaimPrefix)}
	if skipAudience {
		return jwksauth.NewVerifierSkipAudience(ctx, issuerURL, opts...)
	}
	return jwksauth.NewVerifier(ctx, issuerURL, audience, opts...)
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	info, ok := jwksauth.TokenInfoFromContext(r.Context())
	if !ok {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"subject":   info.Subject,
		"client_id": info.Claims.ClientID,
		"audience":  info.Audience,
		"scope":     info.Claims.Scope,
		"expires":   info.Expiry.UTC().Format(time.RFC3339),
		"domain":    info.Claims.Domain,
	})
}

func dataHandler(w http.ResponseWriter, r *http.Request) {
	info, ok := jwksauth.TokenInfoFromContext(r.Context())
	if !ok {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	msg := "You have email-only access"
	if info.HasScope("profile") {
		msg = "You have email+profile access"
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": msg,
		"subject": info.Subject,
	})
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	info, ok := jwksauth.TokenInfoFromContext(r.Context())
	if !ok {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message":         "admin endpoint",
		"domain":          info.Claims.Domain,
		"service_account": info.Claims.ServiceAccount,
		"project":         info.Claims.Project,
	})
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
