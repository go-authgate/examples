// Resource server example — accepts AuthGate-issued access tokens from
// MULTIPLE trusted issuers, validated offline against each issuer's JWKS,
// with per-route allowlists for the `tenant`, `service_account`, and
// `project` custom claims. The validation core lives in the SDK's
// jwksauth package; this file shows configuration + routing.
//
// Use cases:
//   - Multi-region: one AuthGate per region; any region's tokens accepted.
//   - Multi-tenant: one AuthGate per tenant, mounted under a shared API.
//   - Migration: accept the old and new AuthGate concurrently during cutover.
//   - Federation: trust tokens from a partner organization's AuthGate.
//
// Why ISSUER_TENANTS matters with short tenant codes:
//
//	Short codes like "oa" / "hwrd" carry no DNS-style trust boundary, so a
//	compromised issuer A could otherwise sign a token claiming
//	`tenant=swrd` (which actually belongs to issuer B). The optional
//	ISSUER_TENANTS map pins each issuer to the tenants it owns and rejects
//	cross-tenant claims at the resource server.
//
// Usage:
//
//	export TRUSTED_ISSUERS=https://auth-a.example.com,https://auth-b.example.com
//	export EXPECTED_AUDIENCE=https://api.example.com   # or SKIP_AUDIENCE_CHECK=1
//	# Optional cross-tenant defense — strongly recommended with short codes:
//	export ISSUER_TENANTS='https://auth-a.example.com=oa,hwrd;https://auth-b.example.com=swrd,cdomain'
//	go run main.go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-authgate/sdk-go/jwksauth"

	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load()

	rawIssuers := strings.TrimSpace(os.Getenv("TRUSTED_ISSUERS"))
	expectedAudience := strings.TrimSpace(os.Getenv("EXPECTED_AUDIENCE"))
	skipAudience := strings.TrimSpace(os.Getenv("SKIP_AUDIENCE_CHECK")) == "1"
	rawIssuerTenants := strings.TrimSpace(os.Getenv("ISSUER_TENANTS"))

	if rawIssuers == "" {
		log.Fatal("Set TRUSTED_ISSUERS to a comma-separated list of issuer URLs")
	}
	if expectedAudience != "" && skipAudience {
		log.Fatal("Set exactly one of EXPECTED_AUDIENCE or SKIP_AUDIENCE_CHECK=1, not both")
	}
	if expectedAudience == "" && !skipAudience {
		log.Fatal("Set EXPECTED_AUDIENCE to enforce the `aud` claim, " +
			"or SKIP_AUDIENCE_CHECK=1 to opt out")
	}

	mv, err := newMultiVerifier(rawIssuers, expectedAudience, skipAudience)
	if err != nil {
		log.Fatalf("build verifiers: %v", err)
	}
	if err := mv.SetIssuerTenants(rawIssuerTenants); err != nil {
		log.Fatalf("parse ISSUER_TENANTS: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/profile", jwksauth.Middleware(mv, jwksauth.AccessRule{})(http.HandlerFunc(profileHandler)))
	mux.Handle("/api/data", jwksauth.Middleware(mv, jwksauth.AccessRule{
		Scopes:  []string{"email"},
		Tenants: []string{"oa", "hwrd"},
	})(http.HandlerFunc(dataHandler)))
	mux.Handle("/api/admin", jwksauth.Middleware(mv, jwksauth.AccessRule{
		ServiceAccounts: []string{"sync-bot@oa.local"},
		Projects:        []string{"admin-tools"},
	})(http.HandlerFunc(adminHandler)))
	mux.HandleFunc("/health", healthHandler)

	srv := &http.Server{
		Addr:              ":8089",
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

	logStartup(mv, expectedAudience)
	log.Fatal(srv.ListenAndServe())
}

func newMultiVerifier(rawIssuers, audience string, skipAudience bool) (*jwksauth.MultiVerifier, error) {
	issuers, err := parseIssuers(rawIssuers)
	if err != nil {
		return nil, err
	}
	// Bound *total* discovery time, not per-issuer — one slow issuer must
	// not multiply startup time by N. The SDK runs discovery concurrently.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if skipAudience {
		return jwksauth.NewMultiVerifierSkipAudience(ctx, issuers)
	}
	return jwksauth.NewMultiVerifier(ctx, issuers, audience)
}

// parseIssuers splits a comma-separated TRUSTED_ISSUERS value into trimmed,
// deduplicated issuer URLs. Every entry is treated as an authoritative signing
// authority, so each one must be an unambiguous identifier: https for
// production (http allowed only for loopback hosts to keep the local
// testissuer flow runnable), no userinfo / query / fragment, and no opaque
// form. Without these guards, a typo like `https://auth.example.com@evil.com`
// would silently trust evil.com. Duplicates and empty results are rejected up
// front rather than deferred into the SDK.
func parseIssuers(raw string) ([]string, error) {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if err := validateIssuerURL(p); err != nil {
			return nil, fmt.Errorf("TRUSTED_ISSUERS entry %q: %w", p, err)
		}
		if _, dup := seen[p]; dup {
			return nil, fmt.Errorf("TRUSTED_ISSUERS contains duplicate issuer: %s", p)
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("TRUSTED_ISSUERS must contain at least one non-empty issuer URL")
	}
	return out, nil
}

func validateIssuerURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("must be a valid URL: %w", err)
	}
	if u.Opaque != "" || u.Hostname() == "" {
		return fmt.Errorf("must be an absolute URL with a host")
	}
	if u.User != nil {
		return fmt.Errorf("must not contain userinfo (an entry like https://x@evil.com is treated as evil.com)")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("must not contain a query string or fragment")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("http is only allowed for loopback hosts (localhost, 127.0.0.1, ::1)")
	default:
		return fmt.Errorf("scheme must be https (or http for loopback), got %q", u.Scheme)
	}
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func logStartup(mv *jwksauth.MultiVerifier, audience string) {
	tenants := mv.IssuerTenants()
	issuers := mv.Issuers()
	log.Printf("Trusted issuers (%d):", len(issuers))
	for _, iss := range issuers {
		if t := tenants[iss]; t != nil {
			log.Printf("  - %s  →  tenants: %v", iss, t)
		} else {
			log.Printf("  - %s  →  tenants: (any — ISSUER_TENANTS not set)", iss)
		}
	}
	if audience != "" {
		log.Printf("Audience: %s (applied to all issuers)", audience)
	} else {
		log.Println("Audience: DISABLED (SKIP_AUDIENCE_CHECK=1)")
	}
	log.Println("Listening on :8089 — multi-issuer offline JWKS validation")
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	info, ok := jwksauth.TokenInfoFromContext(r.Context())
	if !ok {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":          info.Issuer,
		"subject":         info.Subject,
		"client_id":       info.Claims.ClientID,
		"audience":        info.Audience,
		"scope":           info.Claims.Scope,
		"tenant":          info.Claims.Tenant,
		"service_account": info.Claims.ServiceAccount,
		"project":         info.Claims.Project,
		"expires":         info.Expiry.UTC().Format(time.RFC3339),
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
		"issuer":  info.Issuer,
		"subject": info.Subject,
		"tenant":  info.Claims.Tenant,
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
		"service_account": info.Claims.ServiceAccount,
		"project":         info.Claims.Project,
	})
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
