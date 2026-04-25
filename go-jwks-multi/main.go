// Resource server example — accepts AuthGate-issued access tokens from
// MULTIPLE trusted issuers, validated offline against each issuer's JWKS,
// with per-route allowlists for the `tenant`, `service_account`, and
// `project` custom claims.
//
// Use cases:
//   - Multi-region: one AuthGate per region; any region's tokens accepted.
//   - Multi-tenant: one AuthGate per tenant, mounted under a shared API.
//   - Migration: accept the old and new AuthGate concurrently during cutover.
//   - Federation: trust tokens from a partner organization's AuthGate.
//
// Flow:
//
//  1. At startup, for each ISSUER in TRUSTED_ISSUERS:
//     - GET {ISSUER}/.well-known/openid-configuration
//     - GET {jwks_uri} (cached + auto-refreshed on unknown kid)
//     - Build a verifier keyed by the canonical issuer string.
//  2. Per request with Authorization: Bearer <jwt>:
//     - Read the `iss` claim from the unverified payload (selection only).
//     - Look up the matching verifier; reject if `iss` is not trusted.
//     - Verifier authoritatively checks signature, iss, aud, exp, nbf.
//     - If ISSUER_TENANTS is set, confirm THIS issuer is permitted to
//     sign tokens for the token's `tenant` (cross-tenant defense).
//     - Per-route accessRule enforces required scopes + allowlists for
//     `tenant` / `service_account` / `project`.
//
// Why "read iss before verifying" is safe:
//
//	`iss` is read unverified only to PICK which verifier to use. Each
//	verifier then validates the signature against ITS issuer's JWKS and
//	re-checks the `iss` claim. An attacker who claims `iss=trustedA` but
//	signs with their own key fails signature verification.
//
// Why ISSUER_TENANTS matters with short tenant codes:
//
//	Short codes like "oa" / "hwrd" carry no DNS-style trust boundary, so
//	a compromised issuer A could otherwise sign a token claiming
//	`tenant=swrd` (which actually belongs to issuer B). The optional
//	ISSUER_TENANTS map pins each issuer to the tenants it owns and
//	rejects cross-tenant claims at the resource server.
//
// Trade-off vs. ../go-jwks (single issuer): same offline benefits, plus
// the ability to roll AuthGates independently. Cost: one JWKS cache per
// issuer, one extra map lookup per request.
//
// Usage:
//
//	export TRUSTED_ISSUERS=https://auth-a.example.com,https://auth-b.example.com
//	export EXPECTED_AUDIENCE=https://api.example.com   # or SKIP_AUDIENCE_CHECK=1
//	# Optional cross-tenant defense — strongly recommended with short codes:
//	export ISSUER_TENANTS='https://auth-a.example.com=oa,hwrd;https://auth-b.example.com=swrd,cdomain'
//	go run main.go
//
// Test:
//
//	curl -H "Authorization: Bearer <token>" http://localhost:8089/api/profile
//	curl -H "Authorization: Bearer <token>" http://localhost:8089/api/data
//	curl -H "Authorization: Bearer <token>" http://localhost:8089/api/admin
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/joho/godotenv"
)

type ctxKey struct{}

// extraClaims holds non-standard JWT claims AuthGate puts in the payload.
// Field tags must match what AuthGate actually emits — change them if your
// deployment uses namespaced claims (e.g. "https://authgate.example.com/tenant").
type extraClaims struct {
	ClientID       string `json:"client_id,omitempty"`
	Scope          string `json:"scope,omitempty"`
	Tenant         string `json:"tenant,omitempty"`          // tenant short code, e.g. "oa"
	ServiceAccount string `json:"service_account,omitempty"` // OAuth-app-bound SA identifier
	Project        string `json:"project,omitempty"`         // project the OAuth app belongs to
}

type tokenInfo struct {
	*oidc.IDToken
	Extra  extraClaims
	scopes []string
	// tenant is the case-folded form of Extra.Tenant, used for all
	// allowlist comparisons so route configs remain case-insensitive.
	tenant string
}

func (t *tokenInfo) hasScope(s string) bool {
	return slices.Contains(t.scopes, s)
}

// accessRule is the per-route policy: required scopes plus allowlists for
// the three custom claims. An empty slice means "don't check this dimension";
// when a slice is set, the token's value MUST be in it (fail-closed: a missing
// claim is treated as not-in-allowlist and rejected).
//
// Tenant compares case-insensitively (allowlist values must already be lower-
// case — `oa` not `OA`). ServiceAccount and Project are compared exactly.
type accessRule struct {
	scopes          []string
	tenants         []string // pre-lower-cased
	serviceAccounts []string
	projects        []string
}

// checkClaims validates the non-scope dimensions and returns a short reason
// for the server log if something failed. Scope checks are done separately
// in the middleware so they can advertise the missing scope per RFC 6750.
func (r accessRule) checkClaims(info *tokenInfo) (reason string, ok bool) {
	if len(r.tenants) > 0 && !slices.Contains(r.tenants, info.tenant) {
		return fmt.Sprintf("tenant=%q not in allowlist", info.Extra.Tenant), false
	}
	if len(r.serviceAccounts) > 0 && !slices.Contains(r.serviceAccounts, info.Extra.ServiceAccount) {
		return fmt.Sprintf("service_account=%q not in allowlist", info.Extra.ServiceAccount), false
	}
	if len(r.projects) > 0 && !slices.Contains(r.projects, info.Extra.Project) {
		return fmt.Sprintf("project=%q not in allowlist", info.Extra.Project), false
	}
	return "", true
}

// multiValidator dispatches verification to the right per-issuer verifier
// based on the token's `iss` claim. Both maps are built once at startup and
// read-only afterwards, so no locking is needed on the hot path.
type multiValidator struct {
	verifiers map[string]*oidc.IDTokenVerifier
	// issuerTenants pins each issuer to the set of `tenant` values it is
	// permitted to sign for. nil = enforcement disabled (single-tenant deploy
	// or operator opted out). Keys are canonical issuer strings; values are
	// already lower-cased.
	issuerTenants map[string][]string
	timeout       time.Duration
}

func (v *multiValidator) verify(ctx context.Context, raw string) (*tokenInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()

	// Read `iss` from the unverified payload only to PICK the verifier.
	// The verifier then authoritatively re-checks `iss` plus signature,
	// aud, exp, nbf — so a forged `iss` cannot bypass the right key set.
	iss, err := unverifiedIssuer(raw)
	if err != nil {
		return nil, err
	}
	verifier, ok := v.verifiers[iss]
	if !ok {
		// Carry the iss in the error so the middleware can log it once
		// server-side; the client still gets a generic "invalid_token"
		// since `iss` is attacker-controlled in the unverified payload
		// and could be used to probe which issuers we trust.
		return nil, fmt.Errorf("untrusted issuer: iss=%q", iss)
	}
	tok, err := verifier.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	var extra extraClaims
	if err := tok.Claims(&extra); err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}
	tenant := strings.ToLower(extra.Tenant)

	// Cross-tenant defense: if the operator configured ISSUER_TENANTS, this
	// issuer is only allowed to sign tokens for its declared tenant set.
	// Stops a compromised issuer A from minting tokens that claim a tenant
	// owned by issuer B — a real risk with opaque short tenant codes.
	if v.issuerTenants != nil {
		allowed := v.issuerTenants[iss]
		if !slices.Contains(allowed, tenant) {
			return nil, fmt.Errorf(
				"issuer not permitted for this tenant: iss=%q tenant=%q allowed=%v",
				iss, extra.Tenant, allowed,
			)
		}
	}

	return &tokenInfo{
		IDToken: tok,
		Extra:   extra,
		scopes:  strings.Fields(extra.Scope),
		tenant:  tenant,
	}, nil
}

// unverifiedIssuer extracts the `iss` claim from the JWT payload WITHOUT
// validating the signature. The result must only be used to route to the
// correct verifier — never to make trust decisions.
func unverifiedIssuer(raw string) (string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("malformed JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode payload: %w", err)
	}
	var c struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return "", fmt.Errorf("parse payload: %w", err)
	}
	if c.Iss == "" {
		return "", fmt.Errorf("missing iss claim")
	}
	return c.Iss, nil
}

func (v *multiValidator) middleware(rule accessRule) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := bearerToken(r)
			if raw == "" {
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			info, err := v.verify(r.Context(), raw)
			if err != nil {
				log.Printf("token verification failed: %v", err)
				writeAuthError(w, "invalid_token", "invalid token")
				return
			}
			// Scope checks first so the WWW-Authenticate challenge can
			// advertise the missing scope per RFC 6750 §3.1.
			for _, s := range rule.scopes {
				if !info.hasScope(s) {
					writeAuthError(w, "insufficient_scope", "required scope: "+s, s)
					return
				}
			}
			// Custom-claim allowlist. The reason string is for server logs
			// only — clients see a generic "invalid_token" so the allowlist
			// itself isn't disclosed or easily probeable.
			if reason, ok := rule.checkClaims(info); !ok {
				log.Printf("policy reject: %s (sub=%s iss=%s)", reason, info.Subject, info.Issuer)
				writeAuthError(w, "invalid_token", "token not authorized for this resource")
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, info)))
		})
	}
}

func bearerToken(r *http.Request) string {
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}

func writeAuthError(w http.ResponseWriter, code, desc string, scopes ...string) {
	status := http.StatusUnauthorized
	if code == "insufficient_scope" {
		status = http.StatusForbidden
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

// buildVerifiers performs OIDC discovery for every trusted issuer
// concurrently and returns a map keyed by the issuer string each provider
// reports (which is what `iss` claims will match against, byte-for-byte).
func buildVerifiers(ctx context.Context, issuers []string, audience string, skipAudience bool) (map[string]*oidc.IDTokenVerifier, error) {
	type result struct {
		canonicalIssuer string
		verifier        *oidc.IDTokenVerifier
		err             error
	}
	results := make([]result, len(issuers))

	var wg sync.WaitGroup
	for i, issuer := range issuers {
		wg.Add(1)
		// Pass i and issuer explicitly so the goroutine binds to this
		// iteration's values. Go 1.22+ already makes the implicit capture
		// safe, but being explicit means the example reads correctly when
		// copied into a module on an older go directive.
		go func(i int, issuer string) {
			defer wg.Done()
			provider, err := oidc.NewProvider(ctx, issuer)
			if err != nil {
				results[i] = result{err: fmt.Errorf("discover %s: %w", issuer, err)}
				return
			}
			// Use the issuer string the provider itself returned — that's
			// the value tokens will carry in `iss`. NewProvider already
			// validated it matches the requested URL byte-for-byte.
			var meta struct {
				Issuer string `json:"issuer"`
			}
			if err := provider.Claims(&meta); err != nil {
				results[i] = result{err: fmt.Errorf("read metadata for %s: %w", issuer, err)}
				return
			}
			results[i] = result{
				canonicalIssuer: meta.Issuer,
				verifier: provider.Verifier(&oidc.Config{
					ClientID:          audience,
					SkipClientIDCheck: skipAudience,
				}),
			}
		}(i, issuer)
	}
	wg.Wait()

	verifiers := make(map[string]*oidc.IDTokenVerifier, len(issuers))
	for _, r := range results {
		if r.err != nil {
			return nil, r.err
		}
		if _, dup := verifiers[r.canonicalIssuer]; dup {
			return nil, fmt.Errorf("duplicate issuer in TRUSTED_ISSUERS after discovery: %s", r.canonicalIssuer)
		}
		verifiers[r.canonicalIssuer] = r.verifier
	}
	return verifiers, nil
}

// parseIssuerTenants parses ISSUER_TENANTS=iss1=tenantA,tenantB;iss2=tenantC,tenantD
// and validates every entry's issuer against the verifier map, so a typo
// in one variable is caught at startup instead of silently disabling the
// cross-tenant check for that issuer.
func parseIssuerTenants(raw string, verifiers map[string]*oidc.IDTokenVerifier) (map[string][]string, error) {
	if raw == "" {
		return nil, nil
	}
	out := make(map[string][]string)
	for _, entry := range strings.Split(raw, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		iss, tenantsRaw, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, fmt.Errorf("malformed ISSUER_TENANTS entry %q (want iss=tenantA,tenantB)", entry)
		}
		iss = strings.TrimSpace(iss)
		if _, known := verifiers[iss]; !known {
			canonical := make([]string, 0, len(verifiers))
			for k := range verifiers {
				canonical = append(canonical, k)
			}
			return nil, fmt.Errorf("ISSUER_TENANTS issuer %q is not a canonical TRUSTED_ISSUERS entry (canonical issuers after discovery: %v)", iss, canonical)
		}
		var tenants []string
		for _, t := range strings.Split(tenantsRaw, ",") {
			t = strings.ToLower(strings.TrimSpace(t))
			if t != "" {
				tenants = append(tenants, t)
			}
		}
		if len(tenants) == 0 {
			return nil, fmt.Errorf("issuer %q in ISSUER_TENANTS has no tenants", iss)
		}
		if _, dup := out[iss]; dup {
			return nil, fmt.Errorf("duplicate issuer in ISSUER_TENANTS: %s", iss)
		}
		out[iss] = tenants
	}
	// Require every trusted issuer to be listed when ISSUER_TENANTS is set —
	// a silent gap would let one issuer mint tokens for any tenant.
	for iss := range verifiers {
		if _, ok := out[iss]; !ok {
			return nil, fmt.Errorf("issuer %q is missing from ISSUER_TENANTS (every TRUSTED_ISSUERS entry must be listed when ISSUER_TENANTS is set)", iss)
		}
	}
	// A tenant must be owned by exactly ONE issuer, otherwise the cross-tenant
	// defense degrades silently: any of the listed issuers can sign for it.
	tenantOwner := make(map[string]string, len(out))
	for iss, tenants := range out {
		for _, t := range tenants {
			if other, dup := tenantOwner[t]; dup {
				return nil, fmt.Errorf("tenant %q listed under multiple issuers in ISSUER_TENANTS (%q and %q) — a tenant must be owned by exactly one issuer", t, other, iss)
			}
			tenantOwner[t] = iss
		}
	}
	return out, nil
}

func main() {
	_ = godotenv.Load()

	rawIssuers := strings.TrimSpace(os.Getenv("TRUSTED_ISSUERS"))
	expectedAudience := strings.TrimSpace(os.Getenv("EXPECTED_AUDIENCE"))
	skipAudience := strings.TrimSpace(os.Getenv("SKIP_AUDIENCE_CHECK")) == "1"
	rawIssuerTenants := strings.TrimSpace(os.Getenv("ISSUER_TENANTS"))

	if rawIssuers == "" {
		log.Fatal("Set TRUSTED_ISSUERS to a comma-separated list of issuer URLs " +
			"(e.g. https://auth-a.example.com,https://auth-b.example.com)")
	}
	if expectedAudience != "" && skipAudience {
		log.Fatal("Set exactly one of EXPECTED_AUDIENCE or SKIP_AUDIENCE_CHECK=1, not both")
	}
	if expectedAudience == "" && !skipAudience {
		log.Fatal("Set EXPECTED_AUDIENCE to enforce the `aud` claim, " +
			"or SKIP_AUDIENCE_CHECK=1 to opt out (some issuers don't emit aud on access tokens)")
	}

	var issuers []string
	seen := make(map[string]bool)
	for _, raw := range strings.Split(rawIssuers, ",") {
		iss := strings.TrimSpace(raw)
		if iss == "" {
			continue
		}
		// Reject duplicates pre-discovery so the operator gets a clear error
		// instead of a confusing "duplicate after discovery" message later.
		if seen[iss] {
			log.Fatalf("duplicate issuer in TRUSTED_ISSUERS: %s", iss)
		}
		seen[iss] = true
		issuers = append(issuers, iss)
	}
	if len(issuers) == 0 {
		log.Fatal("TRUSTED_ISSUERS is empty after parsing")
	}

	// Bound *total* discovery time, not per-issuer — one slow issuer must
	// not multiply startup time by N. NewProvider clones this ctx internally,
	// so the deadline doesn't leak into the long-lived JWKS keysets.
	discoverCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	verifiers, err := buildVerifiers(discoverCtx, issuers, expectedAudience, skipAudience)
	if err != nil {
		log.Fatalf("build verifiers: %v", err)
	}

	issuerTenants, err := parseIssuerTenants(rawIssuerTenants, verifiers)
	if err != nil {
		log.Fatalf("parse ISSUER_TENANTS: %v", err)
	}

	v := &multiValidator{
		verifiers:     verifiers,
		issuerTenants: issuerTenants,
		timeout:       5 * time.Second,
	}

	// Demo routes show the spread of accessRule features. Replace the
	// allowlists with values from your environment / config service if
	// they need to change without a redeploy.
	mux := http.NewServeMux()
	mux.Handle("/api/profile", v.middleware(accessRule{})(http.HandlerFunc(profileHandler)))
	mux.Handle("/api/data", v.middleware(accessRule{
		scopes:  []string{"email"},
		tenants: []string{"oa", "hwrd"},
	})(http.HandlerFunc(dataHandler)))
	mux.Handle("/api/admin", v.middleware(accessRule{
		serviceAccounts: []string{"sync-bot@oa.local"},
		projects:        []string{"admin-tools"},
	})(http.HandlerFunc(adminHandler)))
	mux.HandleFunc("/health", healthHandler)

	srv := &http.Server{
		Addr:              ":8089",
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("Trusted issuers (%d):", len(verifiers))
	for iss := range verifiers {
		if tenants := issuerTenants[iss]; tenants != nil {
			log.Printf("  - %s  →  tenants: %v", iss, tenants)
		} else {
			log.Printf("  - %s  →  tenants: (any — ISSUER_TENANTS not set)", iss)
		}
	}
	if expectedAudience != "" {
		log.Printf("Audience: %s (applied to all issuers)", expectedAudience)
	} else {
		log.Println("Audience: DISABLED (SKIP_AUDIENCE_CHECK=1)")
	}
	log.Println("Listening on :8089 — multi-issuer offline JWKS validation")
	log.Fatal(srv.ListenAndServe())
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	info, ok := infoFromContext(r.Context())
	if !ok {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":          info.Issuer,
		"subject":         info.Subject,
		"client_id":       info.Extra.ClientID,
		"audience":        info.Audience,
		"scope":           info.Extra.Scope,
		"tenant":          info.Extra.Tenant,
		"service_account": info.Extra.ServiceAccount,
		"project":         info.Extra.Project,
		"expires":         info.Expiry.UTC().Format(time.RFC3339),
	})
}

func dataHandler(w http.ResponseWriter, r *http.Request) {
	info, ok := infoFromContext(r.Context())
	if !ok {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	msg := "You have email-only access"
	if info.hasScope("profile") {
		msg = "You have email+profile access"
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": msg,
		"issuer":  info.Issuer,
		"subject": info.Subject,
		"tenant":  info.Extra.Tenant,
	})
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	info, ok := infoFromContext(r.Context())
	if !ok {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message":         "admin endpoint",
		"service_account": info.Extra.ServiceAccount,
		"project":         info.Extra.Project,
	})
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
