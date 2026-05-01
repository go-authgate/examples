// testissuer — local fake AuthGate(s) for testing the multi-issuer
// resource server in ../main.go.
//
// What it does:
//
//   - Spins up two HTTP issuers (auth-a on :9001, auth-b on :9002), each
//     with an ephemeral RSA-2048 keypair generated at startup.
//   - Each issuer serves OIDC discovery + JWKS so the resource server can
//     auto-discover and cache the public key.
//   - Each issuer exposes a `/sign` endpoint that mints arbitrary JWTs
//     signed by THAT issuer's key. You set `iss` implicitly by choosing
//     the port; everything else (`aud`, `domain`, `sa`,
//     `project`, `scope`, `sub`, `client_id`, `ttl`) is a query param.
//
// Why this exists: ../get-token.sh in ../../go-jwks/ talks to a real
// AuthGate via Client Credentials. For multi-issuer + multi-domain
// testing you typically need to mint tokens with arbitrary `iss` and
// `domain` to exercise both happy paths and security paths (cross-domain
// rejection, untrusted issuer, etc.) without standing up two real
// AuthGates.
//
// Security: this server signs anything you ask for — it's a TEST tool.
// Run it on localhost only, never expose it.
//
// Usage:
//
//  1. Start the test issuers:
//     go run ./testissuer
//
//  2. Point the resource server at them:
//     TRUSTED_ISSUERS=http://127.0.0.1:9001,http://127.0.0.1:9002 \
//     EXPECTED_AUDIENCE=https://api.example.com \
//     ISSUER_DOMAINS='http://127.0.0.1:9001=oa,hwrd;http://127.0.0.1:9002=swrd,cdomain' \
//     go run .
//
//  3. Mint a token and call the API:
//     TOK=$(curl -s 'http://127.0.0.1:9001/sign?domain=oa&scope=email+profile&sa=sync-bot@oa.local&project=admin-tools')
//     curl -i -H "Authorization: Bearer $TOK" http://localhost:8089/api/profile
//
//  4. Try a cross-domain attack — should be rejected by ISSUER_DOMAINS:
//     TOK=$(curl -s 'http://127.0.0.1:9001/sign?domain=swrd')
//     curl -i -H "Authorization: Bearer $TOK" http://localhost:8089/api/profile
//     # → 401; resource server log shows "token verification failed: issuer not permitted for this domain: ..."
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type issuer struct {
	name    string
	port    int
	baseURL string
	key     *rsa.PrivateKey
	kid     string
	signer  jose.Signer
}

func newIssuer(name string, port int) (*issuer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("gen key for %s: %w", name, err)
	}
	// kid must uniquely identify this key so JWKS clients refresh after a
	// restart. Second-resolution timestamps can collide on rapid restarts
	// (same second, same name) and would silently let a verifier keep using
	// the previous public key while the new signer holds a different one —
	// signature checks would then fail. UnixNano + 8 random bytes is enough.
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return nil, fmt.Errorf("gen kid entropy for %s: %w", name, err)
	}
	kid := fmt.Sprintf("%s-%d-%x", name, time.Now().UnixNano(), suffix)
	signOpts := (&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), kid)
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		signOpts,
	)
	if err != nil {
		return nil, fmt.Errorf("new signer for %s: %w", name, err)
	}
	return &issuer{
		name:    name,
		port:    port,
		baseURL: fmt.Sprintf("http://127.0.0.1:%d", port),
		key:     key,
		kid:     kid,
		signer:  signer,
	}, nil
}

func (i *issuer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", i.discovery)
	mux.HandleFunc("/jwks.json", i.jwks)
	mux.HandleFunc("/sign", i.sign)
	mux.HandleFunc("/", i.index)
	return mux
}

func (i *issuer) discovery(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                i.baseURL,
		"jwks_uri":                              i.baseURL + "/jwks.json",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		// token_endpoint isn't used by the JWKS resource server, but coreos/go-oidc
		// expects the field to exist in the discovery doc.
		"token_endpoint": i.baseURL + "/sign",
	})
}

func (i *issuer) jwks(w http.ResponseWriter, _ *http.Request) {
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{
			Key:       &i.key.PublicKey,
			KeyID:     i.kid,
			Algorithm: "RS256",
			Use:       "sig",
		}},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(jwks)
}

func (i *issuer) sign(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	aud := def(q.Get("aud"), "https://api.example.com")
	sub := def(q.Get("sub"), "test-user-1")
	scope := def(q.Get("scope"), "email profile")
	clientID := def(q.Get("client_id"), "test-client")
	domain := q.Get("domain")
	sa := q.Get("sa")
	project := q.Get("project")
	ttlSec, err := strconv.Atoi(def(q.Get("ttl"), "300"))
	if err != nil || ttlSec <= 0 {
		http.Error(w, "ttl must be a positive integer (seconds)", http.StatusBadRequest)
		return
	}

	now := time.Now()
	claims := map[string]any{
		"iss":       i.baseURL,
		"sub":       sub,
		"aud":       []string{aud},
		"iat":       now.Unix(),
		"exp":       now.Add(time.Duration(ttlSec) * time.Second).Unix(),
		"client_id": clientID,
		"scope":     scope,
	}
	// Custom claims are only set when explicitly requested, so you can mint
	// "missing claim" tokens to verify the resource server's fail-closed
	// behavior on routes that require them.
	if domain != "" {
		claims["domain"] = domain
	}
	if sa != "" {
		claims["service_account"] = sa
	}
	if project != "" {
		claims["project"] = project
	}

	token, err := jwt.Signed(i.signer).Claims(claims).Serialize()
	if err != nil {
		http.Error(w, "sign: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("[%s] signed: sub=%q aud=%q domain=%q sa=%q project=%q scope=%q ttl=%ds",
		i.name, sub, aud, domain, sa, project, scope, ttlSec)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, token)
}

func (i *issuer) index(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "test issuer %q at %s\n\nendpoints:\n"+
		"  GET /.well-known/openid-configuration\n"+
		"  GET /jwks.json\n"+
		"  GET /sign?aud=...&sub=...&domain=...&sa=...&project=...&scope=...&ttl=...\n",
		i.name, i.baseURL)
}

func def(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

func main() {
	configs := []struct {
		name string
		port int
	}{
		{"auth-a", 9001},
		{"auth-b", 9002},
	}
	// Bind every listener up front so a port-in-use failure aborts the whole
	// program loudly, before we print an env block that would tell the user
	// to trust an issuer that never came up.
	type bound struct {
		is *issuer
		ln net.Listener
	}
	bounds := make([]bound, 0, len(configs))
	for _, c := range configs {
		is, err := newIssuer(c.name, c.port)
		if err != nil {
			log.Fatal(err)
		}
		// Bind explicitly to loopback so this signing oracle never accepts
		// requests from the local network even if the host's firewall is open.
		// The README warns "test tool, never expose it" — this enforces it.
		addr := fmt.Sprintf("127.0.0.1:%d", is.port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatalf("listen on %s: %v", addr, err)
		}
		bounds = append(bounds, bound{is, ln})
		log.Printf("issuer %q on %s  (kid=%s)", is.name, is.baseURL, is.kid)
	}

	urls := make([]string, 0, len(bounds))
	for _, b := range bounds {
		urls = append(urls, b.is.baseURL)
	}
	log.Println("─── resource server env (copy-paste) ──────────────────────────")
	log.Printf("TRUSTED_ISSUERS=%s", strings.Join(urls, ","))
	log.Printf("EXPECTED_AUDIENCE=https://api.example.com")
	log.Printf("ISSUER_DOMAINS='%s=oa,hwrd;%s=swrd,cdomain'", urls[0], urls[1])
	log.Println("───────────────────────────────────────────────────────────────")

	var wg sync.WaitGroup
	for _, b := range bounds {
		wg.Add(1)
		// Pass b explicitly so the goroutine binds to this iteration's
		// listener/issuer pair. Go 1.22+ already makes the implicit capture
		// safe, but being explicit means the example reads correctly when
		// copied into a module on an older go directive.
		go func(b bound) {
			defer wg.Done()
			srv := &http.Server{
				Handler:           b.is.handler(),
				ReadHeaderTimeout: 5 * time.Second,
			}
			// Test harness invariant: both issuers must stay up. If one dies
			// unexpectedly, scenarios that depend on the other become silent
			// no-ops, so fail loudly instead of carrying on with a half-up
			// fixture.
			if err := srv.Serve(b.ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("issuer %q stopped: %v", b.is.name, err)
			}
		}(b)
	}
	wg.Wait()
}
