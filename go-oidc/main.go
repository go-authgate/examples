// OIDC web example using github.com/coreos/go-oidc/v3/oidc.
//
// Demonstrates the Authorization Code flow against any OpenID Connect
// provider (including AuthGate):
//
//   - Provider discovery via /.well-known/openid-configuration
//   - Authorization request with state (CSRF), nonce (replay protection),
//     and PKCE (S256) — required by most modern providers
//   - Code exchange with golang.org/x/oauth2
//   - Cryptographic ID token verification (signature, iss, aud, exp, nonce)
//   - UserInfo endpoint query
//
// Usage:
//
//	export ISSUER_URL=https://auth.example.com
//	export CLIENT_ID=your-client-id
//	export CLIENT_SECRET=your-client-secret            # optional (public clients)
//	export REDIRECT_URL=http://localhost:8088/callback # optional
//	go run main.go
//
// Then open http://localhost:8088/ in a browser.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

const (
	stateCookie    = "oidc_state"
	nonceCookie    = "oidc_nonce"
	verifierCookie = "oidc_pkce_verifier"
)

type app struct {
	oauth2   oauth2.Config
	verifier *oidc.IDTokenVerifier
	provider *oidc.Provider
}

func main() {
	_ = godotenv.Load()

	issuerURL := os.Getenv("ISSUER_URL")
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET") // optional (public clients)
	redirectURL := os.Getenv("REDIRECT_URL")
	if redirectURL == "" {
		redirectURL = "http://localhost:8088/callback"
	}
	if issuerURL == "" || clientID == "" {
		log.Fatal("Set ISSUER_URL and CLIENT_ID (CLIENT_SECRET is optional for public clients)")
	}

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		log.Fatalf("discover provider: %v", err)
	}

	a := &app{
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: clientID}),
		oauth2: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", a.handleIndex)
	mux.HandleFunc("/login", a.handleLogin)
	mux.HandleFunc("/callback", a.handleCallback)

	srv := &http.Server{
		Addr:              ":8088",
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("Issuer:   %s", issuerURL)
	log.Printf("Redirect: %s", redirectURL)
	log.Println("Listening on http://localhost:8088 — open / to start")
	log.Fatal(srv.ListenAndServe())
}

func (a *app) handleIndex(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintln(w, `<!doctype html><html><body>
<h1>go-oidc example</h1>
<p><a href="/login">Sign in</a></p>
</body></html>`)
}

func (a *app) handleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := randomString(24)
	if err != nil {
		http.Error(w, "failed to generate state", http.StatusInternalServerError)
		return
	}
	nonce, err := randomString(24)
	if err != nil {
		http.Error(w, "failed to generate nonce", http.StatusInternalServerError)
		return
	}

	// PKCE (RFC 7636) — oauth2.GenerateVerifier returns a 43-char base64url
	// random string. S256ChallengeOption derives the SHA-256 challenge from
	// it and sets code_challenge + code_challenge_method=S256 on the URL.
	pkceVerifier := oauth2.GenerateVerifier()

	setShortCookie(w, r, stateCookie, state)
	setShortCookie(w, r, nonceCookie, nonce)
	setShortCookie(w, r, verifierCookie, pkceVerifier)

	authURL := a.oauth2.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(pkceVerifier),
	)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (a *app) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if errParam := r.URL.Query().Get("error"); errParam != "" {
		desc := r.URL.Query().Get("error_description")
		http.Error(w, fmt.Sprintf("provider returned error: %s: %s", errParam, desc), http.StatusBadRequest)
		return
	}

	stateC, err := r.Cookie(stateCookie)
	if err != nil || stateC.Value == "" || stateC.Value != r.URL.Query().Get("state") {
		http.Error(w, "state mismatch — possible CSRF", http.StatusBadRequest)
		return
	}
	clearCookie(w, stateCookie)

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}

	verifierC, err := r.Cookie(verifierCookie)
	if err != nil || verifierC.Value == "" {
		http.Error(w, "missing pkce verifier cookie", http.StatusBadRequest)
		return
	}
	clearCookie(w, verifierCookie)

	oauth2Token, err := a.oauth2.Exchange(ctx, code,
		oauth2.VerifierOption(verifierC.Value),
	)
	if err != nil {
		http.Error(w, "code exchange failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		http.Error(w, "no id_token in token response", http.StatusBadGateway)
		return
	}

	idToken, err := a.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "id_token verification failed: "+err.Error(), http.StatusUnauthorized)
		return
	}

	nonceC, err := r.Cookie(nonceCookie)
	if err != nil || nonceC.Value == "" || idToken.Nonce != nonceC.Value {
		http.Error(w, "nonce mismatch — possible replay", http.StatusUnauthorized)
		return
	}
	clearCookie(w, nonceCookie)

	if idToken.AccessTokenHash != "" {
		if err := idToken.VerifyAccessToken(oauth2Token.AccessToken); err != nil {
			http.Error(w, "at_hash verification failed: "+err.Error(), http.StatusUnauthorized)
			return
		}
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "failed to parse id_token claims: "+err.Error(), http.StatusInternalServerError)
		return
	}

	userInfo, userInfoErr := a.provider.UserInfo(ctx, oauth2.StaticTokenSource(oauth2Token))
	var userInfoClaims map[string]any
	if userInfoErr == nil {
		if err := userInfo.Claims(&userInfoClaims); err != nil {
			userInfoErr = err
		}
	}

	resp := map[string]any{
		"subject":           idToken.Subject,
		"issuer":            idToken.Issuer,
		"audience":          idToken.Audience,
		"expiry":            idToken.Expiry,
		"id_token_claims":   claims,
		"access_token":      maskToken(oauth2Token.AccessToken),
		"refresh_token":     maskToken(oauth2Token.RefreshToken),
		"token_type":        oauth2Token.TokenType,
		"token_expiry":      oauth2Token.Expiry,
		"userinfo":          userInfoClaims,
		"userinfo_fetch_ok": userInfoErr == nil,
	}
	if userInfoErr != nil && !errors.Is(userInfoErr, context.Canceled) {
		resp["userinfo_error"] = userInfoErr.Error()
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp)
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func setShortCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
}

func maskToken(s string) string {
	if len(s) <= 8 {
		if s == "" {
			return ""
		}
		return "****"
	}
	return s[:8] + "..."
}
