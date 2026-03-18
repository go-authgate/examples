// Web Service example using Bearer token middleware.
//
// This example demonstrates how to protect API endpoints with
// Bearer token validation. Works with any Go HTTP framework.
//
// Usage:
//
//	export AUTHGATE_URL=https://auth.example.com
//	export CLIENT_ID=your-client-id
//	go run main.go
//
// Test:
//
//	curl -H "Authorization: Bearer <token>" http://localhost:8080/api/profile
//	curl -H "Authorization: Bearer <token>" http://localhost:8080/api/data
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/go-authgate/sdk-go/discovery"
	"github.com/go-authgate/sdk-go/middleware"
	"github.com/go-authgate/sdk-go/oauth"
)

func main() {
	authgateURL := os.Getenv("AUTHGATE_URL")
	clientID := os.Getenv("CLIENT_ID")

	if authgateURL == "" || clientID == "" {
		log.Fatal("Set AUTHGATE_URL, CLIENT_ID")
	}

	// 1. Auto-discover endpoints
	disco, err := discovery.NewClient(authgateURL)
	if err != nil {
		log.Fatal(err)
	}
	meta, err := disco.Fetch(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	// 2. Create OAuth client for token validation
	oauthClient, err := oauth.NewClient(clientID, meta.Endpoints())
	if err != nil {
		log.Fatal(err)
	}

	// 3. Create middleware
	auth := middleware.BearerAuth(
		middleware.WithOAuthClient(oauthClient),
	)

	authWithScope := middleware.BearerAuth(
		middleware.WithOAuthClient(oauthClient),
		middleware.WithRequiredScopes("read"),
	)

	// 4. Register routes
	mux := http.NewServeMux()
	mux.Handle("/api/profile", auth(http.HandlerFunc(profileHandler)))
	mux.Handle("/api/data", authWithScope(http.HandlerFunc(dataHandler)))
	mux.HandleFunc("/health", healthHandler)

	log.Println("Listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	info, ok := middleware.TokenInfoFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"user_id":      info.UserID,
		"client_id":    info.ClientID,
		"scope":        info.Scope,
		"subject_type": info.SubjectType,
	})
}

func dataHandler(w http.ResponseWriter, r *http.Request) {
	info, ok := middleware.TokenInfoFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Additional scope check within handler
	msg := "You have read-only access"
	if middleware.HasScope(r.Context(), "write") {
		msg = "You have read+write access"
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": msg,
		"user":    info.UserID,
	})
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
