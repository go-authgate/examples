// CLI example with auto-detection of browser availability.
//
// If a browser is available (local machine), it uses Authorization Code + PKCE.
// If not (SSH session), it falls back to Device Code flow.
// Tokens are persisted to OS keyring (with file fallback) for reuse.
//
// Usage:
//
//	export AUTHGATE_URL=https://auth.example.com
//	export CLIENT_ID=your-client-id
//	go run main.go
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/go-authgate/sdk-go/authflow"
	"github.com/go-authgate/sdk-go/credstore"
	"github.com/go-authgate/sdk-go/discovery"
	"github.com/go-authgate/sdk-go/oauth"
)

func main() {
	authgateURL := os.Getenv("AUTHGATE_URL")
	clientID := os.Getenv("CLIENT_ID")

	if authgateURL == "" || clientID == "" {
		log.Fatal("Set AUTHGATE_URL, CLIENT_ID")
	}

	ctx := context.Background()
	scopes := []string{"openid", "profile", "email"}

	// 1. Auto-discover endpoints
	disco, err := discovery.NewClient(authgateURL)
	if err != nil {
		log.Fatal(err)
	}
	meta, err := disco.Fetch(ctx)
	if err != nil {
		log.Fatal(err)
	}

	// 2. Create OAuth client
	client, err := oauth.NewClient(clientID, meta.Endpoints())
	if err != nil {
		log.Fatal(err)
	}

	// 3. Try loading cached token first
	store := credstore.DefaultTokenSecureStore("authgate-cli", ".authgate-tokens.json")
	ts := authflow.NewTokenSource(client,
		authflow.WithStore(store),
		authflow.WithClientID(clientID),
	)

	token, err := ts.Token(ctx)
	if err == nil {
		fmt.Println("Using cached token")
		printTokenInfo(ctx, client, token)
		return
	}

	// 4. No cached token — authenticate
	if authflow.CheckBrowserAvailability() {
		fmt.Println("Opening browser for authentication...")
		token, err = authflow.RunAuthCodeFlow(ctx, client, scopes)
	} else {
		fmt.Println("No browser detected, using device code flow...")
		token, err = authflow.RunDeviceFlow(ctx, client, scopes,
			authflow.WithOpenBrowser(false),
		)
	}
	if err != nil {
		log.Fatal(err)
	}

	// 5. Save token for next time
	if saveErr := ts.SaveToken(token); saveErr != nil {
		log.Printf("Warning: failed to save token: %v", saveErr)
	}

	fmt.Println("Authentication successful!")
	printTokenInfo(ctx, client, token)
}

func printTokenInfo(ctx context.Context, client *oauth.Client, token *oauth.Token) {
	info, err := client.UserInfo(ctx, token.AccessToken)
	if err != nil {
		fmt.Printf("Token: %s...\n", token.AccessToken[:20])
		return
	}

	fmt.Printf("User: %s (%s)\n", info.Name, info.Email)
	fmt.Printf("Subject: %s\n", info.Sub)
}
