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

	authgate "github.com/go-authgate/sdk-go"
	"github.com/go-authgate/sdk-go/oauth"
)

func main() {
	ctx := context.Background()
	client, token, err := authgate.New(ctx,
		os.Getenv("AUTHGATE_URL"),
		os.Getenv("CLIENT_ID"),
		authgate.WithScopes("profile", "email"),
		authgate.WithFlowMode(authgate.FlowModeDevice),
	)
	if err != nil {
		log.Fatal(err)
	}
	printTokenInfo(ctx, client, token)
}

func maskToken(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:8] + "..."
}

func printTokenInfo(ctx context.Context, client *oauth.Client, token *oauth.Token) {
	info, err := client.UserInfo(ctx, token.AccessToken)
	if err != nil {
		fmt.Printf("Token: %s (UserInfo error: %v)\n", maskToken(token.AccessToken), err)
		return
	}

	fmt.Printf("User: %s (%s)\n", info.Name, info.Email)
	fmt.Printf("Subject: %s\n", info.Sub)
	fmt.Printf("Access Token: %s\n", maskToken(token.AccessToken))
	fmt.Printf("Refresh Token: %s\n", maskToken(token.RefreshToken))
	fmt.Printf("Token Type: %s\n", token.TokenType)
	fmt.Printf("Expires In: %d\n", token.ExpiresIn)
	fmt.Printf("Expires At: %s\n", token.ExpiresAt)
	fmt.Printf("Scope: %s\n", token.Scope)
	fmt.Printf("ID Token: %s\n", maskToken(token.IDToken))

	// Fetch token info for detailed scope and metadata
	tokenInfo, err := client.TokenInfoRequest(ctx, token.AccessToken)
	if err != nil {
		fmt.Printf("TokenInfo error: %v\n", err)
		return
	}
	fmt.Printf("TokenInfo Active: %v\n", tokenInfo.Active)
	fmt.Printf("TokenInfo UserID: %s\n", tokenInfo.UserID)
	fmt.Printf("TokenInfo ClientID: %s\n", tokenInfo.ClientID)
	fmt.Printf("TokenInfo Scope: %s\n", tokenInfo.Scope)
	fmt.Printf("TokenInfo SubjectType: %s\n", tokenInfo.SubjectType)
	fmt.Printf("TokenInfo Issuer: %s\n", tokenInfo.Iss)
	fmt.Printf("TokenInfo Exp: %d\n", tokenInfo.Exp)
}
