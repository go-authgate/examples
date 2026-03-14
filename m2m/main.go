// M2M (Machine-to-Machine) example using Client Credentials grant.
//
// This example demonstrates service-to-service authentication where
// no user interaction is needed. The token is automatically cached
// and refreshed before expiry.
//
// Usage:
//
//	export AUTHGATE_URL=https://auth.example.com
//	export CLIENT_ID=your-client-id
//	export CLIENT_SECRET=your-client-secret
//	go run main.go
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/go-authgate/sdk-go/clientcreds"
	"github.com/go-authgate/sdk-go/discovery"
	"github.com/go-authgate/sdk-go/oauth"
)

func main() {
	authgateURL := os.Getenv("AUTHGATE_URL")
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")

	if authgateURL == "" || clientID == "" || clientSecret == "" {
		log.Fatal("Set AUTHGATE_URL, CLIENT_ID, CLIENT_SECRET")
	}

	ctx := context.Background()

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
	client, err := oauth.NewClient(clientID, meta.Endpoints(),
		oauth.WithClientSecret(clientSecret),
	)
	if err != nil {
		log.Fatal(err)
	}

	// 3. Create auto-refreshing token source
	ts := clientcreds.NewTokenSource(client,
		clientcreds.WithScopes("read", "write"),
		clientcreds.WithExpiryDelta(30*time.Second),
	)

	// 4. Use the auto-authenticated HTTP client
	httpClient := ts.HTTPClient()
	resp, err := httpClient.Get(authgateURL + "/oauth/userinfo")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("Status: %d\nBody: %s\n", resp.StatusCode, body)
}
