# jamfprotect-go-sdk

A Go client library for the [Jamf Protect](https://www.jamf.com/products/jamf-protect/) API.

## Installation

```sh
go get github.com/Jamf-Concepts/jamfprotect-go-sdk
```

Requires Go 1.26 or later.

## Usage

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect"
)

func main() {
	client := jamfprotect.NewClient(
		"https://your-tenant.protect.jamfcloud.com",
		os.Getenv("JAMFPROTECT_CLIENT_ID"),
		os.Getenv("JAMFPROTECT_CLIENT_SECRET"),
	)

	ctx := context.Background()

	roles, err := client.ListRoles(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Found %d roles\n", len(roles))
}
```

## Authentication

The client uses OAuth2 client credentials (client ID + client secret) to authenticate with the Jamf Protect API. Tokens are cached and refreshed automatically.

Create API client credentials in **Jamf Protect > Administrative > API Clients**.

## Configuration Options

```go
// Custom user agent
client := jamfprotect.NewClient(baseURL, clientID, clientSecret,
	jamfprotect.WithUserAgent("my-app/1.0.0"),
)

// Custom HTTP client
client := jamfprotect.NewClient(baseURL, clientID, clientSecret,
	jamfprotect.WithHTTPClient(myHTTPClient),
)

// Enable request/response logging
client := jamfprotect.NewClient(baseURL, clientID, clientSecret,
	jamfprotect.WithLogger(myLogger),
)
```

## Error Handling

The SDK provides sentinel errors for common failure cases:

```go
import "errors"

role, err := client.GetRole(ctx, id)
if errors.Is(err, jamfprotect.ErrNotFound) {
	// Resource does not exist
}
if errors.Is(err, jamfprotect.ErrAuthentication) {
	// Invalid credentials or expired token
}
if errors.Is(err, jamfprotect.ErrGraphQL) {
	// GraphQL API error
}
```

## API Documentation

Full API reference is available on [pkg.go.dev](https://pkg.go.dev/github.com/Jamf-Concepts/jamfprotect-go-sdk/jamfprotect).

## License

[MIT](LICENSE)
