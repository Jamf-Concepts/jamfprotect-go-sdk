// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"os"
	"testing"
)

func TestAcc_Downloads_Get(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()

	downloads, err := client.GetOrganizationDownloads(ctx)
	if err != nil {
		t.Fatalf("GetOrganizationDownloads: %v", err)
	}
	if downloads.InstallerUUID == "" {
		t.Fatal("GetOrganizationDownloads: expected non-empty InstallerUUID")
	}
}

func TestAcc_Connections_List(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()

	connections, err := client.ListConnections(ctx)
	if err != nil {
		t.Fatalf("ListConnections: %v", err)
	}
	// Every tenant has at least the database connection.
	if len(connections) == 0 {
		t.Fatal("ListConnections: expected at least one connection")
	}
}

func TestAcc_Computers_List(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()

	// Just verify the call succeeds — the tenant may not have enrolled computers.
	_, err := client.ListComputers(ctx)
	if err != nil {
		t.Fatalf("ListComputers: %v", err)
	}
}

func TestAcc_FileTokenCache(t *testing.T) {
	t.Helper()

	if os.Getenv("JAMFPROTECT_ACC") == "" {
		t.Skip("set JAMFPROTECT_ACC=1 to run acceptance tests")
	}

	baseURL := os.Getenv("JAMFPROTECT_BASE_URL")
	clientID := os.Getenv("JAMFPROTECT_CLIENT_ID")
	clientSecret := os.Getenv("JAMFPROTECT_CLIENT_SECRET")

	if baseURL == "" || clientID == "" || clientSecret == "" {
		t.Fatal("JAMFPROTECT_BASE_URL, JAMFPROTECT_CLIENT_ID, and JAMFPROTECT_CLIENT_SECRET must be set")
	}

	cacheDir := t.TempDir()
	ctx := context.Background()

	client1 := NewClient(baseURL, clientID, clientSecret,
		WithUserAgent("jamfprotect-go-sdk/acc-test"),
		WithFileTokenCache(cacheDir),
	)

	tok1, err := client1.AccessToken(ctx)
	if err != nil {
		t.Fatalf("first AccessToken call: %v", err)
	}
	if tok1.AccessToken == "" {
		t.Fatal("first AccessToken: expected non-empty token")
	}

	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		t.Fatalf("reading cache dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 cache file, got %d", len(entries))
	}

	client2 := NewClient(baseURL, clientID, clientSecret,
		WithUserAgent("jamfprotect-go-sdk/acc-test"),
		WithFileTokenCache(cacheDir),
	)

	tok2, err := client2.AccessToken(ctx)
	if err != nil {
		t.Fatalf("second AccessToken call: %v", err)
	}
	if tok2.AccessToken != tok1.AccessToken {
		t.Error("expected second client to return the same cached token")
	}

	_, err = client2.ListComputers(ctx)
	if err != nil {
		t.Fatalf("ListComputers with cached token: %v", err)
	}
}
