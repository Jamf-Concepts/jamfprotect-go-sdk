// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
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
