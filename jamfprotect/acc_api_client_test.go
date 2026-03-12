// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"testing"
)

func TestAcc_ApiClient_CRUD(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()
	name := accName("api-client")

	// Create
	input := ApiClientInput{
		Name:    name,
		RoleIDs: []string{},
	}
	created, err := client.CreateApiClient(ctx, input)
	if err != nil {
		t.Fatalf("CreateApiClient: %v", err)
	}
	if created.ClientID == "" {
		t.Fatal("CreateApiClient: expected non-empty ClientID")
	}
	if created.Password == "" {
		t.Fatal("CreateApiClient: expected non-empty Password on create")
	}

	// Get
	got, err := client.GetApiClient(ctx, created.ClientID)
	if err != nil {
		t.Fatalf("GetApiClient: %v", err)
	}
	if got.Name != name {
		t.Fatalf("GetApiClient: expected name %q, got %q", name, got.Name)
	}

	// List
	clients, err := client.ListApiClients(ctx)
	if err != nil {
		t.Fatalf("ListApiClients: %v", err)
	}
	found := false
	for _, c := range clients {
		if c.ClientID == created.ClientID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ListApiClients: created client %q not found", created.ClientID)
	}

	// Update
	updatedName := name + "-updated"
	updateInput := ApiClientInput{
		Name:    updatedName,
		RoleIDs: []string{},
	}
	updated, err := client.UpdateApiClient(ctx, created.ClientID, updateInput)
	if err != nil {
		t.Fatalf("UpdateApiClient: %v", err)
	}
	if updated.Name != updatedName {
		t.Fatalf("UpdateApiClient: expected name %q, got %q", updatedName, updated.Name)
	}

	// Delete
	if err := client.DeleteApiClient(ctx, created.ClientID); err != nil {
		t.Fatalf("DeleteApiClient: %v", err)
	}

	// Get after delete — API may return nil result or ErrNotFound.
	got, err = client.GetApiClient(ctx, created.ClientID)
	if err == nil && got != nil && got.ClientID != "" {
		t.Fatal("GetApiClient after delete: expected deleted client to be gone")
	}
}
