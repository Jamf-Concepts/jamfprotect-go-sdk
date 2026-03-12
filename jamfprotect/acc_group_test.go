// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"testing"
)

func TestAcc_Group_CRUD(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()
	name := accName("group")

	// Create
	input := GroupInput{
		Name:        name,
		AccessGroup: false,
		RoleIDs:     []string{},
	}
	created, err := client.CreateGroup(ctx, input)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if created.ID == "" {
		t.Fatal("CreateGroup: expected non-empty ID")
	}

	// Get
	got, err := client.GetGroup(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetGroup: %v", err)
	}
	if got.Name != name {
		t.Fatalf("GetGroup: expected name %q, got %q", name, got.Name)
	}

	// List
	groups, err := client.ListGroups(ctx)
	if err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	found := false
	for _, g := range groups {
		if g.ID == created.ID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ListGroups: created group %q not found", created.ID)
	}

	// Update
	updatedName := name + "-updated"
	updateInput := GroupInput{
		Name:        updatedName,
		AccessGroup: false,
		RoleIDs:     []string{},
	}
	updated, err := client.UpdateGroup(ctx, created.ID, updateInput)
	if err != nil {
		t.Fatalf("UpdateGroup: %v", err)
	}
	if updated.Name != updatedName {
		t.Fatalf("UpdateGroup: expected name %q, got %q", updatedName, updated.Name)
	}

	// Delete
	if err := client.DeleteGroup(ctx, created.ID); err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}

	// Get after delete — the API may return ErrNotFound, a GraphQL error,
	// or a nil result depending on the resource.
	got, err = client.GetGroup(ctx, created.ID)
	if err == nil && got != nil && got.Name != "" {
		t.Fatal("GetGroup after delete: expected deleted group to be gone")
	}
}
