// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"testing"
)

func TestAcc_Role_CRUD(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()
	name := accName("role")

	// Create
	input := RoleInput{
		Name:           name,
		ReadResources:  []string{"Computer", "Plan"},
		WriteResources: []string{"Plan"},
	}
	created, err := client.CreateRole(ctx, input)
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if created.ID == "" {
		t.Fatal("CreateRole: expected non-empty ID")
	}
	if created.Name != name {
		t.Fatalf("CreateRole: expected name %q, got %q", name, created.Name)
	}

	// Get
	got, err := client.GetRole(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetRole: %v", err)
	}
	if got.ID != created.ID {
		t.Fatalf("GetRole: expected ID %q, got %q", created.ID, got.ID)
	}
	if got.Name != name {
		t.Fatalf("GetRole: expected name %q, got %q", name, got.Name)
	}

	// List
	roles, err := client.ListRoles(ctx)
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	found := false
	for _, r := range roles {
		if r.ID == created.ID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ListRoles: created role %q not found in list", created.ID)
	}

	// Update
	updatedName := name + "-updated"
	updateInput := RoleInput{
		Name:           updatedName,
		ReadResources:  []string{"Computer"},
		WriteResources: []string{"Computer"},
	}
	updated, err := client.UpdateRole(ctx, created.ID, updateInput)
	if err != nil {
		t.Fatalf("UpdateRole: %v", err)
	}
	if updated.Name != updatedName {
		t.Fatalf("UpdateRole: expected name %q, got %q", updatedName, updated.Name)
	}

	// Get after update
	got, err = client.GetRole(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetRole after update: %v", err)
	}
	if got.Name != updatedName {
		t.Fatalf("GetRole after update: expected name %q, got %q", updatedName, got.Name)
	}

	// Delete
	if err := client.DeleteRole(ctx, created.ID); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}

	// Get after delete — the API may return ErrNotFound, a GraphQL error
	// for null non-nullable fields, or a nil result depending on the resource.
	got, err = client.GetRole(ctx, created.ID)
	if err == nil && got != nil && got.Name != "" {
		t.Fatal("GetRole after delete: expected deleted role to be gone")
	}
}
