// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"errors"
	"testing"
)

func TestAcc_RemovableStorageControlSet_CRUD(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()
	name := accName("usb-control")

	// Create
	input := RemovableStorageControlSetInput{
		Name:               name,
		Description:        "acceptance test USB control set",
		DefaultMountAction: "ReadWrite",
		Rules:              []RemovableStorageControlRuleInput{},
	}
	created, err := client.CreateRemovableStorageControlSet(ctx, input)
	if err != nil {
		t.Fatalf("CreateRemovableStorageControlSet: %v", err)
	}
	if created.ID == "" {
		t.Fatal("CreateRemovableStorageControlSet: expected non-empty ID")
	}

	// Get
	got, err := client.GetRemovableStorageControlSet(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetRemovableStorageControlSet: %v", err)
	}
	if got.Name != name {
		t.Fatalf("GetRemovableStorageControlSet: expected name %q, got %q", name, got.Name)
	}

	// List
	sets, err := client.ListRemovableStorageControlSets(ctx)
	if err != nil {
		t.Fatalf("ListRemovableStorageControlSets: %v", err)
	}
	found := false
	for _, s := range sets {
		if s.ID == created.ID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ListRemovableStorageControlSets: created set %q not found", created.ID)
	}

	// Update
	updatedName := name + "-updated"
	updateInput := RemovableStorageControlSetInput{
		Name:               updatedName,
		Description:        "updated description",
		DefaultMountAction: "Prevented",
		Rules:              []RemovableStorageControlRuleInput{},
	}
	updated, err := client.UpdateRemovableStorageControlSet(ctx, created.ID, updateInput)
	if err != nil {
		t.Fatalf("UpdateRemovableStorageControlSet: %v", err)
	}
	if updated.Name != updatedName {
		t.Fatalf("UpdateRemovableStorageControlSet: expected name %q, got %q", updatedName, updated.Name)
	}

	// Delete
	if err := client.DeleteRemovableStorageControlSet(ctx, created.ID); err != nil {
		t.Fatalf("DeleteRemovableStorageControlSet: %v", err)
	}

	// Get after delete
	_, err = client.GetRemovableStorageControlSet(ctx, created.ID)
	if err == nil {
		t.Fatal("GetRemovableStorageControlSet after delete: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetRemovableStorageControlSet after delete: expected ErrNotFound, got %v", err)
	}
}
