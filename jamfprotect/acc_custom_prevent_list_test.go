// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"errors"
	"testing"
)

func TestAcc_CustomPreventList_CRUD(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()
	name := accName("prevent-list")

	// Create
	input := CustomPreventListInput{
		Name:        name,
		Description: "acceptance test prevent list",
		Type:        "SIGNINGID",
		Tags:        []string{"acc-test"},
		List:        []string{"com.example.test"},
	}
	created, err := client.CreateCustomPreventList(ctx, input)
	if err != nil {
		t.Fatalf("CreateCustomPreventList: %v", err)
	}
	if created.ID == "" {
		t.Fatal("CreateCustomPreventList: expected non-empty ID")
	}

	// Get
	got, err := client.GetCustomPreventList(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetCustomPreventList: %v", err)
	}
	if got.Name != name {
		t.Fatalf("GetCustomPreventList: expected name %q, got %q", name, got.Name)
	}

	// List
	lists, err := client.ListCustomPreventLists(ctx)
	if err != nil {
		t.Fatalf("ListCustomPreventLists: %v", err)
	}
	found := false
	for _, l := range lists {
		if l.ID == created.ID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ListCustomPreventLists: created list %q not found", created.ID)
	}

	// Update
	updatedName := name + "-updated"
	updateInput := CustomPreventListInput{
		Name:        updatedName,
		Description: "updated description",
		Type:        "SIGNINGID",
		Tags:        []string{"acc-test", "updated"},
		List:        []string{"com.example.test", "com.example.test2"},
	}
	updated, err := client.UpdateCustomPreventList(ctx, created.ID, updateInput)
	if err != nil {
		t.Fatalf("UpdateCustomPreventList: %v", err)
	}
	if updated.Name != updatedName {
		t.Fatalf("UpdateCustomPreventList: expected name %q, got %q", updatedName, updated.Name)
	}

	// Delete
	if err := client.DeleteCustomPreventList(ctx, created.ID); err != nil {
		t.Fatalf("DeleteCustomPreventList: %v", err)
	}

	// Get after delete
	_, err = client.GetCustomPreventList(ctx, created.ID)
	if err == nil {
		t.Fatal("GetCustomPreventList after delete: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetCustomPreventList after delete: expected ErrNotFound, got %v", err)
	}
}
