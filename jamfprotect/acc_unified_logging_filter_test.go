// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"errors"
	"testing"
)

func TestAcc_UnifiedLoggingFilter_CRUD(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()
	name := accName("ulf")

	// Create
	input := UnifiedLoggingFilterInput{
		Name:        name,
		Description: "acceptance test unified logging filter",
		Tags:        []string{"acc-test"},
		Filter:      "subsystem == \"com.apple.test\"",
		Enabled:     false,
	}
	created, err := client.CreateUnifiedLoggingFilter(ctx, input)
	if err != nil {
		t.Fatalf("CreateUnifiedLoggingFilter: %v", err)
	}
	if created.UUID == "" {
		t.Fatal("CreateUnifiedLoggingFilter: expected non-empty UUID")
	}

	// Get
	got, err := client.GetUnifiedLoggingFilter(ctx, created.UUID)
	if err != nil {
		t.Fatalf("GetUnifiedLoggingFilter: %v", err)
	}
	if got.Name != name {
		t.Fatalf("GetUnifiedLoggingFilter: expected name %q, got %q", name, got.Name)
	}

	// List
	filters, err := client.ListUnifiedLoggingFilters(ctx)
	if err != nil {
		t.Fatalf("ListUnifiedLoggingFilters: %v", err)
	}
	found := false
	for _, f := range filters {
		if f.UUID == created.UUID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ListUnifiedLoggingFilters: created filter %q not found", created.UUID)
	}

	// Update
	updatedName := name + "-updated"
	updateInput := UnifiedLoggingFilterInput{
		Name:        updatedName,
		Description: "updated description",
		Tags:        []string{"acc-test", "updated"},
		Filter:      "subsystem == \"com.apple.updated\"",
		Enabled:     true,
	}
	updated, err := client.UpdateUnifiedLoggingFilter(ctx, created.UUID, updateInput)
	if err != nil {
		t.Fatalf("UpdateUnifiedLoggingFilter: %v", err)
	}
	if updated.Name != updatedName {
		t.Fatalf("UpdateUnifiedLoggingFilter: expected name %q, got %q", updatedName, updated.Name)
	}

	// Delete
	if err := client.DeleteUnifiedLoggingFilter(ctx, created.UUID); err != nil {
		t.Fatalf("DeleteUnifiedLoggingFilter: %v", err)
	}

	// Get after delete
	_, err = client.GetUnifiedLoggingFilter(ctx, created.UUID)
	if err == nil {
		t.Fatal("GetUnifiedLoggingFilter after delete: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetUnifiedLoggingFilter after delete: expected ErrNotFound, got %v", err)
	}
}
