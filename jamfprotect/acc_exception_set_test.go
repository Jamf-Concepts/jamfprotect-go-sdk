// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"errors"
	"testing"
)

func TestAcc_ExceptionSet_CRUD(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()
	name := accName("exception-set")

	// Create
	input := ExceptionSetInput{
		Name:         name,
		Description:  "acceptance test exception set",
		Exceptions:   []ExceptionInput{},
		EsExceptions: []EsExceptionInput{},
	}
	created, err := client.CreateExceptionSet(ctx, input)
	if err != nil {
		t.Fatalf("CreateExceptionSet: %v", err)
	}
	if created.UUID == "" {
		t.Fatal("CreateExceptionSet: expected non-empty UUID")
	}

	// Get
	got, err := client.GetExceptionSet(ctx, created.UUID)
	if err != nil {
		t.Fatalf("GetExceptionSet: %v", err)
	}
	if got.Name != name {
		t.Fatalf("GetExceptionSet: expected name %q, got %q", name, got.Name)
	}

	// List
	sets, err := client.ListExceptionSets(ctx)
	if err != nil {
		t.Fatalf("ListExceptionSets: %v", err)
	}
	found := false
	for _, s := range sets {
		if s.UUID == created.UUID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ListExceptionSets: created set %q not found in list", created.UUID)
	}

	// Update
	updatedName := name + "-updated"
	updateInput := ExceptionSetInput{
		Name:         updatedName,
		Description:  "updated description",
		Exceptions:   []ExceptionInput{},
		EsExceptions: []EsExceptionInput{},
	}
	updated, err := client.UpdateExceptionSet(ctx, created.UUID, updateInput)
	if err != nil {
		t.Fatalf("UpdateExceptionSet: %v", err)
	}
	if updated.Name != updatedName {
		t.Fatalf("UpdateExceptionSet: expected name %q, got %q", updatedName, updated.Name)
	}

	// Delete
	if err := client.DeleteExceptionSet(ctx, created.UUID); err != nil {
		t.Fatalf("DeleteExceptionSet: %v", err)
	}

	// Get after delete
	_, err = client.GetExceptionSet(ctx, created.UUID)
	if err == nil {
		t.Fatal("GetExceptionSet after delete: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetExceptionSet after delete: expected ErrNotFound, got %v", err)
	}
}
