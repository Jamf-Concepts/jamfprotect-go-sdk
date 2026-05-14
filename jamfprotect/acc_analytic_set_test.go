// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"errors"
	"testing"
)

func TestAcc_AnalyticSet_CRUD(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()
	name := accName("analytic-set")

	input := AnalyticSetInput{
		Name:        name,
		Description: "acceptance test analytic set",
		Analytics:   []string{},
		Types:       []string{"Report"},
	}

	created, err := client.CreateAnalyticSet(ctx, input)
	if err != nil {
		t.Fatalf("CreateAnalyticSet: %v", err)
	}
	if created.UUID == "" {
		t.Fatal("CreateAnalyticSet: expected non-empty UUID")
	}
	if created.Name != name {
		t.Fatalf("CreateAnalyticSet: expected name %q, got %q", name, created.Name)
	}

	defer func() {
		if err := client.DeleteAnalyticSet(ctx, created.UUID); err != nil && !errors.Is(err, ErrNotFound) {
			t.Errorf("cleanup DeleteAnalyticSet: %v", err)
		}
	}()

	got, err := client.GetAnalyticSet(ctx, created.UUID)
	if err != nil {
		t.Fatalf("GetAnalyticSet: %v", err)
	}
	if got == nil {
		t.Fatal("GetAnalyticSet: expected non-nil result")
	}
	if got.Name != name {
		t.Fatalf("GetAnalyticSet: expected name %q, got %q", name, got.Name)
	}

	items, err := client.ListAnalyticSets(ctx)
	if err != nil {
		t.Fatalf("ListAnalyticSets: %v", err)
	}
	found := false
	for _, a := range items {
		if a.UUID == created.UUID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ListAnalyticSets: created analytic set %q not found", created.UUID)
	}

	updatedName := name + "-updated"
	updateInput := AnalyticSetInput{
		Name:        updatedName,
		Description: "updated description",
		Analytics:   []string{},
		Types:       []string{"Report"},
	}
	updated, err := client.UpdateAnalyticSet(ctx, created.UUID, updateInput)
	if err != nil {
		t.Fatalf("UpdateAnalyticSet: %v", err)
	}
	if updated.Name != updatedName {
		t.Fatalf("UpdateAnalyticSet: expected name %q, got %q", updatedName, updated.Name)
	}

	if err := client.DeleteAnalyticSet(ctx, created.UUID); err != nil {
		t.Fatalf("DeleteAnalyticSet: %v", err)
	}

	gotAfterDelete, err := client.GetAnalyticSet(ctx, created.UUID)
	if err == nil && gotAfterDelete != nil {
		t.Fatal("GetAnalyticSet after delete: expected nil or error, got result")
	}
}
