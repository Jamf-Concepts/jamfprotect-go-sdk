// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"errors"
	"testing"
)

func TestAcc_ActionConfig_CRUD(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()
	name := accName("action-config")

	// Create
	emptyEventType := map[string]any{"attrs": []any{}, "related": []any{}}
	input := ActionConfigInput{
		Name:        name,
		Description: "acceptance test action config",
		AlertConfig: map[string]any{
			"data": map[string]any{
				"binary":              emptyEventType,
				"clickEvent":          emptyEventType,
				"downloadEvent":       emptyEventType,
				"file":                emptyEventType,
				"fsEvent":             emptyEventType,
				"group":               emptyEventType,
				"procEvent":           emptyEventType,
				"process":             emptyEventType,
				"screenshotEvent":     emptyEventType,
				"user":                emptyEventType,
				"gkEvent":             emptyEventType,
				"keylogRegisterEvent": emptyEventType,
				"usbEvent":            emptyEventType,
				"mrtEvent":            emptyEventType,
			},
		},
		Clients: []map[string]any{},
	}
	created, err := client.CreateActionConfig(ctx, input)
	if err != nil {
		t.Fatalf("CreateActionConfig: %v", err)
	}
	if created.ID == "" {
		t.Fatal("CreateActionConfig: expected non-empty ID")
	}

	// Get
	got, err := client.GetActionConfig(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetActionConfig: %v", err)
	}
	if got.Name != name {
		t.Fatalf("GetActionConfig: expected name %q, got %q", name, got.Name)
	}

	// List
	configs, err := client.ListActionConfigs(ctx)
	if err != nil {
		t.Fatalf("ListActionConfigs: %v", err)
	}
	found := false
	for _, c := range configs {
		if c.ID == created.ID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ListActionConfigs: created config %q not found", created.ID)
	}

	// Update
	updatedName := name + "-updated"
	updateInput := ActionConfigInput{
		Name:        updatedName,
		Description: "updated description",
		AlertConfig: map[string]any{
			"data": map[string]any{
				"binary":              emptyEventType,
				"clickEvent":          emptyEventType,
				"downloadEvent":       emptyEventType,
				"file":                emptyEventType,
				"fsEvent":             emptyEventType,
				"group":               emptyEventType,
				"procEvent":           emptyEventType,
				"process":             emptyEventType,
				"screenshotEvent":     emptyEventType,
				"user":                emptyEventType,
				"gkEvent":             emptyEventType,
				"keylogRegisterEvent": emptyEventType,
				"usbEvent":            emptyEventType,
				"mrtEvent":            emptyEventType,
			},
		},
		Clients: []map[string]any{},
	}
	updated, err := client.UpdateActionConfig(ctx, created.ID, updateInput)
	if err != nil {
		t.Fatalf("UpdateActionConfig: %v", err)
	}
	if updated.Name != updatedName {
		t.Fatalf("UpdateActionConfig: expected name %q, got %q", updatedName, updated.Name)
	}

	// Delete
	if err := client.DeleteActionConfig(ctx, created.ID); err != nil {
		t.Fatalf("DeleteActionConfig: %v", err)
	}

	// Get after delete
	_, err = client.GetActionConfig(ctx, created.ID)
	if err == nil {
		t.Fatal("GetActionConfig after delete: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetActionConfig after delete: expected ErrNotFound, got %v", err)
	}
}
