// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"errors"
	"testing"
)

func TestAcc_TelemetryV2_CRUD(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()
	name := accName("telemetry-v2")

	// Create
	input := TelemetryV2Input{
		Name:               name,
		Description:        "acceptance test telemetry v2",
		LogFiles:           []string{},
		LogFileCollection:  false,
		PerformanceMetrics: false,
		Events:             []string{},
		FileHashing:        false,
	}
	created, err := client.CreateTelemetryV2(ctx, input)
	if err != nil {
		t.Fatalf("CreateTelemetryV2: %v", err)
	}
	if created.ID == "" {
		t.Fatal("CreateTelemetryV2: expected non-empty ID")
	}

	// Get
	got, err := client.GetTelemetryV2(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetTelemetryV2: %v", err)
	}
	if got.Name != name {
		t.Fatalf("GetTelemetryV2: expected name %q, got %q", name, got.Name)
	}

	// List
	items, err := client.ListTelemetriesV2(ctx)
	if err != nil {
		t.Fatalf("ListTelemetriesV2: %v", err)
	}
	found := false
	for _, item := range items {
		if item.ID == created.ID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ListTelemetriesV2: created telemetry %q not found in list", created.ID)
	}

	// Update
	updatedName := name + "-updated"
	updateInput := TelemetryV2Input{
		Name:               updatedName,
		Description:        "updated description",
		LogFiles:           []string{"/var/log/system.log"},
		LogFileCollection:  true,
		PerformanceMetrics: true,
		Events:             []string{},
		FileHashing:        false,
	}
	updated, err := client.UpdateTelemetryV2(ctx, created.ID, updateInput)
	if err != nil {
		t.Fatalf("UpdateTelemetryV2: %v", err)
	}
	if updated.Name != updatedName {
		t.Fatalf("UpdateTelemetryV2: expected name %q, got %q", updatedName, updated.Name)
	}

	// Delete
	if err := client.DeleteTelemetryV2(ctx, created.ID); err != nil {
		t.Fatalf("DeleteTelemetryV2: %v", err)
	}

	// Get after delete
	_, err = client.GetTelemetryV2(ctx, created.ID)
	if err == nil {
		t.Fatal("GetTelemetryV2 after delete: expected error, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetTelemetryV2 after delete: expected ErrNotFound, got %v", err)
	}
}
