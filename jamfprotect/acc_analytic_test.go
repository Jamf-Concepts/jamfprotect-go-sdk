// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"errors"
	"testing"
)

func TestAcc_Analytic_CRUD(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()
	name := accName("analytic")

	input := AnalyticInput{
		Name:            name,
		InputType:       "GPFSEvent",
		Description:     "acceptance test analytic",
		AnalyticActions: []AnalyticActionInput{},
		Tags:            []string{"acc-test"},
		Categories:      []string{"Testing"},
		Filter:          `($event.type == "Filter")`,
		Context:         []AnalyticContextInput{},
		Level:           0,
		Severity:        "Informational",
		SnapshotFiles:   []string{},
	}

	created, err := client.CreateAnalytic(ctx, input)
	if err != nil {
		t.Fatalf("CreateAnalytic: %v", err)
	}
	if created.UUID == "" {
		t.Fatal("CreateAnalytic: expected non-empty UUID")
	}
	if created.Jamf {
		t.Fatal("CreateAnalytic: expected Jamf=false for new custom analytic")
	}

	defer func() {
		if err := client.DeleteAnalytic(ctx, created.UUID); err != nil && !errors.Is(err, ErrNotFound) {
			t.Errorf("cleanup DeleteAnalytic: %v", err)
		}
	}()

	got, err := client.GetAnalytic(ctx, created.UUID)
	if err != nil {
		t.Fatalf("GetAnalytic: %v", err)
	}
	if got == nil {
		t.Fatal("GetAnalytic: expected non-nil result")
	}
	if got.Name != name {
		t.Fatalf("GetAnalytic: expected name %q, got %q", name, got.Name)
	}

	items, err := client.ListAnalytics(ctx)
	if err != nil {
		t.Fatalf("ListAnalytics: %v", err)
	}
	found := false
	for _, a := range items {
		if a.UUID == created.UUID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ListAnalytics: created analytic %q not found", created.UUID)
	}

	updatedName := name + "-updated"
	updateInput := input
	updateInput.Name = updatedName
	updateInput.Description = "updated description"

	updated, err := client.UpdateAnalytic(ctx, created.UUID, updateInput)
	if err != nil {
		t.Fatalf("UpdateAnalytic: %v", err)
	}
	if updated.Name != updatedName {
		t.Fatalf("UpdateAnalytic: expected name %q, got %q", updatedName, updated.Name)
	}

	if err := client.DeleteAnalytic(ctx, created.UUID); err != nil {
		t.Fatalf("DeleteAnalytic: %v", err)
	}

	gotAfterDelete, err := client.GetAnalytic(ctx, created.UUID)
	if err == nil && gotAfterDelete != nil {
		t.Fatal("GetAnalytic after delete: expected nil or error, got result")
	}
}

// TestAcc_Analytic_UpdateInternal exercises the tenant-scoped UpdateInternalAnalytic
// mutation against a Jamf-managed analytic discovered at runtime. Because Jamf-managed
// analytics cannot be created or destroyed via API, the test mutates a real shared
// resource and restores its original state on completion. Skipped if no Jamf-managed
// analytic exists in the target tenant.
func TestAcc_Analytic_UpdateInternal(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()

	all, err := client.ListAnalytics(ctx)
	if err != nil {
		t.Fatalf("ListAnalytics: %v", err)
	}

	var target *Analytic
	for i, a := range all {
		if a.Jamf {
			target = &all[i]
			break
		}
	}
	if target == nil {
		t.Skip("no Jamf-managed analytic found in tenant — skipping internal-update test")
	}

	originalActions := append([]AnalyticAction(nil), target.TenantActions...)
	originalSeverity := target.TenantSeverity

	t.Cleanup(func() {
		restoreInput := InternalAnalyticInput{
			TenantSeverity: originalSeverity,
		}
		if originalActions != nil {
			restoreInput.TenantActions = make([]AnalyticActionInput, 0, len(originalActions))
			for _, a := range originalActions {
				restoreInput.TenantActions = append(restoreInput.TenantActions, AnalyticActionInput(a))
			}
		}
		if _, err := client.UpdateInternalAnalytic(context.Background(), target.UUID, restoreInput); err != nil {
			t.Errorf("cleanup UpdateInternalAnalytic: %v", err)
		}
	})

	newSeverity := "Low"
	if originalSeverity == "Low" {
		newSeverity = "High"
	}
	newActions := []AnalyticActionInput{
		{Name: "Report", Parameters: "{}"},
	}

	updated, err := client.UpdateInternalAnalytic(ctx, target.UUID, InternalAnalyticInput{
		TenantActions:  newActions,
		TenantSeverity: newSeverity,
	})
	if err != nil {
		t.Fatalf("UpdateInternalAnalytic: %v", err)
	}
	if updated.TenantSeverity != newSeverity {
		t.Errorf("expected TenantSeverity %q, got %q", newSeverity, updated.TenantSeverity)
	}
	if !updated.Jamf {
		t.Error("expected Jamf=true on updated response")
	}

	verify, err := client.GetAnalytic(ctx, target.UUID)
	if err != nil {
		t.Fatalf("GetAnalytic verify: %v", err)
	}
	if verify == nil {
		t.Fatal("GetAnalytic verify: expected non-nil")
	}
	if verify.TenantSeverity != newSeverity {
		t.Errorf("verify TenantSeverity: expected %q, got %q", newSeverity, verify.TenantSeverity)
	}
}
