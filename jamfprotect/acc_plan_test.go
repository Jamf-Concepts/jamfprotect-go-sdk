// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"errors"
	"testing"
)

func TestAcc_Plan_CRUD(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()
	name := accName("plan")

	// Require an existing ActionConfig — plans must reference one.
	configs, err := client.ListActionConfigs(ctx)
	if err != nil {
		t.Fatalf("ListActionConfigs: %v", err)
	}
	if len(configs) == 0 {
		t.Skip("no ActionConfigs available; skipping plan CRUD test")
	}
	actionConfigID := configs[0].ID

	input := PlanInput{
		Name:          name,
		Description:   "acceptance test plan",
		ActionConfigs: actionConfigID,
		AutoUpdate:    false,
		CommsConfig: PlanCommsConfigInput{
			FQDN:     "test.protect.jamfcloud.com",
			Protocol: "auto",
		},
		InfoSync: PlanInfoSyncInput{
			Attrs:                []string{"insights"},
			InsightsSyncInterval: 0,
		},
		SignaturesFeedConfig: PlanSignaturesFeedConfigInput{
			Mode: "disabled",
		},
	}

	// Create
	created, err := client.CreatePlan(ctx, input)
	if err != nil {
		t.Fatalf("CreatePlan: %v", err)
	}
	if created.ID == "" {
		t.Fatal("CreatePlan: expected non-empty ID")
	}
	if created.Name != name {
		t.Fatalf("CreatePlan: expected name %q, got %q", name, created.Name)
	}

	defer func() {
		if err := client.DeletePlan(ctx, created.ID); err != nil && !errors.Is(err, ErrNotFound) {
			t.Errorf("cleanup DeletePlan: %v", err)
		}
	}()

	// Get
	got, err := client.GetPlan(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetPlan: %v", err)
	}
	if got == nil {
		t.Fatal("GetPlan: expected non-nil result")
	}
	if got.Name != name {
		t.Fatalf("GetPlan: expected name %q, got %q", name, got.Name)
	}

	// List
	plans, err := client.ListPlans(ctx)
	if err != nil {
		t.Fatalf("ListPlans: %v", err)
	}
	found := false
	for _, p := range plans {
		if p.ID == created.ID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ListPlans: created plan %q not found", created.ID)
	}

	// Update
	updatedName := name + "-updated"
	updateInput := PlanInput{
		Name:          updatedName,
		Description:   "updated description",
		ActionConfigs: actionConfigID,
		AutoUpdate:    false,
		CommsConfig:   input.CommsConfig,
		InfoSync:      input.InfoSync,
		SignaturesFeedConfig: PlanSignaturesFeedConfigInput{
			Mode: "disabled",
		},
	}
	updated, err := client.UpdatePlan(ctx, created.ID, updateInput)
	if err != nil {
		t.Fatalf("UpdatePlan: %v", err)
	}
	if updated.Name != updatedName {
		t.Fatalf("UpdatePlan: expected name %q, got %q", updatedName, updated.Name)
	}

}
