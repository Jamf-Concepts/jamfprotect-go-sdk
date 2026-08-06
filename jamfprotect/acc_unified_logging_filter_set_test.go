// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"errors"
	"testing"
)

// accULFilter creates a Unified Logging filter for use as set membership and
// registers its cleanup.
func accULFilter(t *testing.T, ctx context.Context, client *Client, name string) UnifiedLoggingFilter {
	t.Helper()

	filter, err := client.CreateUnifiedLoggingFilter(ctx, UnifiedLoggingFilterInput{
		Name:        name,
		Description: "acceptance test filter for set membership",
		Tags:        []string{"acc-test"},
		Filter:      "subsystem == \"com.apple.test\"",
	})
	if err != nil {
		t.Fatalf("CreateUnifiedLoggingFilter: %v", err)
	}
	t.Cleanup(func() {
		if err := client.DeleteUnifiedLoggingFilter(ctx, filter.UUID); err != nil && !errors.Is(err, ErrNotFound) {
			t.Errorf("cleanup DeleteUnifiedLoggingFilter: %v", err)
		}
	})
	return filter
}

func TestAcc_UnifiedLoggingFilterSet_CRUD(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()
	name := accName("ulfs")

	filter := accULFilter(t, ctx, client, accName("ulfs-member"))

	// Create
	created, err := client.CreateUnifiedLoggingFilterSet(ctx, UnifiedLoggingFilterSetInput{
		Name:        name,
		Description: "acceptance test unified logging filter set",
		Filters:     []string{filter.UUID},
	})
	if err != nil {
		t.Fatalf("CreateUnifiedLoggingFilterSet: %v", err)
	}
	if created.UUID == "" {
		t.Fatal("CreateUnifiedLoggingFilterSet: expected non-empty UUID")
	}
	if created.Name != name {
		t.Fatalf("CreateUnifiedLoggingFilterSet: expected name %q, got %q", name, created.Name)
	}
	if len(created.Filters) != 1 || created.Filters[0].UUID != filter.UUID {
		t.Fatalf("CreateUnifiedLoggingFilterSet: expected filter %q in set, got %+v", filter.UUID, created.Filters)
	}

	deleted := false
	defer func() {
		if deleted {
			return
		}
		if err := client.DeleteUnifiedLoggingFilterSet(ctx, created.UUID); err != nil && !errors.Is(err, ErrNotFound) {
			t.Errorf("cleanup DeleteUnifiedLoggingFilterSet: %v", err)
		}
	}()

	// Get
	got, err := client.GetUnifiedLoggingFilterSet(ctx, created.UUID)
	if err != nil {
		t.Fatalf("GetUnifiedLoggingFilterSet: %v", err)
	}
	if got == nil {
		t.Fatal("GetUnifiedLoggingFilterSet: expected non-nil result")
	}
	if got.Name != name {
		t.Fatalf("GetUnifiedLoggingFilterSet: expected name %q, got %q", name, got.Name)
	}
	if len(got.Plans) != 0 {
		t.Fatalf("GetUnifiedLoggingFilterSet: expected no plans, got %+v", got.Plans)
	}

	// The filter now reports its set membership.
	member, err := client.GetUnifiedLoggingFilter(ctx, filter.UUID)
	if err != nil {
		t.Fatalf("GetUnifiedLoggingFilter: %v", err)
	}
	if len(member.Sets) != 1 || member.Sets[0].UUID != created.UUID {
		t.Fatalf("GetUnifiedLoggingFilter: expected set %q in Sets, got %+v", created.UUID, member.Sets)
	}

	// List
	sets, err := client.ListUnifiedLoggingFilterSets(ctx)
	if err != nil {
		t.Fatalf("ListUnifiedLoggingFilterSets: %v", err)
	}
	found := false
	for _, s := range sets {
		if s.UUID == created.UUID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ListUnifiedLoggingFilterSets: created set %q not found", created.UUID)
	}

	// Update — rename and clear membership.
	updatedName := name + "-updated"
	updated, err := client.UpdateUnifiedLoggingFilterSet(ctx, created.UUID, UnifiedLoggingFilterSetInput{
		Name:        updatedName,
		Description: "updated description",
		Filters:     []string{},
	})
	if err != nil {
		t.Fatalf("UpdateUnifiedLoggingFilterSet: %v", err)
	}
	if updated.Name != updatedName {
		t.Fatalf("UpdateUnifiedLoggingFilterSet: expected name %q, got %q", updatedName, updated.Name)
	}
	if len(updated.Filters) != 0 {
		t.Fatalf("UpdateUnifiedLoggingFilterSet: expected empty filters, got %+v", updated.Filters)
	}

	// Update — restore membership.
	restored, err := client.UpdateUnifiedLoggingFilterSet(ctx, created.UUID, UnifiedLoggingFilterSetInput{
		Name:        updatedName,
		Description: "updated description",
		Filters:     []string{filter.UUID},
	})
	if err != nil {
		t.Fatalf("UpdateUnifiedLoggingFilterSet restore: %v", err)
	}
	if len(restored.Filters) != 1 {
		t.Fatalf("UpdateUnifiedLoggingFilterSet restore: expected 1 filter, got %+v", restored.Filters)
	}

	// Delete
	if err := client.DeleteUnifiedLoggingFilterSet(ctx, created.UUID); err != nil {
		t.Fatalf("DeleteUnifiedLoggingFilterSet: %v", err)
	}
	deleted = true

	// Get after delete
	if _, err := client.GetUnifiedLoggingFilterSet(ctx, created.UUID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetUnifiedLoggingFilterSet after delete: expected ErrNotFound, got %v", err)
	}
}

func TestAcc_UnifiedLoggingFilterSet_PlanAssignment(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()

	configs, err := client.ListActionConfigs(ctx)
	if err != nil {
		t.Fatalf("ListActionConfigs: %v", err)
	}
	if len(configs) == 0 {
		t.Skip("no ActionConfigs available; skipping plan assignment test")
	}

	filter := accULFilter(t, ctx, client, accName("ulfs-plan-member"))

	set, err := client.CreateUnifiedLoggingFilterSet(ctx, UnifiedLoggingFilterSetInput{
		Name:    accName("ulfs-plan"),
		Filters: []string{filter.UUID},
	})
	if err != nil {
		t.Fatalf("CreateUnifiedLoggingFilterSet: %v", err)
	}
	t.Cleanup(func() {
		if err := client.DeleteUnifiedLoggingFilterSet(ctx, set.UUID); err != nil && !errors.Is(err, ErrNotFound) {
			t.Errorf("cleanup DeleteUnifiedLoggingFilterSet: %v", err)
		}
	})

	planInput := PlanInput{
		Name:          accName("ulfs-plan-target"),
		Description:   "acceptance test plan for filter set assignment",
		ActionConfigs: configs[0].ID,
		CommsConfig: PlanCommsConfigInput{
			FQDN:     "test.protect.jamfcloud.com",
			Protocol: "auto",
		},
		InfoSync: PlanInfoSyncInput{
			Attrs: []string{"insights"},
		},
		SignaturesFeedConfig: PlanSignaturesFeedConfigInput{
			Mode: "disabled",
		},
		UnifiedLoggingFilterSets: []string{set.UUID},
	}

	// Assignment at create time.
	plan, err := client.CreatePlan(ctx, planInput)
	if err != nil {
		t.Fatalf("CreatePlan: %v", err)
	}
	t.Cleanup(func() {
		if err := client.DeletePlan(ctx, plan.ID); err != nil && !errors.Is(err, ErrNotFound) {
			t.Errorf("cleanup DeletePlan: %v", err)
		}
	})
	if len(plan.UnifiedLoggingFilterSets) != 1 || plan.UnifiedLoggingFilterSets[0].UUID != set.UUID {
		t.Fatalf("CreatePlan: expected set %q assigned, got %+v", set.UUID, plan.UnifiedLoggingFilterSets)
	}

	// The set reports the reverse relationship.
	gotSet, err := client.GetUnifiedLoggingFilterSet(ctx, set.UUID)
	if err != nil {
		t.Fatalf("GetUnifiedLoggingFilterSet: %v", err)
	}
	if len(gotSet.Plans) != 1 || gotSet.Plans[0].ID != plan.ID {
		t.Fatalf("GetUnifiedLoggingFilterSet: expected plan %q in Plans, got %+v", plan.ID, gotSet.Plans)
	}

	// A set assigned to a plan cannot be deleted.
	if err := client.DeleteUnifiedLoggingFilterSet(ctx, set.UUID); err == nil {
		t.Fatal("DeleteUnifiedLoggingFilterSet while assigned to a plan: expected error, got nil")
	}

	// A nil UnifiedLoggingFilterSets leaves the existing assignment untouched.
	omitted := planInput
	omitted.UnifiedLoggingFilterSets = nil
	unchanged, err := client.UpdatePlan(ctx, plan.ID, omitted)
	if err != nil {
		t.Fatalf("UpdatePlan with omitted filter sets: %v", err)
	}
	if len(unchanged.UnifiedLoggingFilterSets) != 1 {
		t.Fatalf("UpdatePlan with omitted filter sets: expected assignment preserved, got %+v", unchanged.UnifiedLoggingFilterSets)
	}

	// An empty (non-nil) slice clears the assignment.
	cleared := planInput
	cleared.UnifiedLoggingFilterSets = []string{}
	emptied, err := client.UpdatePlan(ctx, plan.ID, cleared)
	if err != nil {
		t.Fatalf("UpdatePlan clearing filter sets: %v", err)
	}
	if len(emptied.UnifiedLoggingFilterSets) != 0 {
		t.Fatalf("UpdatePlan clearing filter sets: expected no assignments, got %+v", emptied.UnifiedLoggingFilterSets)
	}
}
