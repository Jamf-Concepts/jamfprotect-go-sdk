// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"errors"
	"testing"
)

// accPreventList creates a custom prevent list for use as set membership and
// registers its cleanup.
func accPreventList(t *testing.T, ctx context.Context, client *Client, name string) CustomPreventList {
	t.Helper()

	list, err := client.CreateCustomPreventList(ctx, CustomPreventListInput{
		Name:        name,
		Description: "acceptance test list for set membership",
		Type:        "TEAMID",
		Tags:        []string{},
		List:        []string{"ABCDE12345"},
	})
	if err != nil {
		t.Fatalf("CreateCustomPreventList: %v", err)
	}
	t.Cleanup(func() {
		if err := client.DeleteCustomPreventList(ctx, list.ID); err != nil && !errors.Is(err, ErrNotFound) {
			t.Errorf("cleanup DeleteCustomPreventList: %v", err)
		}
	})
	return list
}

func TestAcc_PreventListSet_CRUD(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()
	name := accName("pls")

	list := accPreventList(t, ctx, client, accName("pls-member"))
	if len(list.Sets) != 0 {
		t.Fatalf("CreateCustomPreventList: expected a new list to belong to no set, got %+v", list.Sets)
	}

	created, err := client.CreatePreventListSet(ctx, PreventListSetInput{
		Name:         name,
		Description:  "acceptance test prevent list set",
		PreventLists: []string{list.ID},
	})
	if err != nil {
		t.Fatalf("CreatePreventListSet: %v", err)
	}
	if created.UUID == "" {
		t.Fatal("CreatePreventListSet: expected non-empty UUID")
	}
	if len(created.PreventLists) != 1 || created.PreventLists[0].ID != list.ID {
		t.Fatalf("CreatePreventListSet: expected list %q in set, got %+v", list.ID, created.PreventLists)
	}

	deleted := false
	defer func() {
		if deleted {
			return
		}
		if err := client.DeletePreventListSet(ctx, created.UUID); err != nil && !errors.Is(err, ErrNotFound) {
			t.Errorf("cleanup DeletePreventListSet: %v", err)
		}
	}()

	got, err := client.GetPreventListSet(ctx, created.UUID)
	if err != nil {
		t.Fatalf("GetPreventListSet: %v", err)
	}
	if got == nil || got.Name != name {
		t.Fatalf("GetPreventListSet: expected name %q, got %+v", name, got)
	}
	if len(got.Plans) != 0 {
		t.Fatalf("GetPreventListSet: expected no plans, got %+v", got.Plans)
	}

	member, err := client.GetCustomPreventList(ctx, list.ID)
	if err != nil {
		t.Fatalf("GetCustomPreventList: %v", err)
	}
	if len(member.Sets) != 1 || member.Sets[0].UUID != created.UUID {
		t.Fatalf("GetCustomPreventList: expected set %q in Sets, got %+v", created.UUID, member.Sets)
	}

	sets, err := client.ListPreventListSets(ctx)
	if err != nil {
		t.Fatalf("ListPreventListSets: %v", err)
	}
	found := false
	for _, s := range sets {
		if s.UUID == created.UUID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ListPreventListSets: created set %q not found", created.UUID)
	}

	updatedName := name + "-updated"
	updated, err := client.UpdatePreventListSet(ctx, created.UUID, PreventListSetInput{
		Name:         updatedName,
		Description:  "updated description",
		PreventLists: []string{},
	})
	if err != nil {
		t.Fatalf("UpdatePreventListSet: %v", err)
	}
	if updated.Name != updatedName || len(updated.PreventLists) != 0 {
		t.Fatalf("UpdatePreventListSet: expected renamed empty set, got %+v", updated)
	}

	// A list that does not exist is rejected.
	if _, err := client.CreatePreventListSet(ctx, PreventListSetInput{
		Name:         accName("pls-bad"),
		PreventLists: []string{"999999999"},
	}); err == nil {
		t.Fatal("CreatePreventListSet with unknown list: expected error, got nil")
	}

	if err := client.DeletePreventListSet(ctx, created.UUID); err != nil {
		t.Fatalf("DeletePreventListSet: %v", err)
	}
	deleted = true

	if _, err := client.GetPreventListSet(ctx, created.UUID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetPreventListSet after delete: expected ErrNotFound, got %v", err)
	}
}

func TestAcc_PreventListSet_PlanAssignment(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()

	configs, err := client.ListActionConfigs(ctx)
	if err != nil {
		t.Fatalf("ListActionConfigs: %v", err)
	}
	if len(configs) == 0 {
		t.Skip("no ActionConfigs available; skipping plan assignment test")
	}

	list := accPreventList(t, ctx, client, accName("pls-plan-member"))

	set, err := client.CreatePreventListSet(ctx, PreventListSetInput{
		Name:         accName("pls-plan"),
		PreventLists: []string{list.ID},
	})
	if err != nil {
		t.Fatalf("CreatePreventListSet: %v", err)
	}
	t.Cleanup(func() {
		if err := client.DeletePreventListSet(ctx, set.UUID); err != nil && !errors.Is(err, ErrNotFound) {
			t.Errorf("cleanup DeletePreventListSet: %v", err)
		}
	})

	planInput := PlanInput{
		Name:          accName("pls-plan-target"),
		Description:   "acceptance test plan for prevent list set assignment",
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
		PreventListSets: []string{set.UUID},
	}

	plan, err := client.CreatePlan(ctx, planInput)
	if err != nil {
		t.Fatalf("CreatePlan: %v", err)
	}
	t.Cleanup(func() {
		if err := client.DeletePlan(ctx, plan.ID); err != nil && !errors.Is(err, ErrNotFound) {
			t.Errorf("cleanup DeletePlan: %v", err)
		}
	})
	if len(plan.PreventListSets) != 1 || plan.PreventListSets[0].UUID != set.UUID {
		t.Fatalf("CreatePlan: expected set %q assigned, got %+v", set.UUID, plan.PreventListSets)
	}

	gotSet, err := client.GetPreventListSet(ctx, set.UUID)
	if err != nil {
		t.Fatalf("GetPreventListSet: %v", err)
	}
	if len(gotSet.Plans) != 1 || gotSet.Plans[0].ID != plan.ID {
		t.Fatalf("GetPreventListSet: expected plan %q in Plans, got %+v", plan.ID, gotSet.Plans)
	}

	// A set assigned to a plan cannot be deleted.
	if err := client.DeletePreventListSet(ctx, set.UUID); err == nil {
		t.Fatal("DeletePreventListSet while assigned to a plan: expected error, got nil")
	}

	// A plan cannot reference a set that does not exist.
	unknown := planInput
	unknown.PreventListSets = []string{"00000000-0000-0000-0000-000000000000"}
	if _, err := client.UpdatePlan(ctx, plan.ID, unknown); err == nil {
		t.Fatal("UpdatePlan with unknown prevent list set: expected error, got nil")
	}

	// A nil PreventListSets leaves the existing assignment untouched.
	omitted := planInput
	omitted.PreventListSets = nil
	unchanged, err := client.UpdatePlan(ctx, plan.ID, omitted)
	if err != nil {
		t.Fatalf("UpdatePlan with omitted prevent list sets: %v", err)
	}
	if len(unchanged.PreventListSets) != 1 {
		t.Fatalf("UpdatePlan with omitted prevent list sets: expected assignment preserved, got %+v", unchanged.PreventListSets)
	}

	// An empty (non-nil) slice clears the assignment.
	cleared := planInput
	cleared.PreventListSets = []string{}
	emptied, err := client.UpdatePlan(ctx, plan.ID, cleared)
	if err != nil {
		t.Fatalf("UpdatePlan clearing prevent list sets: %v", err)
	}
	if len(emptied.PreventListSets) != 0 {
		t.Fatalf("UpdatePlan clearing prevent list sets: expected no assignments, got %+v", emptied.PreventListSets)
	}
}
