// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"testing"
)

func TestDeleteComputer(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()

		if req.Variables["uuid"] != "test-uuid" {
			t.Errorf("expected uuid %q, got %q", "test-uuid", req.Variables["uuid"])
		}

		return map[string]any{
			"deleteComputer": map[string]any{
				"uuid": "test-uuid",
			},
		}
	})

	ctx := context.Background()
	err := client.DeleteComputer(ctx, "test-uuid")
	if err != nil {
		t.Fatalf("DeleteComputer: %v", err)
	}
}

func TestDeleteComputer_Error(t *testing.T) {
	t.Parallel()

	_, client := testServerError(t, "computer not found")

	ctx := context.Background()
	err := client.DeleteComputer(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestSetComputerPlan(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()

		if req.Variables["uuid"] != "test-uuid" {
			t.Errorf("expected uuid %q, got %q", "test-uuid", req.Variables["uuid"])
		}
		if req.Variables["plan"] != "plan-123" {
			t.Errorf("expected plan %q, got %q", "plan-123", req.Variables["plan"])
		}
		if req.Variables["RBAC_Plan"] != true {
			t.Error("expected RBAC_Plan to be true")
		}
		if req.Variables["RBAC_Insight"] != true {
			t.Error("expected RBAC_Insight to be true")
		}
		if req.Variables["RBAC_ThreatPreventionVersion"] != true {
			t.Error("expected RBAC_ThreatPreventionVersion to be true")
		}

		return map[string]any{
			"setComputerPlan": map[string]any{
				"uuid":             "test-uuid",
				"serial":           "C02TEST",
				"hostName":         "test-host",
				"connectionStatus": "Connected",
				"pendingPlan":      123,
				"plan": map[string]any{
					"id":   "plan-123",
					"name": "Test Plan",
					"hash": "abc123",
				},
			},
		}
	})

	ctx := context.Background()
	computer, err := client.SetComputerPlan(ctx, "test-uuid", "plan-123")
	if err != nil {
		t.Fatalf("SetComputerPlan: %v", err)
	}
	if computer == nil {
		t.Fatal("SetComputerPlan: expected non-nil computer")
	}
	if *computer.UUID != "test-uuid" {
		t.Errorf("expected UUID %q, got %q", "test-uuid", *computer.UUID)
	}
	if computer.Plan == nil {
		t.Fatal("expected non-nil plan")
	}
	if *computer.Plan.ID != "plan-123" {
		t.Errorf("expected plan ID %q, got %q", "plan-123", *computer.Plan.ID)
	}
	if *computer.Plan.Name != "Test Plan" {
		t.Errorf("expected plan name %q, got %q", "Test Plan", *computer.Plan.Name)
	}
}

func TestSetComputerPlan_Error(t *testing.T) {
	t.Parallel()

	_, client := testServerError(t, "computer not found")

	ctx := context.Background()
	_, err := client.SetComputerPlan(ctx, "nonexistent", "plan-123")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestUpdateComputer(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()

		if req.Variables["uuid"] != "test-uuid" {
			t.Errorf("expected uuid %q, got %q", "test-uuid", req.Variables["uuid"])
		}
		if req.Variables["label"] != "New Label" {
			t.Errorf("expected label %q, got %q", "New Label", req.Variables["label"])
		}
		tags, ok := req.Variables["tags"].([]any)
		if !ok {
			t.Fatalf("expected tags to be a slice, got %T", req.Variables["tags"])
		}
		if len(tags) != 2 || tags[0] != "tag1" || tags[1] != "tag2" {
			t.Errorf("expected tags [tag1 tag2], got %v", tags)
		}
		if req.Variables["RBAC_Plan"] != true {
			t.Error("expected RBAC_Plan to be true")
		}

		return map[string]any{
			"updateComputer": map[string]any{
				"uuid":             "test-uuid",
				"serial":           "C02TEST",
				"hostName":         "test-host",
				"label":            "New Label",
				"tags":             []string{"tag1", "tag2"},
				"connectionStatus": "Connected",
			},
		}
	})

	ctx := context.Background()
	label := "New Label"
	computer, err := client.UpdateComputer(ctx, "test-uuid", ComputerUpdateInput{
		Label: &label,
		Tags:  []string{"tag1", "tag2"},
	})
	if err != nil {
		t.Fatalf("UpdateComputer: %v", err)
	}
	if computer == nil {
		t.Fatal("UpdateComputer: expected non-nil computer")
	}
	if *computer.UUID != "test-uuid" {
		t.Errorf("expected UUID %q, got %q", "test-uuid", *computer.UUID)
	}
	if *computer.Label != "New Label" {
		t.Errorf("expected label %q, got %q", "New Label", *computer.Label)
	}
	if computer.Tags == nil || len(*computer.Tags) != 2 {
		t.Fatalf("expected 2 tags, got %v", computer.Tags)
	}
}

func TestUpdateComputer_LabelOnly(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()

		if _, ok := req.Variables["tags"]; ok {
			t.Error("expected tags to be absent when nil")
		}
		if req.Variables["label"] != "Only Label" {
			t.Errorf("expected label %q, got %q", "Only Label", req.Variables["label"])
		}

		return map[string]any{
			"updateComputer": map[string]any{
				"uuid":     "test-uuid",
				"hostName": "test-host",
				"label":    "Only Label",
			},
		}
	})

	ctx := context.Background()
	label := "Only Label"
	computer, err := client.UpdateComputer(ctx, "test-uuid", ComputerUpdateInput{
		Label: &label,
	})
	if err != nil {
		t.Fatalf("UpdateComputer: %v", err)
	}
	if *computer.Label != "Only Label" {
		t.Errorf("expected label %q, got %q", "Only Label", *computer.Label)
	}
}

func TestUpdateComputer_TagsOnly(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()

		if _, ok := req.Variables["label"]; ok {
			t.Error("expected label to be absent when nil")
		}
		tags, ok := req.Variables["tags"].([]any)
		if !ok {
			t.Fatalf("expected tags to be a slice, got %T", req.Variables["tags"])
		}
		if len(tags) != 1 || tags[0] != "solo" {
			t.Errorf("expected tags [solo], got %v", tags)
		}

		return map[string]any{
			"updateComputer": map[string]any{
				"uuid":     "test-uuid",
				"hostName": "test-host",
				"tags":     []string{"solo"},
			},
		}
	})

	ctx := context.Background()
	computer, err := client.UpdateComputer(ctx, "test-uuid", ComputerUpdateInput{
		Tags: []string{"solo"},
	})
	if err != nil {
		t.Fatalf("UpdateComputer: %v", err)
	}
	if computer.Tags == nil || len(*computer.Tags) != 1 {
		t.Fatalf("expected 1 tag, got %v", computer.Tags)
	}
}

func TestUpdateComputer_ClearTags(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()

		tags, ok := req.Variables["tags"].([]any)
		if !ok {
			t.Fatalf("expected tags to be a slice, got %T", req.Variables["tags"])
		}
		if len(tags) != 0 {
			t.Errorf("expected empty tags, got %v", tags)
		}

		return map[string]any{
			"updateComputer": map[string]any{
				"uuid":     "test-uuid",
				"hostName": "test-host",
				"tags":     []string{},
			},
		}
	})

	ctx := context.Background()
	computer, err := client.UpdateComputer(ctx, "test-uuid", ComputerUpdateInput{
		Tags: []string{},
	})
	if err != nil {
		t.Fatalf("UpdateComputer: %v", err)
	}
	if computer.Tags == nil || len(*computer.Tags) != 0 {
		t.Fatalf("expected empty tags, got %v", computer.Tags)
	}
}

func TestUpdateComputer_Error(t *testing.T) {
	t.Parallel()

	_, client := testServerError(t, "permission denied")

	ctx := context.Background()
	label := "test"
	_, err := client.UpdateComputer(ctx, "test-uuid", ComputerUpdateInput{Label: &label})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
