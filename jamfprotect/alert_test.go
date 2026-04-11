// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"testing"
)

func TestGetAlert(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()

		if req.Variables["uuid"] != "alert-uuid-1" {
			t.Errorf("expected uuid %q, got %q", "alert-uuid-1", req.Variables["uuid"])
		}

		return map[string]any{
			"getAlert": map[string]any{
				"uuid":      "alert-uuid-1",
				"created":   "2026-04-11T12:00:00Z",
				"status":    "New",
				"severity":  "High",
				"actions":   []string{"Log"},
				"tags":      []string{"malware"},
				"eventType": "GPProcessEvent",
				"plan": map[string]any{
					"uuid": "plan-uuid",
					"name": "Default Plan",
				},
				"computer": map[string]any{
					"uuid":      "comp-uuid",
					"hostName":  "test-mac",
					"modelName": "MacBookPro18,1",
					"plan": map[string]any{
						"id":   "plan-123",
						"name": "Default Plan",
					},
				},
				"analytics": []map[string]any{
					{
						"name":        "Test Analytic",
						"label":       "test-label",
						"description": "A test analytic",
						"uuid":        "analytic-uuid",
					},
				},
				"facts": []map[string]any{
					{
						"name":        "Test Fact",
						"tags":        []string{"threat"},
						"human":       "Suspicious process detected",
						"severity":    "High",
						"matchReason": "path match",
						"actions":     []map[string]any{{"name": "Log"}},
					},
				},
			},
		}
	})

	ctx := context.Background()
	alert, err := client.GetAlert(ctx, "alert-uuid-1")
	if err != nil {
		t.Fatalf("GetAlert: %v", err)
	}
	if alert == nil {
		t.Fatal("GetAlert: expected non-nil alert")
	}
	if alert.UUID != "alert-uuid-1" {
		t.Errorf("expected UUID %q, got %q", "alert-uuid-1", alert.UUID)
	}
	if alert.Status != "New" {
		t.Errorf("expected status %q, got %q", "New", alert.Status)
	}
	if alert.Severity != "High" {
		t.Errorf("expected severity %q, got %q", "High", alert.Severity)
	}
	if alert.Plan == nil || alert.Plan.Name != "Default Plan" {
		t.Errorf("expected plan name %q, got %v", "Default Plan", alert.Plan)
	}
	if alert.Computer == nil || alert.Computer.HostName != "test-mac" {
		t.Errorf("expected computer hostname %q, got %v", "test-mac", alert.Computer)
	}
	if alert.Computer.Plan == nil || alert.Computer.Plan.ID != "plan-123" {
		t.Error("expected computer plan to be populated")
	}
	if len(alert.Analytics) != 1 || alert.Analytics[0].UUID != "analytic-uuid" {
		t.Errorf("expected 1 analytic, got %d", len(alert.Analytics))
	}
	if len(alert.Facts) != 1 || alert.Facts[0].Human != "Suspicious process detected" {
		t.Errorf("expected 1 fact, got %d", len(alert.Facts))
	}
	if alert.Facts[0].MatchReason != "path match" {
		t.Errorf("expected matchReason %q, got %q", "path match", alert.Facts[0].MatchReason)
	}
	if len(alert.Facts[0].Actions) != 1 || alert.Facts[0].Actions[0].Name != "Log" {
		t.Error("expected fact actions to be populated")
	}
}

func TestGetAlert_NotFound(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()
		return map[string]any{
			"getAlert": nil,
		}
	})

	ctx := context.Background()
	alert, err := client.GetAlert(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("GetAlert: %v", err)
	}
	if alert != nil {
		t.Errorf("expected nil alert, got %v", alert)
	}
}

func TestListAlerts(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()

		if req.Variables["direction"] != "DESC" {
			t.Errorf("expected direction %q, got %q", "DESC", req.Variables["direction"])
		}
		if req.Variables["field"] != "created" {
			t.Errorf("expected field %q, got %q", "created", req.Variables["field"])
		}

		return map[string]any{
			"listAlerts": map[string]any{
				"items": []map[string]any{
					{
						"uuid":     "alert-1",
						"created":  "2026-04-11T12:00:00Z",
						"status":   "New",
						"severity": "High",
					},
					{
						"uuid":     "alert-2",
						"created":  "2026-04-11T11:00:00Z",
						"status":   "Resolved",
						"severity": "Low",
					},
				},
				"pageInfo": map[string]any{
					"next":  nil,
					"total": 2,
				},
			},
		}
	})

	ctx := context.Background()
	alerts, err := client.ListAlerts(ctx)
	if err != nil {
		t.Fatalf("ListAlerts: %v", err)
	}
	if len(alerts) != 2 {
		t.Fatalf("expected 2 alerts, got %d", len(alerts))
	}
	if alerts[0].UUID != "alert-1" {
		t.Errorf("expected first alert UUID %q, got %q", "alert-1", alerts[0].UUID)
	}
	if alerts[1].Status != "Resolved" {
		t.Errorf("expected second alert status %q, got %q", "Resolved", alerts[1].Status)
	}
}

func TestListAlerts_Empty(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()
		return map[string]any{
			"listAlerts": map[string]any{
				"items": []map[string]any{},
				"pageInfo": map[string]any{
					"next":  nil,
					"total": 0,
				},
			},
		}
	})

	ctx := context.Background()
	alerts, err := client.ListAlerts(ctx)
	if err != nil {
		t.Fatalf("ListAlerts: %v", err)
	}
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts, got %d", len(alerts))
	}
}

func TestUpdateAlerts(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()

		uuids, ok := req.Variables["uuids"].([]any)
		if !ok {
			t.Fatalf("expected uuids to be a slice, got %T", req.Variables["uuids"])
		}
		if len(uuids) != 2 || uuids[0] != "alert-1" || uuids[1] != "alert-2" {
			t.Errorf("expected uuids [alert-1 alert-2], got %v", uuids)
		}
		if req.Variables["status"] != "Resolved" {
			t.Errorf("expected status %q, got %q", "Resolved", req.Variables["status"])
		}

		return map[string]any{
			"updateAlerts": map[string]any{
				"items": []map[string]any{
					{"uuid": "alert-1", "status": "Resolved", "severity": "High"},
					{"uuid": "alert-2", "status": "Resolved", "severity": "Low"},
				},
			},
		}
	})

	ctx := context.Background()
	alerts, err := client.UpdateAlerts(ctx, AlertUpdateInput{
		UUIDs:  []string{"alert-1", "alert-2"},
		Status: "Resolved",
	})
	if err != nil {
		t.Fatalf("UpdateAlerts: %v", err)
	}
	if len(alerts) != 2 {
		t.Fatalf("expected 2 alerts, got %d", len(alerts))
	}
	if alerts[0].Status != "Resolved" {
		t.Errorf("expected status %q, got %q", "Resolved", alerts[0].Status)
	}
	if alerts[1].Status != "Resolved" {
		t.Errorf("expected status %q, got %q", "Resolved", alerts[1].Status)
	}
}

func TestGetAlertStatusCounts(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()
		return map[string]any{
			"getAlertStatusCounts": map[string]any{
				"New":          12,
				"InProgress":   3,
				"Resolved":     45,
				"AutoResolved": 7,
			},
		}
	})

	ctx := context.Background()
	counts, err := client.GetAlertStatusCounts(ctx)
	if err != nil {
		t.Fatalf("GetAlertStatusCounts: %v", err)
	}
	if counts.New != 12 {
		t.Errorf("expected New=12, got %d", counts.New)
	}
	if counts.InProgress != 3 {
		t.Errorf("expected InProgress=3, got %d", counts.InProgress)
	}
	if counts.Resolved != 45 {
		t.Errorf("expected Resolved=45, got %d", counts.Resolved)
	}
	if counts.AutoResolved != 7 {
		t.Errorf("expected AutoResolved=7, got %d", counts.AutoResolved)
	}
}

func TestUpdateAlerts_Error(t *testing.T) {
	t.Parallel()

	_, client := testServerError(t, "permission denied")

	ctx := context.Background()
	_, err := client.UpdateAlerts(ctx, AlertUpdateInput{
		UUIDs:  []string{"alert-1"},
		Status: "Resolved",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
