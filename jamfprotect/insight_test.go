// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"testing"
)

func TestListInsights(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()
		return map[string]any{
			"listInsights": []map[string]any{
				{
					"uuid":        "insight-1",
					"label":       "FileVault Enabled",
					"description": "FileVault secures data",
					"section":     "System Settings",
					"totalPass":   10,
					"totalFail":   2,
					"totalNone":   0,
					"tags":        []string{"CIS Level 1"},
					"enabled":     true,
					"cisid": []map[string]any{
						{"id": "2.6.6", "osVersion": "macOS 15"},
					},
				},
				{
					"uuid":      "insight-2",
					"label":     "Firewall Enabled",
					"section":   "System Settings",
					"totalPass": 5,
					"totalFail": 7,
					"totalNone": 0,
					"tags":      []string{"CIS Level 1"},
					"enabled":   false,
					"cisid":     []map[string]any{},
				},
			},
		}
	})

	ctx := context.Background()
	insights, err := client.ListInsights(ctx)
	if err != nil {
		t.Fatalf("ListInsights: %v", err)
	}
	if len(insights) != 2 {
		t.Fatalf("expected 2 insights, got %d", len(insights))
	}
	if insights[0].UUID != "insight-1" {
		t.Errorf("expected UUID %q, got %q", "insight-1", insights[0].UUID)
	}
	if insights[0].Label != "FileVault Enabled" {
		t.Errorf("expected label %q, got %q", "FileVault Enabled", insights[0].Label)
	}
	if insights[0].TotalPass != 10 {
		t.Errorf("expected totalPass=10, got %d", insights[0].TotalPass)
	}
	if insights[0].TotalFail != 2 {
		t.Errorf("expected totalFail=2, got %d", insights[0].TotalFail)
	}
	if !insights[0].Enabled {
		t.Error("expected first insight to be enabled")
	}
	if len(insights[0].CisID) != 1 || insights[0].CisID[0].ID != "2.6.6" {
		t.Errorf("expected cisid [2.6.6], got %v", insights[0].CisID)
	}
	if insights[1].Enabled {
		t.Error("expected second insight to be disabled")
	}
}

func TestUpdateInsightStatus(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()

		if req.Variables["uuid"] != "insight-1" {
			t.Errorf("expected uuid %q, got %q", "insight-1", req.Variables["uuid"])
		}
		if req.Variables["enabled"] != false {
			t.Errorf("expected enabled=false, got %v", req.Variables["enabled"])
		}

		return map[string]any{
			"updateInsightStatus": map[string]any{
				"uuid":      "insight-1",
				"label":     "FileVault Enabled",
				"section":   "System Settings",
				"totalPass": 10,
				"totalFail": 2,
				"totalNone": 0,
				"tags":      []string{"CIS Level 1"},
				"enabled":   false,
			},
		}
	})

	ctx := context.Background()
	insight, err := client.UpdateInsightStatus(ctx, "insight-1", false)
	if err != nil {
		t.Fatalf("UpdateInsightStatus: %v", err)
	}
	if insight.UUID != "insight-1" {
		t.Errorf("expected UUID %q, got %q", "insight-1", insight.UUID)
	}
	if insight.Enabled {
		t.Error("expected insight to be disabled")
	}
}

func TestListInsightComputers(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()

		if req.Variables["uuid"] != "insight-1" {
			t.Errorf("expected uuid %q, got %q", "insight-1", req.Variables["uuid"])
		}

		return map[string]any{
			"listInsightComputers": map[string]any{
				"items": []map[string]any{
					{
						"uuid":                 "comp-1",
						"hostName":             "test-mac",
						"insightsUpdated":      "2026-04-11T12:00:00Z",
						"insightsStatsFail":    3,
						"insightsStatsPass":    40,
						"insightsStatsUnknown": 1,
					},
				},
				"pageInfo": map[string]any{
					"next":  nil,
					"total": 1,
				},
			},
		}
	})

	ctx := context.Background()
	computers, err := client.ListInsightComputers(ctx, "insight-1")
	if err != nil {
		t.Fatalf("ListInsightComputers: %v", err)
	}
	if len(computers) != 1 {
		t.Fatalf("expected 1 computer, got %d", len(computers))
	}
	if computers[0].HostName != "test-mac" {
		t.Errorf("expected hostname %q, got %q", "test-mac", computers[0].HostName)
	}
	if computers[0].InsightsStatsFail != 3 {
		t.Errorf("expected fail=3, got %d", computers[0].InsightsStatsFail)
	}
}

func TestGetFleetComplianceScore(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()
		return map[string]any{
			"getFleetComplianceBaselineScore": map[string]any{
				"updated": "2026-04-11",
				"score":   56.25,
			},
		}
	})

	ctx := context.Background()
	score, err := client.GetFleetComplianceScore(ctx, "")
	if err != nil {
		t.Fatalf("GetFleetComplianceScore: %v", err)
	}
	if score.Score != 56.25 {
		t.Errorf("expected score 56.25, got %f", score.Score)
	}
	if score.Updated != "2026-04-11" {
		t.Errorf("expected updated %q, got %q", "2026-04-11", score.Updated)
	}
}

func TestGetFleetComplianceScore_WithDate(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()

		if req.Variables["date"] != "2026-03-12" {
			t.Errorf("expected date %q, got %q", "2026-03-12", req.Variables["date"])
		}

		return map[string]any{
			"getFleetComplianceBaselineScore": map[string]any{
				"updated": "2026-03-12",
				"score":   50.0,
			},
		}
	})

	ctx := context.Background()
	score, err := client.GetFleetComplianceScore(ctx, "2026-03-12")
	if err != nil {
		t.Fatalf("GetFleetComplianceScore: %v", err)
	}
	if score.Score != 50.0 {
		t.Errorf("expected score 50.0, got %f", score.Score)
	}
}
