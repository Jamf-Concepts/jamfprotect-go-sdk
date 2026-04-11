// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"testing"
)

func TestListAuditLogsByDate(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()

		if req.Variables["pageSize"] != float64(500) {
			t.Errorf("expected pageSize 500, got %v", req.Variables["pageSize"])
		}

		return map[string]any{
			"listAuditLogsByDate": map[string]any{
				"items": []map[string]any{
					{
						"resourceId": "res-1",
						"date":       "2026-04-11T12:00:00Z",
						"args":       `{"id":"res-1"}`,
						"error":      nil,
						"ips":        "10.0.0.1",
						"op":         "createRole",
						"user":       "admin@example.com",
					},
					{
						"resourceId": "res-2",
						"date":       "2026-04-11T11:00:00Z",
						"args":       `{"id":"res-2"}`,
						"error":      "Operation Failed: NotFound",
						"ips":        "10.0.0.2",
						"op":         "deleteRole",
						"user":       "api-client@clients",
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
	logs, err := client.ListAuditLogsByDate(ctx, nil)
	if err != nil {
		t.Fatalf("ListAuditLogsByDate: %v", err)
	}
	if len(logs) != 2 {
		t.Fatalf("expected 2 logs, got %d", len(logs))
	}
	if logs[0].Op != "createRole" {
		t.Errorf("expected op %q, got %q", "createRole", logs[0].Op)
	}
	if logs[0].Error != nil {
		t.Error("expected nil error on first log")
	}
	if logs[1].Error == nil || *logs[1].Error != "Operation Failed: NotFound" {
		t.Errorf("expected error on second log, got %v", logs[1].Error)
	}
}

func TestListAuditLogsByDate_WithCondition(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()

		cond, ok := req.Variables["condition"].(map[string]any)
		if !ok {
			t.Fatal("expected condition to be set")
		}
		dr, ok := cond["dateRange"].(map[string]any)
		if !ok {
			t.Fatal("expected dateRange in condition")
		}
		if dr["startDate"] != "2026-04-09T00:00:00Z" {
			t.Errorf("expected startDate, got %v", dr["startDate"])
		}

		return map[string]any{
			"listAuditLogsByDate": map[string]any{
				"items":    []map[string]any{},
				"pageInfo": map[string]any{"next": nil, "total": 0},
			},
		}
	})

	ctx := context.Background()
	logs, err := client.ListAuditLogsByDate(ctx, &AuditLogDateCondition{
		DateRange: &AuditLogDateRange{
			StartDate: "2026-04-09T00:00:00Z",
			EndDate:   "2026-04-11T23:59:59Z",
		},
	})
	if err != nil {
		t.Fatalf("ListAuditLogsByDate: %v", err)
	}
	if len(logs) != 0 {
		t.Errorf("expected 0 logs, got %d", len(logs))
	}
}

func TestListAuditLogsByUser(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()

		cond, ok := req.Variables["condition"].(map[string]any)
		if !ok {
			t.Fatal("expected condition")
		}
		if cond["beginsWith"] != "neil" {
			t.Errorf("expected beginsWith %q, got %v", "neil", cond["beginsWith"])
		}

		return map[string]any{
			"listAuditLogsByUser": map[string]any{
				"items": []map[string]any{
					{
						"resourceId": "res-1",
						"date":       "2026-04-11T12:00:00Z",
						"args":       `{}`,
						"error":      nil,
						"ips":        "10.0.0.1",
						"op":         "updateComputer",
						"user":       "neil.martin@jamf.com#oidc|test",
					},
				},
				"pageInfo": map[string]any{"next": nil, "total": 1},
			},
		}
	})

	ctx := context.Background()
	logs, err := client.ListAuditLogsByUser(ctx, "neil")
	if err != nil {
		t.Fatalf("ListAuditLogsByUser: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(logs))
	}
	if logs[0].User != "neil.martin@jamf.com#oidc|test" {
		t.Errorf("expected user prefix match, got %q", logs[0].User)
	}
}

func TestListAuditLogsByOp(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()

		cond, ok := req.Variables["condition"].(map[string]any)
		if !ok {
			t.Fatal("expected condition")
		}
		if cond["beginsWith"] != "create" {
			t.Errorf("expected beginsWith %q, got %v", "create", cond["beginsWith"])
		}

		return map[string]any{
			"listAuditLogsByOp": map[string]any{
				"items": []map[string]any{
					{
						"resourceId": "res-1",
						"date":       "2026-04-11T12:00:00Z",
						"args":       `{}`,
						"error":      nil,
						"ips":        "10.0.0.1",
						"op":         "createRole",
						"user":       "admin@clients",
					},
				},
				"pageInfo": map[string]any{"next": nil, "total": 1},
			},
		}
	})

	ctx := context.Background()
	logs, err := client.ListAuditLogsByOp(ctx, "create")
	if err != nil {
		t.Fatalf("ListAuditLogsByOp: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(logs))
	}
	if logs[0].Op != "createRole" {
		t.Errorf("expected op %q, got %q", "createRole", logs[0].Op)
	}
}
