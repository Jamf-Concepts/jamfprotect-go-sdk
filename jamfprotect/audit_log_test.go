// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"testing"
	"time"
)

func TestListAuditLogsByDate_Default(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()

		cond, ok := req.Variables["condition"].(map[string]any)
		if !ok {
			t.Fatal("expected condition with date range")
		}
		if _, ok := cond["dateRange"]; !ok {
			t.Fatal("expected dateRange in condition")
		}

		return map[string]any{
			"listAuditLogsByDate": map[string]any{
				"items": []map[string]any{
					{"resourceId": "res-1", "date": "2026-04-11T12:00:00Z", "args": `{}`, "error": nil, "ips": "10.0.0.1", "op": "createRole", "user": "admin"},
				},
				"pageInfo": map[string]any{"next": nil, "total": 1},
			},
		}
	})

	ctx := context.Background()
	logs, err := client.ListAuditLogsByDate(ctx, nil)
	if err != nil {
		t.Fatalf("ListAuditLogsByDate: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("expected 1 log, got %d", len(logs))
	}
}

func TestListAuditLogsByDate_CustomRange(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()

		cond := req.Variables["condition"].(map[string]any)
		dr := cond["dateRange"].(map[string]any)
		if dr["startDate"] == nil || dr["endDate"] == nil {
			t.Error("expected start and end dates")
		}

		return map[string]any{
			"listAuditLogsByDate": map[string]any{
				"items":    []map[string]any{},
				"pageInfo": map[string]any{"next": nil, "total": 0},
			},
		}
	})

	ctx := context.Background()
	end := time.Date(2026, 4, 11, 23, 59, 59, 0, time.UTC)
	start := end.AddDate(0, 0, -1)
	logs, err := client.ListAuditLogsByDate(ctx, &AuditLogDateRange{StartDate: start, EndDate: end})
	if err != nil {
		t.Fatalf("ListAuditLogsByDate: %v", err)
	}
	if len(logs) != 0 {
		t.Errorf("expected 0 logs, got %d", len(logs))
	}
}

func TestListAuditLogsByDate_ClampedRange(t *testing.T) {
	t.Parallel()

	var capturedStart string
	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()
		cond := req.Variables["condition"].(map[string]any)
		dr := cond["dateRange"].(map[string]any)
		capturedStart = dr["startDate"].(string)

		return map[string]any{
			"listAuditLogsByDate": map[string]any{
				"items":    []map[string]any{},
				"pageInfo": map[string]any{"next": nil, "total": 0},
			},
		}
	})

	ctx := context.Background()
	end := time.Date(2026, 4, 11, 0, 0, 0, 0, time.UTC)
	start := end.AddDate(0, 0, -30) // 30 days — should be clamped to 2

	_, err := client.ListAuditLogsByDate(ctx, &AuditLogDateRange{StartDate: start, EndDate: end})
	if err != nil {
		t.Fatalf("ListAuditLogsByDate: %v", err)
	}

	parsed, _ := time.Parse(time.RFC3339, capturedStart)
	expected := end.AddDate(0, 0, -MaxAuditLogDays)
	if !parsed.Equal(expected) {
		t.Errorf("expected clamped start %v, got %v", expected, parsed)
	}
}

func TestListAuditLogsByDate_ErrorField(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()
		return map[string]any{
			"listAuditLogsByDate": map[string]any{
				"items": []map[string]any{
					{"resourceId": "res-1", "date": "2026-04-11T12:00:00Z", "args": `{}`, "error": "Operation Failed: NotFound", "ips": "10.0.0.1", "op": "deleteRole", "user": "admin"},
				},
				"pageInfo": map[string]any{"next": nil, "total": 1},
			},
		}
	})

	ctx := context.Background()
	logs, err := client.ListAuditLogsByDate(ctx, nil)
	if err != nil {
		t.Fatalf("ListAuditLogsByDate: %v", err)
	}
	if logs[0].Error == nil || *logs[0].Error != "Operation Failed: NotFound" {
		t.Errorf("expected error string, got %v", logs[0].Error)
	}
}

func TestListAuditLogsByUser(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()
		cond := req.Variables["condition"].(map[string]any)
		if cond["beginsWith"] != "neil" {
			t.Errorf("expected beginsWith %q, got %v", "neil", cond["beginsWith"])
		}

		return map[string]any{
			"listAuditLogsByUser": map[string]any{
				"items": []map[string]any{
					{"resourceId": "res-1", "date": "2026-04-11T12:00:00Z", "args": `{}`, "error": nil, "ips": "10.0.0.1", "op": "updateComputer", "user": "neil.martin@jamf.com"},
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
}

func TestListAuditLogsByOp(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()
		cond := req.Variables["condition"].(map[string]any)
		if cond["beginsWith"] != "create" {
			t.Errorf("expected beginsWith %q, got %v", "create", cond["beginsWith"])
		}

		return map[string]any{
			"listAuditLogsByOp": map[string]any{
				"items": []map[string]any{
					{"resourceId": "res-1", "date": "2026-04-11T12:00:00Z", "args": `{}`, "error": nil, "ips": "10.0.0.1", "op": "createRole", "user": "admin@clients"},
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
}
