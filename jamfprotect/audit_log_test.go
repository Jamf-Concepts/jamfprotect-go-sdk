// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"testing"
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
				"pageInfo": map[string]any{"next": nil},
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

func TestListAuditLogsByDate_StopsOnRepeatedCursor(t *testing.T) {
	t.Parallel()

	callCount := 0
	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()
		callCount++
		return map[string]any{
			"listAuditLogsByDate": map[string]any{
				"items": []map[string]any{
					{"resourceId": "1", "date": "2026-04-11T12:00:00Z", "args": "{}", "ips": "", "op": "a", "user": "u"},
				},
				"pageInfo": map[string]any{"next": "same-cursor-forever"},
			},
		}
	})

	ctx := context.Background()
	logs, err := client.ListAuditLogsByDate(ctx, nil)
	if err != nil {
		t.Fatalf("ListAuditLogsByDate: %v", err)
	}
	if callCount > 2 {
		t.Errorf("expected pagination to stop on repeated cursor, got %d calls", callCount)
	}
	if len(logs) == 0 {
		t.Fatal("expected at least some logs")
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
				"pageInfo": map[string]any{"next": nil},
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
				"pageInfo": map[string]any{"next": nil},
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
				"pageInfo": map[string]any{"next": nil},
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
