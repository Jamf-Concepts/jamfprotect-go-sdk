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
	page, err := client.ListAuditLogsByDate(ctx, 100, nil, nil)
	if err != nil {
		t.Fatalf("ListAuditLogsByDate: %v", err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("expected 1 log, got %d", len(page.Items))
	}
	if page.Next != nil {
		t.Error("expected nil Next cursor")
	}
}

func TestListAuditLogsByDate_Pagination(t *testing.T) {
	t.Parallel()

	callCount := 0
	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()
		callCount++
		if callCount == 1 {
			cursor := "page2"
			return map[string]any{
				"listAuditLogsByDate": map[string]any{
					"items":    []map[string]any{{"resourceId": "1", "date": "2026-04-11T12:00:00Z", "args": "{}", "ips": "", "op": "a", "user": "u"}},
					"pageInfo": map[string]any{"next": cursor},
				},
			}
		}
		return map[string]any{
			"listAuditLogsByDate": map[string]any{
				"items":    []map[string]any{{"resourceId": "2", "date": "2026-04-10T12:00:00Z", "args": "{}", "ips": "", "op": "b", "user": "u"}},
				"pageInfo": map[string]any{"next": nil},
			},
		}
	})

	ctx := context.Background()
	p1, err := client.ListAuditLogsByDate(ctx, 1, nil, nil)
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if p1.Next == nil {
		t.Fatal("expected cursor on page 1")
	}

	p2, err := client.ListAuditLogsByDate(ctx, 1, p1.Next, nil)
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	if p2.Next != nil {
		t.Error("expected nil cursor on page 2")
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
	page, err := client.ListAuditLogsByDate(ctx, 100, nil, nil)
	if err != nil {
		t.Fatalf("ListAuditLogsByDate: %v", err)
	}
	if page.Items[0].Error == nil || *page.Items[0].Error != "Operation Failed: NotFound" {
		t.Errorf("expected error string, got %v", page.Items[0].Error)
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
	page, err := client.ListAuditLogsByUser(ctx, 100, nil, "neil")
	if err != nil {
		t.Fatalf("ListAuditLogsByUser: %v", err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("expected 1 log, got %d", len(page.Items))
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
	page, err := client.ListAuditLogsByOp(ctx, 100, nil, "create")
	if err != nil {
		t.Fatalf("ListAuditLogsByOp: %v", err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("expected 1 log, got %d", len(page.Items))
	}
}
