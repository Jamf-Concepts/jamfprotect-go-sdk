// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"errors"
	"sync"
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

func TestListAuditLogsByDate_RepeatedCursor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cursors []string
	}{
		{name: "same cursor", cursors: []string{"c1", "c1"}},
		{name: "alternating cursors", cursors: []string{"c1", "c2", "c1"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var mu sync.Mutex
			callCount := 0
			_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
				t.Helper()
				mu.Lock()
				defer mu.Unlock()
				next := tt.cursors[min(callCount, len(tt.cursors)-1)]
				callCount++
				return map[string]any{
					"listAuditLogsByDate": map[string]any{
						"items": []map[string]any{
							{"resourceId": "1", "date": "2026-04-11T12:00:00Z", "args": "{}", "ips": "", "op": "a", "user": "u"},
						},
						"pageInfo": map[string]any{"next": next},
					},
				}
			})

			logs, err := client.ListAuditLogsByDate(context.Background(), nil)
			if !errors.Is(err, ErrPaginationLimit) {
				t.Fatalf("expected ErrPaginationLimit, got logs=%d err=%v", len(logs), err)
			}
			mu.Lock()
			defer mu.Unlock()
			if callCount != len(tt.cursors) {
				t.Errorf("expected %d calls, got %d", len(tt.cursors), callCount)
			}
		})
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
