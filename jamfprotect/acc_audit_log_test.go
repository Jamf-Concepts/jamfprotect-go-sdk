// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"testing"
)

func TestAcc_AuditLogs_ListByDate(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()

	var all []AuditLog
	var next *string
	for {
		page, err := client.ListAuditLogsByDate(ctx, 500, next, nil)
		if err != nil {
			t.Fatalf("ListAuditLogsByDate: %v", err)
		}
		all = append(all, page.Items...)
		if page.Next == nil {
			break
		}
		next = page.Next
	}

	if len(all) == 0 {
		t.Fatal("ListAuditLogsByDate: expected at least one audit log entry")
	}
	t.Logf("ListAuditLogsByDate (7 days): %d total entries", len(all))
}

func TestAcc_AuditLogs_ListByOp(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()

	page, err := client.ListAuditLogsByOp(ctx, 10, nil, "create")
	if err != nil {
		t.Fatalf("ListAuditLogsByOp: %v", err)
	}
	for _, log := range page.Items {
		if len(log.Op) < 6 || log.Op[:6] != "create" {
			t.Errorf("expected op starting with 'create', got %q", log.Op)
		}
	}
	t.Logf("ListAuditLogsByOp(create): %d items, hasMore=%v", len(page.Items), page.Next != nil)
}

func TestAcc_AuditLogs_ListByUser(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()

	page, err := client.ListAuditLogsByUser(ctx, 10, nil, "7UBMO52m")
	if err != nil {
		t.Fatalf("ListAuditLogsByUser: %v", err)
	}
	if len(page.Items) == 0 {
		t.Fatal("ListAuditLogsByUser: expected at least one entry for the acc test API client")
	}
	t.Logf("ListAuditLogsByUser(7UBMO52m): %d items, hasMore=%v", len(page.Items), page.Next != nil)
}
