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

	page, err := client.ListAuditLogsByDate(ctx, 0, nil, nil)
	if err != nil {
		t.Fatalf("ListAuditLogsByDate: %v", err)
	}
	if len(page.Items) == 0 {
		t.Fatal("ListAuditLogsByDate: expected at least one audit log entry")
	}
	t.Logf("ListAuditLogsByDate: %d items", len(page.Items))
}

func TestAcc_AuditLogs_ListByOp(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()

	page, err := client.ListAuditLogsByOp(ctx, 0, nil, "create")
	if err != nil {
		t.Fatalf("ListAuditLogsByOp: %v", err)
	}
	t.Logf("ListAuditLogsByOp(create): %d items", len(page.Items))
}

func TestAcc_AuditLogs_ListByUser(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()

	page, err := client.ListAuditLogsByUser(ctx, 0, nil, "7UBMO52m")
	if err != nil {
		t.Fatalf("ListAuditLogsByUser: %v", err)
	}
	t.Logf("ListAuditLogsByUser(7UBMO52m): %d items", len(page.Items))
}
