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

	logs, err := client.ListAuditLogsByDate(ctx, nil)
	if err != nil {
		t.Fatalf("ListAuditLogsByDate: %v", err)
	}
	if len(logs) == 0 {
		t.Fatal("ListAuditLogsByDate: expected at least one audit log entry")
	}
	t.Logf("ListAuditLogsByDate: %d entries", len(logs))
}

func TestAcc_AuditLogs_ListByOp(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()

	logs, err := client.ListAuditLogsByOp(ctx, "create")
	if err != nil {
		t.Fatalf("ListAuditLogsByOp: %v", err)
	}
	t.Logf("ListAuditLogsByOp(create): %d entries", len(logs))
}

func TestAcc_AuditLogs_ListByUser(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()

	logs, err := client.ListAuditLogsByUser(ctx, "7UBMO52m")
	if err != nil {
		t.Fatalf("ListAuditLogsByUser: %v", err)
	}
	t.Logf("ListAuditLogsByUser(7UBMO52m): %d entries", len(logs))
}
