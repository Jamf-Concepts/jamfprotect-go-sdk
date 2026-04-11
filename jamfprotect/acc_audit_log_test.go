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

	logs, err := client.ListAuditLogsByDate(ctx, 2)
	if err != nil {
		t.Fatalf("ListAuditLogsByDate: %v", err)
	}
	if len(logs) == 0 {
		t.Fatal("ListAuditLogsByDate: expected at least one audit log entry")
	}
	t.Logf("ListAuditLogsByDate: %d entries (first op: %s by %s)", len(logs), logs[0].Op, logs[0].User)
}
