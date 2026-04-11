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

	page, err := client.ListAuditLogsByDate(ctx, 10, nil, nil)
	if err != nil {
		t.Fatalf("ListAuditLogsByDate: %v", err)
	}
	if len(page.Items) == 0 {
		t.Fatal("ListAuditLogsByDate: expected at least one audit log entry")
	}
	t.Logf("ListAuditLogsByDate: %d items, hasMore=%v (first op: %s by %s)",
		len(page.Items), page.Next != nil, page.Items[0].Op, page.Items[0].User)
}
