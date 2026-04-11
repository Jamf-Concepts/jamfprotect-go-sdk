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

	// Use a tight 1-hour window to keep the acc test fast.
	logs, err := client.ListAuditLogsByDate(ctx, nil)
	if err != nil {
		t.Fatalf("ListAuditLogsByDate: %v", err)
	}
	t.Logf("ListAuditLogsByDate: %d entries", len(logs))
}
