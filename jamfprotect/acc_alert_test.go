// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"testing"
)

func TestAcc_Alerts_List(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()

	alerts, err := client.ListAlerts(ctx)
	if err != nil {
		t.Fatalf("ListAlerts: %v", err)
	}

	counts, err := client.GetAlertStatusCounts(ctx)
	if err != nil {
		t.Fatalf("GetAlertStatusCounts: %v", err)
	}
	total := counts.New + counts.InProgress + counts.Resolved + counts.AutoResolved
	t.Logf("Alert status counts: New=%d InProgress=%d Resolved=%d AutoResolved=%d (total=%d)",
		counts.New, counts.InProgress, counts.Resolved, counts.AutoResolved, total)

	// If alerts exist, verify we can get one by UUID.
	if len(alerts) > 0 {
		alert, err := client.GetAlert(ctx, alerts[0].UUID)
		if err != nil {
			t.Fatalf("GetAlert(%s): %v", alerts[0].UUID, err)
		}
		if alert == nil {
			t.Fatalf("GetAlert(%s): expected non-nil alert", alerts[0].UUID)
		}
		if alert.UUID != alerts[0].UUID {
			t.Errorf("expected UUID %q, got %q", alerts[0].UUID, alert.UUID)
		}
	}
}
