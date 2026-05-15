// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"testing"
)

func TestAcc_Alerts_UpdateStatus(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()

	alerts, err := client.ListAlerts(ctx)
	if err != nil {
		t.Fatalf("ListAlerts: %v", err)
	}
	if len(alerts) == 0 {
		t.Skip("no alerts available; skipping UpdateAlerts test")
	}

	// Pick a "New" alert to avoid disturbing alerts already in progress.
	var target *Alert
	for i := range alerts {
		if alerts[i].Status == "New" {
			target = &alerts[i]
			break
		}
	}
	if target == nil {
		t.Skip("no New alerts available; skipping UpdateAlerts test")
	}

	// Update to InProgress.
	updated, err := client.UpdateAlerts(ctx, AlertUpdateInput{
		UUIDs:  []string{target.UUID},
		Status: "InProgress",
	})
	if err != nil {
		t.Fatalf("UpdateAlerts: %v", err)
	}
	if len(updated) != 1 {
		t.Fatalf("UpdateAlerts: expected 1 updated alert, got %d", len(updated))
	}
	if updated[0].Status != "InProgress" {
		t.Errorf("expected status %q, got %q", "InProgress", updated[0].Status)
	}

	// Restore original status.
	t.Cleanup(func() {
		_, err := client.UpdateAlerts(ctx, AlertUpdateInput{
			UUIDs:  []string{target.UUID},
			Status: "New",
		})
		if err != nil {
			t.Logf("warning: failed to restore alert %s status: %v", target.UUID, err)
		}
	})
}
