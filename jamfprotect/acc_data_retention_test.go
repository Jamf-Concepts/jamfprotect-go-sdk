// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"testing"
)

func TestAcc_DataRetention_Get(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()

	retention, err := client.GetDataRetention(ctx)
	if err != nil {
		t.Fatalf("GetDataRetention: %v", err)
	}
	t.Logf("DataRetention: databaseLogDays=%d databaseAlertDays=%d coldAlertDays=%d updated=%s",
		retention.Database.Log.NumberOfDays,
		retention.Database.Alert.NumberOfDays,
		retention.Cold.Alert.NumberOfDays,
		retention.Updated,
	)
}
