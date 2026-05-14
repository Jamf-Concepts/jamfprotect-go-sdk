// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"testing"
)

func TestAcc_ChangeManagement_GetConfigFreeze(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()

	cfg, err := client.GetConfigFreeze(ctx)
	if err != nil {
		t.Fatalf("GetConfigFreeze: %v", err)
	}
	t.Logf("ConfigFreeze: %t", cfg.ConfigFreeze)
}
