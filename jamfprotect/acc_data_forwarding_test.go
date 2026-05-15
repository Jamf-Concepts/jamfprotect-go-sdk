// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"testing"
)

func TestAcc_DataForwarding_Get(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()

	result, err := client.GetDataForwarding(ctx)
	if err != nil {
		t.Fatalf("GetDataForwarding: %v", err)
	}
	t.Logf("DataForwarding: uuid=%s s3Enabled=%t sentinelEnabled=%t sentinelV2Enabled=%t",
		result.UUID,
		result.Forward.S3.Enabled,
		result.Forward.Sentinel.Enabled,
		result.Forward.SentinelV2.Enabled,
	)
}
