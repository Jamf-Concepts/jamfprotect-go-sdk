// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"encoding/json"
	"testing"
)

func TestAcc_GetCount(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()

	counts, err := client.GetCount(ctx)
	if err != nil {
		t.Fatalf("GetCount: %v", err)
	}
	b, _ := json.MarshalIndent(counts, "", "  ")
	t.Logf("GetCount:\n%s", b)
}

func TestAcc_GetComputerCount(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()

	count, err := client.GetComputerCount(ctx)
	if err != nil {
		t.Fatalf("GetComputerCount: %v", err)
	}
	t.Logf("GetComputerCount: %d computers", count)
}

func TestAcc_ListRiskiestComputers(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()

	computers, err := client.ListRiskiestComputers(ctx, 5, "30d")
	if err != nil {
		t.Fatalf("ListRiskiestComputers: %v", err)
	}
	b, _ := json.MarshalIndent(computers, "", "  ")
	t.Logf("ListRiskiestComputers (top 5, 30d):\n%s", b)
}
