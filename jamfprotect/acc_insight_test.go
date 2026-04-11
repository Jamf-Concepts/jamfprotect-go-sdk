// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"testing"
)

func TestAcc_Insights_List(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()

	insights, err := client.ListInsights(ctx)
	if err != nil {
		t.Fatalf("ListInsights: %v", err)
	}
	if len(insights) == 0 {
		t.Fatal("ListInsights: expected at least one insight")
	}
	t.Logf("ListInsights: %d insights", len(insights))

	// Verify we can list computers for the first insight.
	computers, err := client.ListInsightComputers(ctx, insights[0].UUID)
	if err != nil {
		t.Fatalf("ListInsightComputers(%s): %v", insights[0].UUID, err)
	}
	t.Logf("ListInsightComputers(%s / %s): %d computers", insights[0].UUID, insights[0].Label, len(computers))

	// Verify fleet compliance score.
	score, err := client.GetFleetComplianceScore(ctx, "")
	if err != nil {
		t.Fatalf("GetFleetComplianceScore: %v", err)
	}
	t.Logf("Fleet compliance score: %.2f%% (updated %s)", score.Score, score.Updated)
}
