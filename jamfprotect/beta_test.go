// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"testing"
)

func TestGetBetaAcceptanceStatus(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()
		return map[string]any{
			"getAppInitializationData": map[string]any{
				"betaAcceptanceStatus": []map[string]any{
					{
						"betaName":          "NGTP_BETA",
						"acceptedTimestamp": "2026-01-15T10:00:00Z",
						"acceptedUser":      "admin@example.com",
					},
				},
			},
		}
	})

	ctx := context.Background()
	statuses, err := client.GetBetaAcceptanceStatus(ctx)
	if err != nil {
		t.Fatalf("GetBetaAcceptanceStatus: %v", err)
	}
	if len(statuses) != 1 {
		t.Fatalf("expected 1 status, got %d", len(statuses))
	}
	if statuses[0].BetaName != "NGTP_BETA" {
		t.Errorf("expected betaName %q, got %q", "NGTP_BETA", statuses[0].BetaName)
	}
	if statuses[0].AcceptedTimestamp != "2026-01-15T10:00:00Z" {
		t.Errorf("expected acceptedTimestamp %q, got %q", "2026-01-15T10:00:00Z", statuses[0].AcceptedTimestamp)
	}
	if statuses[0].AcceptedUser != "admin@example.com" {
		t.Errorf("expected acceptedUser %q, got %q", "admin@example.com", statuses[0].AcceptedUser)
	}
}

func TestGetBetaAcceptanceStatus_Empty(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()
		return map[string]any{
			"getAppInitializationData": map[string]any{
				"betaAcceptanceStatus": []map[string]any{},
			},
		}
	})

	ctx := context.Background()
	statuses, err := client.GetBetaAcceptanceStatus(ctx)
	if err != nil {
		t.Fatalf("GetBetaAcceptanceStatus: %v", err)
	}
	if len(statuses) != 0 {
		t.Fatalf("expected 0 statuses, got %d", len(statuses))
	}
}

func TestUpdateBetaAcceptanceStatus(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()

		if req.Variables["betaName"] != string(BetaNameNGTP) {
			t.Errorf("expected betaName %q, got %q", BetaNameNGTP, req.Variables["betaName"])
		}

		return map[string]any{
			"updateBetaAcceptanceStatus": map[string]any{
				"betaAcceptanceStatus": []map[string]any{
					{
						"betaName":          "NGTP_BETA",
						"acceptedTimestamp": "2026-04-28T09:00:00Z",
						"acceptedUser":      "admin@example.com",
					},
				},
			},
		}
	})

	ctx := context.Background()
	statuses, err := client.UpdateBetaAcceptanceStatus(ctx, BetaNameNGTP)
	if err != nil {
		t.Fatalf("UpdateBetaAcceptanceStatus: %v", err)
	}
	if len(statuses) != 1 {
		t.Fatalf("expected 1 status, got %d", len(statuses))
	}
	if statuses[0].BetaName != "NGTP_BETA" {
		t.Errorf("expected betaName %q, got %q", "NGTP_BETA", statuses[0].BetaName)
	}
	if statuses[0].AcceptedUser != "admin@example.com" {
		t.Errorf("expected acceptedUser %q, got %q", "admin@example.com", statuses[0].AcceptedUser)
	}
}

func TestUpdateBetaAcceptanceStatus_Error(t *testing.T) {
	t.Parallel()

	_, client := testServerError(t, "unauthorized")

	ctx := context.Background()
	_, err := client.UpdateBetaAcceptanceStatus(ctx, BetaNameNGTP)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
