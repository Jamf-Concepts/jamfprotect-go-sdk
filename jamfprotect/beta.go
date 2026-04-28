// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"fmt"
)

// BetaName identifies a beta program in Jamf Protect.
type BetaName string

const (
	// BetaNameNGTP is the Next-Generation Threat Prevention beta program.
	BetaNameNGTP BetaName = "NGTP_BETA"
)

const betaAcceptanceGetQuery = `
query getBetaAcceptanceStatus {
	getAppInitializationData {
		betaAcceptanceStatus {
			betaName
			acceptedTimestamp
			acceptedUser
		}
	}
}
`

const betaAcceptanceUpdateMutation = `
mutation updateBetaAcceptanceStatus($betaName: BetaName!) {
	updateBetaAcceptanceStatus(input: {betaName: $betaName}) {
		betaAcceptanceStatus {
			betaName
			acceptedTimestamp
			acceptedUser
		}
	}
}
`

// BetaAcceptanceStatus records the acceptance details for a beta program.
type BetaAcceptanceStatus struct {
	BetaName          string `json:"betaName"`
	AcceptedTimestamp string `json:"acceptedTimestamp"`
	AcceptedUser      string `json:"acceptedUser"`
}

// GetBetaAcceptanceStatus retrieves beta program acceptance records for the organization.
func (c *Client) GetBetaAcceptanceStatus(ctx context.Context) ([]BetaAcceptanceStatus, error) {
	var result struct {
		GetAppInitializationData struct {
			BetaAcceptanceStatus []BetaAcceptanceStatus `json:"betaAcceptanceStatus"`
		} `json:"getAppInitializationData"`
	}
	if err := c.transport.DoGraphQL(ctx, "/app", betaAcceptanceGetQuery, nil, &result); err != nil {
		return nil, fmt.Errorf("GetBetaAcceptanceStatus: %w", err)
	}
	return result.GetAppInitializationData.BetaAcceptanceStatus, nil
}

// UpdateBetaAcceptanceStatus opts the organization in to the specified beta program.
// The schema does not expose an opt-out mutation; call Jamf support to remove acceptance.
func (c *Client) UpdateBetaAcceptanceStatus(ctx context.Context, betaName BetaName) ([]BetaAcceptanceStatus, error) {
	vars := map[string]any{"betaName": betaName}
	var result struct {
		UpdateBetaAcceptanceStatus struct {
			BetaAcceptanceStatus []BetaAcceptanceStatus `json:"betaAcceptanceStatus"`
		} `json:"updateBetaAcceptanceStatus"`
	}
	if err := c.transport.DoGraphQL(ctx, "/app", betaAcceptanceUpdateMutation, vars, &result); err != nil {
		return nil, fmt.Errorf("UpdateBetaAcceptanceStatus: %w", err)
	}
	return result.UpdateBetaAcceptanceStatus.BetaAcceptanceStatus, nil
}
