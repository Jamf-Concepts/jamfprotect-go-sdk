// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"fmt"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/internal/client"
)

const listInsightsQuery = `
query listInsights {
	listInsights {
		uuid
		label
		description
		section
		totalPass
		totalFail
		totalNone
		tags
		enabled
		cisid {
			id
			osVersion
		}
	}
}
`

const updateInsightStatusMutation = `
mutation updateInsightStatus($uuid: ID!, $enabled: Boolean!) {
	updateInsightStatus(uuid: $uuid, input: {enabled: $enabled}) {
		uuid
		label
		section
		description
		totalPass
		totalFail
		totalNone
		tags
		enabled
	}
}
`

const listInsightComputersQuery = `
query listInsightComputers(
	$uuid: ID!,
	$pageSize: Int,
	$nextToken: String,
	$filter: ComputerFiltersInput
) {
	listInsightComputers(
		uuid: $uuid
		input: {next: $nextToken, pageSize: $pageSize, filter: $filter}
	) {
		items {
			uuid
			hostName
			insightsUpdated
			insightsStatsFail
			insightsStatsPass
			insightsStatsUnknown
		}
		pageInfo {
			next
			total
		}
	}
}
`

const getFleetComplianceBaselineScoreQuery = `
query getFleetComplianceBaselineScore($date: AWSDate) {
	getFleetComplianceBaselineScore(date: $date) {
		updated
		score
	}
}
`

// Insight represents a CIS benchmark insight (compliance check).
type Insight struct {
	UUID        string         `json:"uuid"`
	Label       string         `json:"label"`
	Description string         `json:"description"`
	Section     string         `json:"section"`
	TotalPass   int64          `json:"totalPass"`
	TotalFail   int64          `json:"totalFail"`
	TotalNone   int64          `json:"totalNone"`
	Tags        []string       `json:"tags"`
	Enabled     bool           `json:"enabled"`
	CisID       []InsightCisID `json:"cisid"`
}

// InsightCisID represents a CIS benchmark ID mapping for an insight.
type InsightCisID struct {
	ID        string `json:"id"`
	OSVersion string `json:"osVersion"`
}

// InsightComputer represents a computer's insight compliance status.
type InsightComputer struct {
	UUID                 string `json:"uuid"`
	HostName             string `json:"hostName"`
	InsightsUpdated      string `json:"insightsUpdated"`
	InsightsStatsFail    int64  `json:"insightsStatsFail"`
	InsightsStatsPass    int64  `json:"insightsStatsPass"`
	InsightsStatsUnknown int64  `json:"insightsStatsUnknown"`
}

// ComplianceBaselineScore represents a fleet compliance score at a point in time.
type ComplianceBaselineScore struct {
	Updated string  `json:"updated"`
	Score   float64 `json:"score"`
}

// ListInsights retrieves all insight (compliance check) definitions.
func (c *Client) ListInsights(ctx context.Context) ([]Insight, error) {
	var result struct {
		ListInsights []Insight `json:"listInsights"`
	}
	if err := c.transport.DoGraphQL(ctx, "/app", listInsightsQuery, nil, &result); err != nil {
		return nil, fmt.Errorf("ListInsights: %w", err)
	}
	return result.ListInsights, nil
}

// UpdateInsightStatus enables or disables an insight by UUID.
func (c *Client) UpdateInsightStatus(ctx context.Context, uuid string, enabled bool) (Insight, error) {
	vars := map[string]any{
		"uuid":    uuid,
		"enabled": enabled,
	}
	var result struct {
		UpdateInsightStatus Insight `json:"updateInsightStatus"`
	}
	if err := c.transport.DoGraphQL(ctx, "/app", updateInsightStatusMutation, vars, &result); err != nil {
		return Insight{}, fmt.Errorf("UpdateInsightStatus(%s): %w", uuid, err)
	}
	return result.UpdateInsightStatus, nil
}

// ListInsightComputers retrieves computers affected by a specific insight.
func (c *Client) ListInsightComputers(ctx context.Context, uuid string) ([]InsightComputer, error) {
	computers, err := client.ListAll[InsightComputer](ctx, c.transport, "/app", listInsightComputersQuery, map[string]any{
		"uuid":     uuid,
		"pageSize": 100,
	}, "listInsightComputers")
	if err != nil {
		return nil, fmt.Errorf("ListInsightComputers(%s): %w", uuid, err)
	}
	return computers, nil
}

// GetFleetComplianceScore retrieves the current fleet compliance baseline score.
// Pass an empty string for date to get today's score, or an ISO date (e.g. "2026-03-12") for a historical score.
func (c *Client) GetFleetComplianceScore(ctx context.Context, date string) (ComplianceBaselineScore, error) {
	var vars map[string]any
	if date != "" {
		vars = map[string]any{"date": date}
	}
	var result struct {
		GetFleetComplianceBaselineScore ComplianceBaselineScore `json:"getFleetComplianceBaselineScore"`
	}
	if err := c.transport.DoGraphQL(ctx, "/app", getFleetComplianceBaselineScoreQuery, vars, &result); err != nil {
		return ComplianceBaselineScore{}, fmt.Errorf("GetFleetComplianceScore: %w", err)
	}
	return result.GetFleetComplianceBaselineScore, nil
}
