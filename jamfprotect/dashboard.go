// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"fmt"
)

const getCountQuery = `
query getCount($input: CountQueryInput) {
	getCount(input: $input) {
		computers
		alerts
		alertsComputers
		insightsComputers
	}
}
`

const getComputerCountQuery = `
query getComputerCount {
	getComputerCount {
		computers
	}
}
`

const listRiskiestComputersQuery = `
query listRiskiestComputers($createdInterval: String, $limit: Int) {
	listRiskiestComputers(input: {createdInterval: $createdInterval, limit: $limit}) {
		items {
			computer {
				uuid
				hostName
				serial
			}
			alertCounts {
				severity
				count
			}
		}
	}
}
`

// CountResponse holds aggregated counts for the Jamf Protect instance.
type CountResponse struct {
	Computers         *int64 `json:"computers"`
	Alerts            *int64 `json:"alerts"`
	AlertsComputers   *int64 `json:"alertsComputers"`
	InsightsComputers *int64 `json:"insightsComputers"`
}

// RiskyComputer represents a computer ranked by alert risk.
type RiskyComputer struct {
	Computer    RiskyComputerRef      `json:"computer"`
	AlertCounts []RiskyComputerAlerts `json:"alertCounts"`
}

// RiskyComputerRef is a lightweight computer reference on a risky computer entry.
type RiskyComputerRef struct {
	UUID     string `json:"uuid"`
	HostName string `json:"hostName"`
	Serial   string `json:"serial"`
}

// RiskyComputerAlerts holds alert counts by severity for a risky computer.
type RiskyComputerAlerts struct {
	Severity string `json:"severity"`
	Count    int64  `json:"count"`
}

// GetCount returns aggregated counts of computers, alerts, and insights computers.
func (c *Client) GetCount(ctx context.Context) (CountResponse, error) {
	vars := map[string]any{
		"input": map[string]any{},
	}
	var result struct {
		GetCount CountResponse `json:"getCount"`
	}
	if err := c.transport.DoGraphQL(ctx, "/app", getCountQuery, vars, &result); err != nil {
		return CountResponse{}, fmt.Errorf("GetCount: %w", err)
	}
	return result.GetCount, nil
}

// GetComputerCount returns the total number of computers.
func (c *Client) GetComputerCount(ctx context.Context) (int64, error) {
	var result struct {
		GetComputerCount struct {
			Computers int64 `json:"computers"`
		} `json:"getComputerCount"`
	}
	if err := c.transport.DoGraphQL(ctx, "/app", getComputerCountQuery, nil, &result); err != nil {
		return 0, fmt.Errorf("GetComputerCount: %w", err)
	}
	return result.GetComputerCount.Computers, nil
}

// ListRiskiestComputers returns computers ranked by alert risk.
// Pass 0 for limit to use the API default. The createdInterval filters alerts
// by age (e.g. "7d" for 7 days, "30d" for 30 days).
func (c *Client) ListRiskiestComputers(ctx context.Context, limit int, createdInterval string) ([]RiskyComputer, error) {
	vars := map[string]any{}
	if limit > 0 {
		vars["limit"] = limit
	}
	if createdInterval != "" {
		vars["createdInterval"] = createdInterval
	}
	var result struct {
		ListRiskiestComputers struct {
			Items []RiskyComputer `json:"items"`
		} `json:"listRiskiestComputers"`
	}
	if err := c.transport.DoGraphQL(ctx, "/app", listRiskiestComputersQuery, vars, &result); err != nil {
		return nil, fmt.Errorf("ListRiskiestComputers: %w", err)
	}
	return result.ListRiskiestComputers.Items, nil
}
