// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"fmt"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/internal/client"
)

const alertFields = `
fragment AlertFields on Alert {
	uuid
	created
	updated
	received
	eventTimestamp
	status
	severity
	actions
	tags
	eventType
	plan {
		uuid
		name
	}
	computer {
		uuid
		hostName
		modelName
		plan {
			id
			name
		}
	}
	analytics {
		name
		label
		description
		uuid
	}
	facts {
		name
		tags
		human
		severity
		matchReason
		actions {
			name
		}
	}
}
`

const getAlertQuery = `
query getAlert($uuid: ID!) {
	getAlert(uuid: $uuid) {
		...AlertFields
	}
}
` + alertFields

const listAlertsQuery = `
query listAlerts(
	$nextToken: String,
	$pageSize: Int = 100,
	$field: AlertOrderField!,
	$direction: OrderDirection!,
	$filter: AlertFiltersInput
) {
	listAlerts(
		input: {next: $nextToken, pageSize: $pageSize, filter: $filter, order: {direction: $direction, field: $field}}
	) {
		items {
			...AlertFields
		}
		pageInfo {
			next
			total
		}
	}
}
` + alertFields

const getAlertStatusCountsQuery = `
query getAlertStatusCounts {
	getAlertStatusCounts {
		New
		InProgress
		Resolved
		AutoResolved
	}
}
`

const updateAlertsMutation = `
mutation updateAlerts($uuids: [ID!]!, $status: ALERT_STATUS!) {
	updateAlerts(input: {uuids: $uuids, status: $status}) {
		items {
			...AlertFields
		}
	}
}
` + alertFields

// Alert represents a security alert in Jamf Protect.
type Alert struct {
	UUID           string          `json:"uuid"`
	Created        string          `json:"created"`
	Updated        string          `json:"updated"`
	Received       string          `json:"received"`
	EventTimestamp string          `json:"eventTimestamp"`
	Status         string          `json:"status"`
	Severity       string          `json:"severity"`
	Actions        []string        `json:"actions"`
	Tags           []string        `json:"tags"`
	EventType      string          `json:"eventType"`
	Plan           *AlertPlan      `json:"plan"`
	Computer       *AlertComputer  `json:"computer"`
	Analytics      []AlertAnalytic `json:"analytics"`
	Facts          []AlertFact     `json:"facts"`
}

// AlertPlan represents a plan reference on an alert.
type AlertPlan struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

// AlertComputer represents a computer reference on an alert.
type AlertComputer struct {
	UUID      string             `json:"uuid"`
	HostName  string             `json:"hostName"`
	ModelName string             `json:"modelName"`
	Plan      *AlertComputerPlan `json:"plan"`
}

// AlertComputerPlan represents the plan assigned to the computer on an alert.
type AlertComputerPlan struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// AlertAnalytic represents an analytic that triggered an alert.
type AlertAnalytic struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Description string `json:"description"`
	UUID        string `json:"uuid"`
}

// AlertFact represents a fact from an alert.
type AlertFact struct {
	Name        string        `json:"name"`
	Tags        []string      `json:"tags"`
	Human       string        `json:"human"`
	Severity    string        `json:"severity"`
	MatchReason string        `json:"matchReason"`
	Actions     []AlertAction `json:"actions"`
}

// AlertAction represents an action on an alert fact.
type AlertAction struct {
	Name string `json:"name"`
}

// AlertStatusCounts holds the count of alerts per status.
type AlertStatusCounts struct {
	New          int64 `json:"New"`
	InProgress   int64 `json:"InProgress"`
	Resolved     int64 `json:"Resolved"`
	AutoResolved int64 `json:"AutoResolved"`
}

// AlertUpdateInput is the input for bulk-updating alert statuses.
type AlertUpdateInput struct {
	UUIDs  []string
	Status string
}

// GetAlert retrieves a single alert by UUID.
func (c *Client) GetAlert(ctx context.Context, uuid string) (*Alert, error) {
	vars := map[string]any{"uuid": uuid}
	var result struct {
		GetAlert *Alert `json:"getAlert"`
	}
	if err := c.transport.DoGraphQL(ctx, "/app", getAlertQuery, vars, &result); err != nil {
		return nil, fmt.Errorf("GetAlert(%s): %w", uuid, err)
	}
	return result.GetAlert, nil
}

// ListAlerts retrieves all alerts ordered by creation date descending.
func (c *Client) ListAlerts(ctx context.Context) ([]Alert, error) {
	alerts, err := client.ListAll[Alert](ctx, c.transport, "/app", listAlertsQuery, map[string]any{
		"direction": "DESC",
		"field":     "created",
	}, "listAlerts")
	if err != nil {
		return nil, fmt.Errorf("ListAlerts: %w", err)
	}
	return alerts, nil
}

// GetAlertStatusCounts returns the count of alerts grouped by status.
func (c *Client) GetAlertStatusCounts(ctx context.Context) (AlertStatusCounts, error) {
	var result struct {
		GetAlertStatusCounts AlertStatusCounts `json:"getAlertStatusCounts"`
	}
	if err := c.transport.DoGraphQL(ctx, "/app", getAlertStatusCountsQuery, nil, &result); err != nil {
		return AlertStatusCounts{}, fmt.Errorf("GetAlertStatusCounts: %w", err)
	}
	return result.GetAlertStatusCounts, nil
}

// UpdateAlerts bulk-updates the status of one or more alerts.
func (c *Client) UpdateAlerts(ctx context.Context, input AlertUpdateInput) ([]Alert, error) {
	vars := map[string]any{
		"uuids":  input.UUIDs,
		"status": input.Status,
	}
	var result struct {
		UpdateAlerts struct {
			Items []Alert `json:"items"`
		} `json:"updateAlerts"`
	}
	if err := c.transport.DoGraphQL(ctx, "/app", updateAlertsMutation, vars, &result); err != nil {
		return nil, fmt.Errorf("UpdateAlerts: %w", err)
	}
	return result.UpdateAlerts.Items, nil
}
