// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"fmt"
	"time"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/internal/client"
)

const auditLogFields = `
fragment AuditLogFields on AuditLog {
	resourceId
	date
	args
	error
	ips
	op
	user
}
`

const listAuditLogsByDateQuery = `
query listAuditLogsByDate(
	$next: String,
	$pageSize: Int,
	$order: AuditLogsOrderInput,
	$condition: AuditLogsDateConditionInput
) {
	listAuditLogsByDate(
		input: {next: $next, pageSize: $pageSize, order: $order, condition: $condition}
	) {
		items {
			...AuditLogFields
		}
		pageInfo {
			next
			total
		}
	}
}
` + auditLogFields

const listAuditLogsByUserQuery = `
query listAuditLogsByUser(
	$next: String,
	$pageSize: Int,
	$order: AuditLogsOrderInput,
	$condition: AuditLogsUserConditionInput
) {
	listAuditLogsByUser(
		input: {next: $next, pageSize: $pageSize, order: $order, condition: $condition}
	) {
		items {
			...AuditLogFields
		}
		pageInfo {
			next
			total
		}
	}
}
` + auditLogFields

const listAuditLogsByOpQuery = `
query listAuditLogsByOp(
	$next: String,
	$pageSize: Int,
	$order: AuditLogsOrderInput,
	$condition: AuditLogsOpConditionInput
) {
	listAuditLogsByOp(
		input: {next: $next, pageSize: $pageSize, order: $order, condition: $condition}
	) {
		items {
			...AuditLogFields
		}
		pageInfo {
			next
			total
		}
	}
}
` + auditLogFields

// DefaultAuditLogDays is the default number of days of audit logs to retrieve.
const DefaultAuditLogDays = 7

// AuditLog represents a single audit log entry.
type AuditLog struct {
	ResourceID string  `json:"resourceId"`
	Date       string  `json:"date"`
	Args       string  `json:"args"`
	Error      *string `json:"error"`
	IPs        string  `json:"ips"`
	Op         string  `json:"op"`
	User       string  `json:"user"`
}

// AuditLogDateRange specifies start and end dates for filtering.
type AuditLogDateRange struct {
	StartDate string `json:"startDate"`
	EndDate   string `json:"endDate"`
}

func defaultDateRange() map[string]any {
	now := time.Now().UTC()
	return map[string]any{
		"dateRange": map[string]any{
			"startDate": now.AddDate(0, 0, -DefaultAuditLogDays).Format(time.RFC3339),
			"endDate":   now.Format(time.RFC3339),
		},
	}
}

// ListAuditLogsByDate retrieves audit logs within a date range.
// Pass nil for dateRange to use the default (last 30 days).
func (c *Client) ListAuditLogsByDate(ctx context.Context, dateRange *AuditLogDateRange) ([]AuditLog, error) {
	var condition map[string]any
	if dateRange != nil {
		condition = map[string]any{
			"dateRange": map[string]any{
				"startDate": dateRange.StartDate,
				"endDate":   dateRange.EndDate,
			},
		}
	} else {
		condition = defaultDateRange()
	}
	vars := map[string]any{
		"pageSize":  500,
		"order":     map[string]any{"direction": "DESC"},
		"condition": condition,
	}
	logs, err := client.ListAll[AuditLog](ctx, c.transport, "/app", listAuditLogsByDateQuery, vars, "listAuditLogsByDate")
	if err != nil {
		return nil, fmt.Errorf("ListAuditLogsByDate: %w", err)
	}
	return logs, nil
}

// ListAuditLogsByUser retrieves audit logs filtered by user prefix (default last 30 days).
func (c *Client) ListAuditLogsByUser(ctx context.Context, userPrefix string) ([]AuditLog, error) {
	vars := map[string]any{
		"pageSize":  500,
		"order":     map[string]any{"direction": "DESC"},
		"condition": map[string]any{"beginsWith": userPrefix},
	}
	logs, err := client.ListAll[AuditLog](ctx, c.transport, "/app", listAuditLogsByUserQuery, vars, "listAuditLogsByUser")
	if err != nil {
		return nil, fmt.Errorf("ListAuditLogsByUser: %w", err)
	}
	return logs, nil
}

// ListAuditLogsByOp retrieves audit logs filtered by operation prefix (default last 30 days).
func (c *Client) ListAuditLogsByOp(ctx context.Context, opPrefix string) ([]AuditLog, error) {
	vars := map[string]any{
		"pageSize":  500,
		"order":     map[string]any{"direction": "DESC"},
		"condition": map[string]any{"beginsWith": opPrefix},
	}
	logs, err := client.ListAll[AuditLog](ctx, c.transport, "/app", listAuditLogsByOpQuery, vars, "listAuditLogsByOp")
	if err != nil {
		return nil, fmt.Errorf("ListAuditLogsByOp: %w", err)
	}
	return logs, nil
}
