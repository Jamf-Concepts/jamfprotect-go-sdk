// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"fmt"

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

// AuditLogDateCondition filters audit logs by date range.
type AuditLogDateCondition struct {
	DateRange *AuditLogDateRange `json:"dateRange,omitempty"`
}

// AuditLogDateRange specifies start and end dates for filtering.
type AuditLogDateRange struct {
	StartDate string `json:"startDate"`
	EndDate   string `json:"endDate"`
}

// ListAuditLogsByDate retrieves audit logs ordered by date.
// Pass nil for condition to list all logs, or provide a date range to filter.
func (c *Client) ListAuditLogsByDate(ctx context.Context, condition *AuditLogDateCondition) ([]AuditLog, error) {
	vars := map[string]any{
		"pageSize": 500,
		"order":    map[string]any{"direction": "DESC"},
	}
	if condition != nil {
		vars["condition"] = condition
	}
	logs, err := client.ListAll[AuditLog](ctx, c.transport, "/app", listAuditLogsByDateQuery, vars, "listAuditLogsByDate")
	if err != nil {
		return nil, fmt.Errorf("ListAuditLogsByDate: %w", err)
	}
	return logs, nil
}

// ListAuditLogsByUser retrieves audit logs filtered by user prefix.
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

// ListAuditLogsByOp retrieves audit logs filtered by operation prefix.
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
