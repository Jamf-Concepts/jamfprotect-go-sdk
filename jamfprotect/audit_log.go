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

// MaxAuditLogDays is the maximum window size enforced by the SDK.
const MaxAuditLogDays = 2

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

// AuditLogDateRange specifies start and end dates for filtering audit logs.
// The SDK enforces a maximum window of 2 days. If the range exceeds this,
// the start date is clamped to 2 days before the end date.
type AuditLogDateRange struct {
	StartDate time.Time
	EndDate   time.Time
}

func auditLogCondition(dateRange *AuditLogDateRange) map[string]any {
	var start, end time.Time
	if dateRange != nil {
		start = dateRange.StartDate
		end = dateRange.EndDate
	} else {
		end = time.Now().UTC()
		start = end.AddDate(0, 0, -MaxAuditLogDays)
	}

	maxStart := end.AddDate(0, 0, -MaxAuditLogDays)
	if start.Before(maxStart) {
		start = maxStart
	}

	return map[string]any{
		"dateRange": map[string]any{
			"startDate": start.Format(time.RFC3339),
			"endDate":   end.Format(time.RFC3339),
		},
	}
}

// ListAuditLogsByDate retrieves audit logs within a date range.
// Pass nil for the default (last 2 days). The window is capped at 2 days;
// consumers can slide it to any period by providing a custom AuditLogDateRange.
func (c *Client) ListAuditLogsByDate(ctx context.Context, dateRange *AuditLogDateRange) ([]AuditLog, error) {
	vars := map[string]any{
		"pageSize":  100,
		"order":     map[string]any{"direction": "DESC"},
		"condition": auditLogCondition(dateRange),
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
		"pageSize":  100,
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
		"pageSize":  100,
		"order":     map[string]any{"direction": "DESC"},
		"condition": map[string]any{"beginsWith": opPrefix},
	}
	logs, err := client.ListAll[AuditLog](ctx, c.transport, "/app", listAuditLogsByOpQuery, vars, "listAuditLogsByOp")
	if err != nil {
		return nil, fmt.Errorf("ListAuditLogsByOp: %w", err)
	}
	return logs, nil
}
