// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
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
const MaxAuditLogDays = 7

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

// AuditLogPage holds a single page of audit log results with a cursor for the next page.
type AuditLogPage struct {
	Items []AuditLog
	Next  *string
}

func (c *Client) fetchAuditLogPage(ctx context.Context, query string, vars map[string]any, resultKey string) (AuditLogPage, error) {
	raw := make(map[string]json.RawMessage)
	if err := c.transport.DoGraphQL(ctx, "/app", query, vars, &raw); err != nil {
		return AuditLogPage{}, err
	}

	data, ok := raw[resultKey]
	if !ok {
		return AuditLogPage{}, fmt.Errorf("response missing expected key %q", resultKey)
	}

	var page struct {
		Items    []AuditLog `json:"items"`
		PageInfo struct {
			Next *string `json:"next"`
		} `json:"pageInfo"`
	}
	if err := json.Unmarshal(data, &page); err != nil {
		return AuditLogPage{}, fmt.Errorf("decoding %s: %w", resultKey, err)
	}

	return AuditLogPage{Items: page.Items, Next: page.PageInfo.Next}, nil
}

// ListAuditLogsByDate retrieves a single page of audit logs within a date range.
// Pass nil for dateRange to use the default (last 2 days). The window is capped at 2 days;
// consumers can slide it to any period by providing a custom AuditLogDateRange.
// Pass nil for nextToken on the first call, then use the returned Next cursor for subsequent pages.
func (c *Client) ListAuditLogsByDate(ctx context.Context, pageSize int, nextToken *string, dateRange *AuditLogDateRange) (AuditLogPage, error) {
	if pageSize <= 0 {
		pageSize = 100
	}
	vars := map[string]any{
		"pageSize":  pageSize,
		"order":     map[string]any{"direction": "DESC"},
		"condition": auditLogCondition(dateRange),
	}
	if nextToken != nil {
		vars["next"] = *nextToken
	}
	page, err := c.fetchAuditLogPage(ctx, listAuditLogsByDateQuery, vars, "listAuditLogsByDate")
	if err != nil {
		return AuditLogPage{}, fmt.Errorf("ListAuditLogsByDate: %w", err)
	}
	return page, nil
}

// ListAuditLogsByUser retrieves a single page of audit logs filtered by user prefix.
func (c *Client) ListAuditLogsByUser(ctx context.Context, pageSize int, nextToken *string, userPrefix string) (AuditLogPage, error) {
	if pageSize <= 0 {
		pageSize = 100
	}
	vars := map[string]any{
		"pageSize":  pageSize,
		"order":     map[string]any{"direction": "DESC"},
		"condition": map[string]any{"beginsWith": userPrefix},
	}
	if nextToken != nil {
		vars["next"] = *nextToken
	}
	page, err := c.fetchAuditLogPage(ctx, listAuditLogsByUserQuery, vars, "listAuditLogsByUser")
	if err != nil {
		return AuditLogPage{}, fmt.Errorf("ListAuditLogsByUser: %w", err)
	}
	return page, nil
}

// ListAuditLogsByOp retrieves a single page of audit logs filtered by operation prefix.
func (c *Client) ListAuditLogsByOp(ctx context.Context, pageSize int, nextToken *string, opPrefix string) (AuditLogPage, error) {
	if pageSize <= 0 {
		pageSize = 100
	}
	vars := map[string]any{
		"pageSize":  pageSize,
		"order":     map[string]any{"direction": "DESC"},
		"condition": map[string]any{"beginsWith": opPrefix},
	}
	if nextToken != nil {
		vars["next"] = *nextToken
	}
	page, err := c.fetchAuditLogPage(ctx, listAuditLogsByOpQuery, vars, "listAuditLogsByOp")
	if err != nil {
		return AuditLogPage{}, fmt.Errorf("ListAuditLogsByOp: %w", err)
	}
	return page, nil
}
