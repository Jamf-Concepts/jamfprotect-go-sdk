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

func (c *Client) fetchAllAuditLogs(ctx context.Context, query string, baseVars map[string]any, resultKey string) ([]AuditLog, error) {
	var allItems []AuditLog
	var prevCursor string

	vars := make(map[string]any, len(baseVars))
	for k, v := range baseVars {
		vars[k] = v
	}

	for {
		raw := make(map[string]json.RawMessage)
		if err := c.transport.DoGraphQL(ctx, "/app", query, vars, &raw); err != nil {
			return nil, err
		}

		data, ok := raw[resultKey]
		if !ok {
			return nil, fmt.Errorf("response missing expected key %q", resultKey)
		}

		var page struct {
			Items    []AuditLog `json:"items"`
			PageInfo struct {
				Next *string `json:"next"`
			} `json:"pageInfo"`
		}
		if err := json.Unmarshal(data, &page); err != nil {
			return nil, fmt.Errorf("decoding %s: %w", resultKey, err)
		}

		allItems = append(allItems, page.Items...)

		if page.PageInfo.Next == nil {
			break
		}
		if *page.PageInfo.Next == prevCursor {
			break
		}
		prevCursor = *page.PageInfo.Next
		vars["next"] = *page.PageInfo.Next
	}

	return allItems, nil
}

// ListAuditLogsByDate retrieves all audit logs within a date range.
// Pass nil for dateRange to use the default (last 7 days). The window is capped
// at 7 days; consumers can slide it to any period by providing a custom AuditLogDateRange.
func (c *Client) ListAuditLogsByDate(ctx context.Context, dateRange *AuditLogDateRange) ([]AuditLog, error) {
	vars := map[string]any{
		"pageSize":  500,
		"order":     map[string]any{"direction": "DESC"},
		"condition": auditLogCondition(dateRange),
	}
	logs, err := c.fetchAllAuditLogs(ctx, listAuditLogsByDateQuery, vars, "listAuditLogsByDate")
	if err != nil {
		return nil, fmt.Errorf("ListAuditLogsByDate: %w", err)
	}
	return logs, nil
}

