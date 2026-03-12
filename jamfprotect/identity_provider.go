// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"fmt"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/internal/client"
)

const connectionFields = `
fragment ConnectionFields on Connection {
	id
	name
	requireKnownUsers
	button
	created
	updated
	strategy
	groupsSupport
	source
}
`

const listConnectionsQuery = `
query listConnections($pageSize: Int, $nextToken: String, $direction: OrderDirection!, $field: ConnectionOrderField!) {
	listConnections(
		input: {next: $nextToken, pageSize: $pageSize, order: {direction: $direction, field: $field}}
	) {
		items {
			...ConnectionFields
		}
		pageInfo {
			next
			total
		}
	}
}
` + connectionFields

// Connection represents an identity provider connection in Jamf Protect.
type Connection struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	RequireKnownUsers bool   `json:"requireKnownUsers"`
	Button            string `json:"button"`
	Created           string `json:"created"`
	Updated           string `json:"updated"`
	Strategy          string `json:"strategy"`
	GroupsSupport     bool   `json:"groupsSupport"`
	Source            string `json:"source"`
}

// ListConnections retrieves all identity provider connections.
func (c *Client) ListConnections(ctx context.Context) ([]Connection, error) {
	connections, err := client.ListAll[Connection](ctx, c.transport, "/app", listConnectionsQuery, map[string]any{
		"direction": "ASC",
		"field":     "name",
	}, "listConnections")
	if err != nil {
		return nil, fmt.Errorf("ListConnections: %w", err)
	}
	return connections, nil
}
