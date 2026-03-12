// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"fmt"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/internal/client"
)

const analyticSetFields = `
fragment AnalyticSetFields on AnalyticSet {
	uuid
	name
	description
	analytics @skip(if: $excludeAnalytics) {
		uuid
		name
		jamf
	}
	plans @include(if: $RBAC_Plan) {
		id
		name
	}
	created
	updated
	managed
	types
}
`

const createAnalyticSetMutation = `
mutation createAnalyticSet(
	$name: String!,
	$description: String,
	$types: [ANALYTIC_SET_TYPE!],
	$analytics: [ID!]!,
	$RBAC_Plan: Boolean!,
	$excludeAnalytics: Boolean!
) {
	createAnalyticSet(input: {
		name: $name,
		description: $description,
		analytics: $analytics,
		types: $types
	}) {
		...AnalyticSetFields
	}
}
` + analyticSetFields

const getAnalyticSetQuery = `
query getAnalyticSet(
	$uuid: ID!,
	$RBAC_Plan: Boolean!,
	$excludeAnalytics: Boolean!
) {
	getAnalyticSet(uuid: $uuid) {
		...AnalyticSetFields
	}
}
` + analyticSetFields

const updateAnalyticSetMutation = `
mutation updateAnalyticSet(
	$uuid: ID!,
	$name: String!,
	$description: String,
	$types: [ANALYTIC_SET_TYPE!],
	$analytics: [ID!]!,
	$RBAC_Plan: Boolean!,
	$excludeAnalytics: Boolean!
) {
	updateAnalyticSet(uuid: $uuid, input: {
		name: $name,
		description: $description,
		analytics: $analytics,
		types: $types
	}) {
		...AnalyticSetFields
	}
}
` + analyticSetFields

const deleteAnalyticSetMutation = `
mutation deleteAnalyticSet($uuid: ID!) {
	deleteAnalyticSet(uuid: $uuid) {
		uuid
	}
}
`

const listAnalyticSetsQuery = `
query listAnalyticSets($nextToken: String, $direction: OrderDirection = DESC, $field: AnalyticSetOrderField = created, $RBAC_Plan: Boolean!, $excludeAnalytics: Boolean = false) {
	listAnalyticSets(
		input: {next: $nextToken, order: {direction: $direction, field: $field}, pageSize: 100}
	) {
    items {
		uuid
		name
		description
		analytics @skip(if: $excludeAnalytics) {
			uuid
			name
			jamf
		}
		plans @include(if: $RBAC_Plan) {
			id
			name
			}
		created
		updated
		managed
		types
		}
    pageInfo {
		next
		total
		}
	}
}
`

// AnalyticSetInput is the create/update input for an analytic set.
type AnalyticSetInput struct {
	Name        string
	Description string
	Types       []string
	Analytics   []string
}

// AnalyticSet represents an analytic set.
type AnalyticSet struct {
	UUID        string                `json:"uuid"`
	Name        string                `json:"name"`
	Description string                `json:"description"`
	Types       []string              `json:"types"`
	Analytics   []AnalyticSetAnalytic `json:"analytics"`
	Plans       []AnalyticSetPlan     `json:"plans"`
	Created     string                `json:"created"`
	Updated     string                `json:"updated"`
	Managed     bool                  `json:"managed"`
}

// AnalyticSetAnalytic represents an analytic entry in a set.
type AnalyticSetAnalytic struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
	Jamf bool   `json:"jamf"`
}

// AnalyticSetPlan represents a plan entry in a set.
type AnalyticSetPlan struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// CreateAnalyticSet creates a new analytic set.
func (c *Client) CreateAnalyticSet(ctx context.Context, input AnalyticSetInput) (AnalyticSet, error) {
	vars := mergeVars(map[string]any{
		"name":             input.Name,
		"description":      input.Description,
		"types":            input.Types,
		"analytics":        input.Analytics,
		"excludeAnalytics": false,
	}, rbacPlan)
	var result struct {
		CreateAnalyticSet AnalyticSet `json:"createAnalyticSet"`
	}
	if err := c.transport.DoGraphQL(ctx, "/app", createAnalyticSetMutation, vars, &result); err != nil {
		return AnalyticSet{}, fmt.Errorf("CreateAnalyticSet: %w", err)
	}
	return result.CreateAnalyticSet, nil
}

// GetAnalyticSet retrieves an analytic set by UUID.
func (c *Client) GetAnalyticSet(ctx context.Context, uuid string) (*AnalyticSet, error) {
	vars := mergeVars(map[string]any{
		"uuid":             uuid,
		"excludeAnalytics": false,
	}, rbacPlan)
	var result struct {
		GetAnalyticSet *AnalyticSet `json:"getAnalyticSet"`
	}
	if err := c.transport.DoGraphQL(ctx, "/app", getAnalyticSetQuery, vars, &result); err != nil {
		return nil, fmt.Errorf("GetAnalyticSet(%s): %w", uuid, err)
	}
	return result.GetAnalyticSet, nil
}

// UpdateAnalyticSet updates an existing analytic set.
func (c *Client) UpdateAnalyticSet(ctx context.Context, uuid string, input AnalyticSetInput) (AnalyticSet, error) {
	vars := mergeVars(map[string]any{
		"uuid":             uuid,
		"name":             input.Name,
		"description":      input.Description,
		"types":            input.Types,
		"analytics":        input.Analytics,
		"excludeAnalytics": false,
	}, rbacPlan)
	var result struct {
		UpdateAnalyticSet AnalyticSet `json:"updateAnalyticSet"`
	}
	if err := c.transport.DoGraphQL(ctx, "/graphql", updateAnalyticSetMutation, vars, &result); err != nil {
		return AnalyticSet{}, fmt.Errorf("UpdateAnalyticSet(%s): %w", uuid, err)
	}
	return result.UpdateAnalyticSet, nil
}

// DeleteAnalyticSet deletes an analytic set by UUID.
func (c *Client) DeleteAnalyticSet(ctx context.Context, uuid string) error {
	vars := map[string]any{"uuid": uuid}
	if err := c.transport.DoGraphQL(ctx, "/app", deleteAnalyticSetMutation, vars, nil); err != nil {
		return fmt.Errorf("DeleteAnalyticSet(%s): %w", uuid, err)
	}
	return nil
}

// ListAnalyticSets retrieves all analytic sets.
func (c *Client) ListAnalyticSets(ctx context.Context) ([]AnalyticSet, error) {
	items, err := client.ListAll[AnalyticSet](ctx, c.transport, "/app", listAnalyticSetsQuery, mergeVars(map[string]any{
		"excludeAnalytics": false,
	}, rbacPlan), "listAnalyticSets")
	if err != nil {
		return nil, fmt.Errorf("ListAnalyticSets: %w", err)
	}
	return items, nil
}
