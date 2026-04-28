// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"fmt"
)

// analyticFields defines the GraphQL fragment for analytic fields.
const analyticFields = `
fragment AnalyticFields on Analytic {
    uuid
    hash
    name
    label
    inputType
    filter
    description
    longDescription
    created
    updated
    startup
    actions
    analyticActions {
        name
        parameters
    }
    tenantActions {
        name
        parameters
    }
    tags
    level
    severity
    tenantSeverity
    snapshotFiles
    context {
        name
        type
        exprs
    }
    categories
    jamf
    remediation
    matchReason
}
`

// createAnalyticMutation defines the GraphQL mutation for creating an analytic.
const createAnalyticMutation = `
mutation createAnalytic(
    $name: String!,
    $inputType: String!,
    $description: String!,
    $actions: [String],
    $analyticActions: [AnalyticActionsInput]!,
    $tags: [String]!,
    $categories: [String]!,
    $filter: String!,
    $context: [AnalyticContextInput]!,
    $level: Int!,
    $severity: SEVERITY!,
    $snapshotFiles: [String]!,
    $label: String,
    $longDescription: String,
    $startup: Boolean,
    $remediation: String,
    $matchReason: String
) {
    createAnalytic(input: {
        name: $name,
        inputType: $inputType,
        description: $description,
        actions: $actions,
        analyticActions: $analyticActions,
        tags: $tags,
        categories: $categories,
        filter: $filter,
        context: $context,
        level: $level,
        severity: $severity,
        snapshotFiles: $snapshotFiles,
        label: $label,
        longDescription: $longDescription,
        startup: $startup,
        remediation: $remediation,
        matchReason: $matchReason
    }) {
        ...AnalyticFields
    }
}
` + analyticFields

// getAnalyticQuery defines the GraphQL query for retrieving an analytic by UUID.
const getAnalyticQuery = `
query getAnalytic($uuid: ID!) {
    getAnalytic(uuid: $uuid) {
        ...AnalyticFields
    }
}
` + analyticFields

// updateAnalyticMutation defines the GraphQL mutation for updating an existing analytic.
const updateAnalyticMutation = `
mutation updateAnalytic(
    $uuid: ID!,
    $name: String!,
    $inputType: String!,
    $description: String!,
    $actions: [String],
    $analyticActions: [AnalyticActionsInput]!,
    $tags: [String]!,
    $categories: [String]!,
    $filter: String!,
    $context: [AnalyticContextInput]!,
    $level: Int!,
    $severity: SEVERITY,
    $snapshotFiles: [String]!,
    $label: String,
    $longDescription: String,
    $startup: Boolean,
    $remediation: String,
    $matchReason: String
) {
    updateAnalytic(uuid: $uuid, input: {
        name: $name,
        inputType: $inputType,
        description: $description,
        actions: $actions,
        analyticActions: $analyticActions,
        categories: $categories,
        tags: $tags,
        filter: $filter,
        context: $context,
        level: $level,
        severity: $severity,
        snapshotFiles: $snapshotFiles,
        label: $label,
        longDescription: $longDescription,
        startup: $startup,
        remediation: $remediation,
        matchReason: $matchReason
    }) {
        ...AnalyticFields
    }
}
` + analyticFields

// updateInternalAnalyticMutation defines the GraphQL mutation for updating tenant-scoped fields on a Jamf-managed analytic.
const updateInternalAnalyticMutation = `
mutation updateInternalAnalytic(
    $uuid: ID!,
    $tenantActions: [AnalyticActionsInput],
    $tenantSeverity: SEVERITY
) {
    updateInternalAnalytic(uuid: $uuid, input: {
        tenantActions: $tenantActions,
        tenantSeverity: $tenantSeverity
    }) {
        ...AnalyticFields
    }
}
` + analyticFields

// deleteAnalyticMutation defines the GraphQL mutation for deleting an analytic by UUID.
const deleteAnalyticMutation = `
mutation deleteAnalytic($uuid: ID!) {
    deleteAnalytic(uuid: $uuid) {
        uuid
    }
}
`

// listAnalyticsQuery defines the GraphQL query for listing all analytics.
const listAnalyticsQuery = `
query listAnalytics {
    listAnalytics {
        items {
            ...AnalyticFields
        }
        pageInfo {
            next
            total
        }
    }
}
` + analyticFields

// InternalAnalyticInput is the update input for tenant-scoped fields on a Jamf-managed analytic.
type InternalAnalyticInput struct {
	TenantActions  []AnalyticActionInput
	TenantSeverity string
}

// AnalyticInput is the create/update input for an analytic.
type AnalyticInput struct {
	Name            string
	InputType       string
	Description     string
	LongDescription string
	Label           string
	Actions         []string
	AnalyticActions []AnalyticActionInput
	Tags            []string
	Categories      []string
	Filter          string
	Context         []AnalyticContextInput
	Level           int64
	Severity        string
	SnapshotFiles   []string
	Startup         *bool
	Remediation     string
	MatchReason     string
}

// AnalyticActionInput represents an analytic action input.
type AnalyticActionInput struct {
	Name       string `json:"name"`
	Parameters string `json:"parameters"`
}

// AnalyticContextInput represents a context input.
type AnalyticContextInput struct {
	Name  string   `json:"name"`
	Type  string   `json:"type"`
	Exprs []string `json:"exprs"`
}

// Analytic is the API representation of an analytic.
type Analytic struct {
	UUID            string            `json:"uuid"`
	Hash            string            `json:"hash"`
	Name            string            `json:"name"`
	Label           string            `json:"label"`
	InputType       string            `json:"inputType"`
	Filter          string            `json:"filter"`
	Description     string            `json:"description"`
	LongDescription string            `json:"longDescription"`
	Created         string            `json:"created"`
	Updated         string            `json:"updated"`
	Startup         bool              `json:"startup"`
	Actions         []string          `json:"actions"`
	AnalyticActions []AnalyticAction  `json:"analyticActions"`
	TenantActions   []AnalyticAction  `json:"tenantActions"`
	Tags            []string          `json:"tags"`
	Level           int64             `json:"level"`
	Severity        string            `json:"severity"`
	TenantSeverity  string            `json:"tenantSeverity"`
	SnapshotFiles   []string          `json:"snapshotFiles"`
	Context         []AnalyticContext `json:"context"`
	Categories      []string          `json:"categories"`
	Jamf            bool              `json:"jamf"`
	Remediation     string            `json:"remediation"`
	MatchReason     string            `json:"matchReason"`
}

// AnalyticAction represents an analytic action.
type AnalyticAction struct {
	Name       string `json:"name"`
	Parameters string `json:"parameters"`
}

// AnalyticContext represents an analytic context entry.
type AnalyticContext struct {
	Name  string   `json:"name"`
	Type  string   `json:"type"`
	Exprs []string `json:"exprs"`
}

// CreateAnalytic creates a new analytic.
func (c *Client) CreateAnalytic(ctx context.Context, input AnalyticInput) (Analytic, error) {
	vars := buildAnalyticVariables(input)
	var result struct {
		CreateAnalytic Analytic `json:"createAnalytic"`
	}
	if err := c.transport.DoGraphQL(ctx, "/app", createAnalyticMutation, vars, &result); err != nil {
		return Analytic{}, fmt.Errorf("CreateAnalytic: %w", err)
	}
	return result.CreateAnalytic, nil
}

// GetAnalytic retrieves an analytic by UUID.
func (c *Client) GetAnalytic(ctx context.Context, uuid string) (*Analytic, error) {
	vars := map[string]any{"uuid": uuid}
	var result struct {
		GetAnalytic *Analytic `json:"getAnalytic"`
	}
	if err := c.transport.DoGraphQL(ctx, "/graphql", getAnalyticQuery, vars, &result); err != nil {
		return nil, fmt.Errorf("GetAnalytic(%s): %w", uuid, err)
	}
	return result.GetAnalytic, nil
}

// UpdateAnalytic updates an existing analytic.
func (c *Client) UpdateAnalytic(ctx context.Context, uuid string, input AnalyticInput) (Analytic, error) {
	vars := buildAnalyticVariables(input)
	vars["uuid"] = uuid
	var result struct {
		UpdateAnalytic Analytic `json:"updateAnalytic"`
	}
	if err := c.transport.DoGraphQL(ctx, "/app", updateAnalyticMutation, vars, &result); err != nil {
		return Analytic{}, fmt.Errorf("UpdateAnalytic(%s): %w", uuid, err)
	}
	return result.UpdateAnalytic, nil
}

// UpdateInternalAnalytic updates tenant-scoped fields on a Jamf-managed analytic.
func (c *Client) UpdateInternalAnalytic(ctx context.Context, uuid string, input InternalAnalyticInput) (Analytic, error) {
	vars := map[string]any{"uuid": uuid}
	if input.TenantActions != nil {
		vars["tenantActions"] = input.TenantActions
	}
	if input.TenantSeverity != "" {
		vars["tenantSeverity"] = input.TenantSeverity
	}
	var result struct {
		UpdateInternalAnalytic Analytic `json:"updateInternalAnalytic"`
	}
	if err := c.transport.DoGraphQL(ctx, "/app", updateInternalAnalyticMutation, vars, &result); err != nil {
		return Analytic{}, fmt.Errorf("UpdateInternalAnalytic(%s): %w", uuid, err)
	}
	return result.UpdateInternalAnalytic, nil
}

// DeleteAnalytic deletes an analytic by UUID.
func (c *Client) DeleteAnalytic(ctx context.Context, uuid string) error {
	vars := map[string]any{"uuid": uuid}
	if err := c.transport.DoGraphQL(ctx, "/app", deleteAnalyticMutation, vars, nil); err != nil {
		return fmt.Errorf("DeleteAnalytic(%s): %w", uuid, err)
	}
	return nil
}

// ListAnalytics retrieves all analytics.
func (c *Client) ListAnalytics(ctx context.Context) ([]Analytic, error) {
	var result struct {
		ListAnalytics struct {
			Items []Analytic `json:"items"`
		} `json:"listAnalytics"`
	}
	if err := c.transport.DoGraphQL(ctx, "/graphql", listAnalyticsQuery, nil, &result); err != nil {
		return nil, fmt.Errorf("ListAnalytics: %w", err)
	}
	return result.ListAnalytics.Items, nil
}

func buildAnalyticVariables(input AnalyticInput) map[string]any {
	vars := map[string]any{
		"name":            input.Name,
		"inputType":       input.InputType,
		"description":     input.Description,
		"actions":         input.Actions,
		"analyticActions": input.AnalyticActions,
		"tags":            input.Tags,
		"categories":      input.Categories,
		"filter":          input.Filter,
		"context":         input.Context,
		"level":           input.Level,
		"severity":        input.Severity,
		"snapshotFiles":   input.SnapshotFiles,
	}

	if input.Label != "" {
		vars["label"] = input.Label
	}
	if input.LongDescription != "" {
		vars["longDescription"] = input.LongDescription
	}
	if input.Startup != nil {
		vars["startup"] = *input.Startup
	}
	if input.Remediation != "" {
		vars["remediation"] = input.Remediation
	}
	if input.MatchReason != "" {
		vars["matchReason"] = input.MatchReason
	}

	return vars
}
