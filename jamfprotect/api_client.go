// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"fmt"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/internal/client"
)

const apiClientFields = `
fragment ApiClientFields on ApiClient {
	clientId
	created
	name
	assignedRoles {
		id
		name
	}
	password
}
`

const listApiClientsQuery = `
query listApiClients($nextToken: String, $direction: OrderDirection!, $field: ApiClientOrderField!) {
	listApiClients(
		input: {next: $nextToken, order: {direction: $direction, field: $field}, pageSize: 100}
	) {
		items {
			...ApiClientFields
		}
		pageInfo {
			next
			total
		}
	}
}
` + apiClientFields

const getApiClientQuery = `
query getApiClient($clientId: ID!) {
	getApiClient(clientId: $clientId) {
		...ApiClientFields
	}
}
` + apiClientFields

const createApiClientMutation = `
mutation createApiClient($name: String!, $roleIds: [ID]) {
	createApiClient(input: {name: $name, roleIds: $roleIds}) {
		...ApiClientFields
	}
}
` + apiClientFields

const updateApiClientMutation = `
mutation updateApiClient($clientId: ID!, $name: String!, $roleIds: [ID]) {
	updateApiClient(clientId: $clientId, input: {name: $name, roleIds: $roleIds}) {
		...ApiClientFields
	}
}
` + apiClientFields

const deleteApiClientMutation = `
mutation deleteApiClient($clientId: ID!) {
	deleteApiClient(clientId: $clientId) {
		clientId
	}
}
`

// ApiClientInput is the create/update input for an API client.
type ApiClientInput struct {
	Name    string
	RoleIDs []string
}

// ApiClientRole represents a role assigned to an API client.
type ApiClientRole struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ApiClient represents an API client in Jamf Protect.
type ApiClient struct {
	ClientID      string          `json:"clientId"`
	Created       string          `json:"created"`
	Name          string          `json:"name"`
	AssignedRoles []ApiClientRole `json:"assignedRoles"`
	Password      string          `json:"password"`
}

// CreateApiClient creates a new API client.
func (c *Client) CreateApiClient(ctx context.Context, input ApiClientInput) (ApiClient, error) {
	vars := buildApiClientVariables(input)
	var result struct {
		CreateApiClient ApiClient `json:"createApiClient"`
	}
	if err := c.transport.DoGraphQL(ctx, "/app", createApiClientMutation, vars, &result); err != nil {
		return ApiClient{}, fmt.Errorf("CreateApiClient: %w", err)
	}
	return result.CreateApiClient, nil
}

// GetApiClient retrieves an API client by ID.
func (c *Client) GetApiClient(ctx context.Context, clientID string) (*ApiClient, error) {
	vars := map[string]any{"clientId": clientID}
	var result struct {
		GetApiClient *ApiClient `json:"getApiClient"`
	}
	if err := c.transport.DoGraphQL(ctx, "/app", getApiClientQuery, vars, &result); err != nil {
		return nil, fmt.Errorf("GetApiClient(%s): %w", clientID, err)
	}
	return result.GetApiClient, nil
}

// UpdateApiClient updates an existing API client.
func (c *Client) UpdateApiClient(ctx context.Context, clientID string, input ApiClientInput) (ApiClient, error) {
	vars := buildApiClientVariables(input)
	vars["clientId"] = clientID
	var result struct {
		UpdateApiClient ApiClient `json:"updateApiClient"`
	}
	if err := c.transport.DoGraphQL(ctx, "/app", updateApiClientMutation, vars, &result); err != nil {
		return ApiClient{}, fmt.Errorf("UpdateApiClient(%s): %w", clientID, err)
	}
	return result.UpdateApiClient, nil
}

// DeleteApiClient deletes an API client by ID.
func (c *Client) DeleteApiClient(ctx context.Context, clientID string) error {
	vars := map[string]any{"clientId": clientID}
	if err := c.transport.DoGraphQL(ctx, "/app", deleteApiClientMutation, vars, nil); err != nil {
		return fmt.Errorf("DeleteApiClient(%s): %w", clientID, err)
	}
	return nil
}

// ListApiClients retrieves all API clients.
func (c *Client) ListApiClients(ctx context.Context) ([]ApiClient, error) {
	clients, err := client.ListAll[ApiClient](ctx, c.transport, "/app", listApiClientsQuery, map[string]any{
		"direction": "DESC",
		"field":     "created",
	}, "listApiClients")
	if err != nil {
		return nil, fmt.Errorf("ListApiClients: %w", err)
	}
	return clients, nil
}

func buildApiClientVariables(input ApiClientInput) map[string]any {
	return map[string]any{
		"name":    input.Name,
		"roleIds": input.RoleIDs,
	}
}
