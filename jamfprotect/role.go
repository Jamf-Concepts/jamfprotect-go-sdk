// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"fmt"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/internal/client"
)

const roleFields = `
fragment RoleFields on Role {
	id
	name
	permissions {
		R
		W
	}
	created
	updated
}
`

const listRolesQuery = `
query listRoles($pageSize: Int, $nextToken: String, $direction: OrderDirection!, $field: RoleOrderField!) {
	listRoles(
		input: {next: $nextToken, pageSize: $pageSize, order: {direction: $direction, field: $field}}
	) {
		items {
			...RoleFields
		}
		pageInfo {
			next
			total
		}
	}
}
` + roleFields

const getRoleQuery = `
query getRole($id: ID!) {
	getRole(id: $id) {
		...RoleFields
	}
}
` + roleFields

const createRoleMutation = `
mutation createRole($name: String!, $readResources: [RBAC_RESOURCE!]!, $writeResources: [RBAC_RESOURCE!]!) {
	createRole(
		input: {name: $name, readResources: $readResources, writeResources: $writeResources}
	) {
		...RoleFields
	}
}
` + roleFields

const updateRoleMutation = `
mutation updateRole($id: ID!, $name: String!, $readResources: [RBAC_RESOURCE!]!, $writeResources: [RBAC_RESOURCE!]!) {
	updateRole(
		id: $id
		input: {name: $name, readResources: $readResources, writeResources: $writeResources}
	) {
		...RoleFields
	}
}
` + roleFields

const deleteRoleMutation = `
mutation deleteRole($id: ID!) {
	deleteRole(id: $id) {
		...RoleFields
	}
}
` + roleFields

// RoleInput is the create/update input for a role.
type RoleInput struct {
	Name           string
	ReadResources  []string
	WriteResources []string
}

// RolePermissions represents role permissions.
type RolePermissions struct {
	Read  []string `json:"R"`
	Write []string `json:"W"`
}

// Role represents a Jamf Protect role.
type Role struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Permissions RolePermissions `json:"permissions"`
	Created     string          `json:"created"`
	Updated     string          `json:"updated"`
}

// CreateRole creates a new role.
func (c *Client) CreateRole(ctx context.Context, input RoleInput) (Role, error) {
	vars := buildRoleVariables(input)
	var result struct {
		CreateRole Role `json:"createRole"`
	}
	if err := c.transport.DoGraphQL(ctx, "/app", createRoleMutation, vars, &result); err != nil {
		return Role{}, fmt.Errorf("CreateRole: %w", err)
	}
	return result.CreateRole, nil
}

// GetRole retrieves a role by ID.
func (c *Client) GetRole(ctx context.Context, id string) (*Role, error) {
	vars := map[string]any{"id": id}
	var result struct {
		GetRole *Role `json:"getRole"`
	}
	if err := c.transport.DoGraphQL(ctx, "/app", getRoleQuery, vars, &result); err != nil {
		return nil, fmt.Errorf("GetRole(%s): %w", id, err)
	}
	return result.GetRole, nil
}

// UpdateRole updates an existing role.
func (c *Client) UpdateRole(ctx context.Context, id string, input RoleInput) (Role, error) {
	vars := buildRoleVariables(input)
	vars["id"] = id
	var result struct {
		UpdateRole Role `json:"updateRole"`
	}
	if err := c.transport.DoGraphQL(ctx, "/app", updateRoleMutation, vars, &result); err != nil {
		return Role{}, fmt.Errorf("UpdateRole(%s): %w", id, err)
	}
	return result.UpdateRole, nil
}

// DeleteRole deletes a role by ID.
func (c *Client) DeleteRole(ctx context.Context, id string) error {
	vars := map[string]any{"id": id}
	if err := c.transport.DoGraphQL(ctx, "/app", deleteRoleMutation, vars, nil); err != nil {
		return fmt.Errorf("DeleteRole(%s): %w", id, err)
	}
	return nil
}

// ListRoles retrieves all roles.
func (c *Client) ListRoles(ctx context.Context) ([]Role, error) {
	roles, err := client.ListAll[Role](ctx, c.transport, "/app", listRolesQuery, map[string]any{
		"pageSize":  100,
		"direction": "ASC",
		"field":     "name",
	}, "listRoles")
	if err != nil {
		return nil, fmt.Errorf("ListRoles: %w", err)
	}
	return roles, nil
}

func buildRoleVariables(input RoleInput) map[string]any {
	return map[string]any{
		"name":           input.Name,
		"readResources":  input.ReadResources,
		"writeResources": input.WriteResources,
	}
}
