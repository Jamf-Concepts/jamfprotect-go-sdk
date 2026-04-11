// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"fmt"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/internal/client"
)

const computerFields = `
fragment ComputerFields on Computer {
    uuid
    serial
    hostName
    modelName
    osMajor
    osMinor
    osPatch
    arch @skip(if: $isList)
    certid @skip(if: $isList)
    memorySize @skip(if: $isList)
    osString
    kernelVersion @skip(if: $isList)
    installType @skip(if: $isList)
    label
    created
    updated
    version
    checkin
    configHash
    tags
    signaturesVersion @include(if: $RBAC_ThreatPreventionVersion)
    plan @include(if: $RBAC_Plan) {
        id
        name
        hash
    }
    insightsStatsFail @include(if: $RBAC_Insight)
    insightsStatsPass @include(if: $RBAC_Insight)
    insightsStatsUnknown @include(if: $RBAC_Insight)
    insightsUpdated @include(if: $RBAC_Insight)
    provisioningUDID
    connectionStatus
    lastConnection
    lastConnectionIp
    lastDisconnection
    lastDisconnectionReason
    webProtectionActive
    fullDiskAccess
    pendingPlan
}
`

const listComputersQuery = `
query listComputers(
    $pageSize: Int,
    $nextToken: String,
    $direction: OrderDirection!,
    $field: [ComputerOrderField!],
    $filter: ComputerFiltersInput,
    $isList: Boolean!,
    $RBAC_ThreatPreventionVersion: Boolean!,
    $RBAC_Plan: Boolean!,
    $RBAC_Insight: Boolean!
) {
    listComputers(
        input: {
            next: $nextToken,
            order: {direction: $direction, field: $field},
            pageSize: $pageSize,
            filter: $filter
        }
    ) {
        items {
            ...ComputerFields
        }
        pageInfo {
            next
            total
        }
    }
}
` + computerFields

const getComputerQuery = `
query getComputer(
    $uuid: ID!,
    $isList: Boolean!,
    $RBAC_ThreatPreventionVersion: Boolean!,
    $RBAC_Plan: Boolean!,
    $RBAC_Insight: Boolean!
) {
    getComputer(uuid: $uuid) {
        ...ComputerFields
    }
}
` + computerFields

const deleteComputerMutation = `
mutation deleteComputer($uuid: ID!) {
    deleteComputer(uuid: $uuid) {
        uuid
    }
}
`

const setComputerPlanMutation = `
mutation setComputerPlan(
    $uuid: ID!,
    $plan: ID!,
    $isList: Boolean = false,
    $RBAC_ThreatPreventionVersion: Boolean!,
    $RBAC_Plan: Boolean!,
    $RBAC_Insight: Boolean!
) {
    setComputerPlan(uuid: $uuid, input: {plan: $plan}) {
        ...ComputerFields
    }
}
` + computerFields

const updateComputerMutation = `
mutation updateComputer(
    $uuid: ID!,
    $label: String,
    $tags: [String],
    $isList: Boolean = false,
    $RBAC_ThreatPreventionVersion: Boolean!,
    $RBAC_Plan: Boolean!,
    $RBAC_Insight: Boolean!
) {
    updateComputer(uuid: $uuid, input: {label: $label, tags: $tags}) {
        ...ComputerFields
    }
}
` + computerFields

// Computer represents a computer enrolled in Jamf Protect.
type Computer struct {
	UUID                    *string       `json:"uuid"`
	Serial                  *string       `json:"serial"`
	HostName                *string       `json:"hostName"`
	ModelName               *string       `json:"modelName"`
	OSMajor                 *int64        `json:"osMajor"`
	OSMinor                 *int64        `json:"osMinor"`
	OSPatch                 *int64        `json:"osPatch"`
	Arch                    *string       `json:"arch"`
	CertID                  *string       `json:"certid"`
	MemorySize              *float64      `json:"memorySize"`
	OSString                *string       `json:"osString"`
	KernelVersion           *string       `json:"kernelVersion"`
	InstallType             *string       `json:"installType"`
	Label                   *string       `json:"label"`
	Created                 *string       `json:"created"`
	Updated                 *string       `json:"updated"`
	Version                 *string       `json:"version"`
	Checkin                 *string       `json:"checkin"`
	ConfigHash              *string       `json:"configHash"`
	Tags                    *[]string     `json:"tags"`
	SignaturesVersion       *int64        `json:"signaturesVersion"`
	Plan                    *ComputerPlan `json:"plan"`
	InsightsStatsFail       *int64        `json:"insightsStatsFail"`
	InsightsStatsPass       *int64        `json:"insightsStatsPass"`
	InsightsStatsUnknown    *int64        `json:"insightsStatsUnknown"`
	InsightsUpdated         *string       `json:"insightsUpdated"`
	ProvisioningUDID        *string       `json:"provisioningUDID"`
	ConnectionStatus        *string       `json:"connectionStatus"`
	LastConnection          *string       `json:"lastConnection"`
	LastConnectionIP        *string       `json:"lastConnectionIp"`
	LastDisconnection       *string       `json:"lastDisconnection"`
	LastDisconnectionReason *string       `json:"lastDisconnectionReason"`
	WebProtectionActive     *bool         `json:"webProtectionActive"`
	FullDiskAccess          *string       `json:"fullDiskAccess"`
	PendingPlan             *int64        `json:"pendingPlan"`
}

// ComputerPlan represents a plan assigned to a computer.
type ComputerPlan struct {
	ID   *string `json:"id"`
	Name *string `json:"name"`
	Hash *string `json:"hash"`
}

// ComputerUpdateInput is the update input for a computer.
type ComputerUpdateInput struct {
	Label *string
	Tags  []string
}

// ListComputers retrieves all computers from Jamf Protect.
func (c *Client) ListComputers(ctx context.Context) ([]Computer, error) {
	computers, err := client.ListAll[Computer](ctx, c.transport, "/app", listComputersQuery, mergeVars(map[string]any{
		"isList":    true,
		"pageSize":  100,
		"direction": "ASC",
		"field":     []any{"hostName"},
		"filter":    nil,
	}, rbacComputer), "listComputers")
	if err != nil {
		return nil, fmt.Errorf("ListComputers: %w", err)
	}
	return computers, nil
}

// GetComputer retrieves a single computer by UUID from Jamf Protect.
func (c *Client) GetComputer(ctx context.Context, uuid string) (*Computer, error) {
	variables := mergeVars(map[string]any{
		"uuid":   uuid,
		"isList": false,
	}, rbacComputer)

	var resp struct {
		GetComputer *Computer `json:"getComputer"`
	}
	if err := c.transport.DoGraphQL(ctx, "/app", getComputerQuery, variables, &resp); err != nil {
		return nil, fmt.Errorf("GetComputer(%s): %w", uuid, err)
	}
	return resp.GetComputer, nil
}

// DeleteComputer deletes a computer by UUID.
func (c *Client) DeleteComputer(ctx context.Context, uuid string) error {
	vars := map[string]any{"uuid": uuid}
	if err := c.transport.DoGraphQL(ctx, "/app", deleteComputerMutation, vars, nil); err != nil {
		return fmt.Errorf("DeleteComputer(%s): %w", uuid, err)
	}
	return nil
}

// SetComputerPlan assigns a plan to a computer.
func (c *Client) SetComputerPlan(ctx context.Context, uuid string, planID string) (*Computer, error) {
	vars := mergeVars(map[string]any{
		"uuid": uuid,
		"plan": planID,
	}, rbacComputer)

	var resp struct {
		SetComputerPlan *Computer `json:"setComputerPlan"`
	}
	if err := c.transport.DoGraphQL(ctx, "/app", setComputerPlanMutation, vars, &resp); err != nil {
		return nil, fmt.Errorf("SetComputerPlan(%s): %w", uuid, err)
	}
	return resp.SetComputerPlan, nil
}

// UpdateComputer updates a computer's label and tags.
func (c *Client) UpdateComputer(ctx context.Context, uuid string, input ComputerUpdateInput) (*Computer, error) {
	vars := mergeVars(map[string]any{
		"uuid": uuid,
	}, rbacComputer)

	if input.Label != nil {
		vars["label"] = *input.Label
	}
	if input.Tags != nil {
		vars["tags"] = input.Tags
	}

	var resp struct {
		UpdateComputer *Computer `json:"updateComputer"`
	}
	if err := c.transport.DoGraphQL(ctx, "/app", updateComputerMutation, vars, &resp); err != nil {
		return nil, fmt.Errorf("UpdateComputer(%s): %w", uuid, err)
	}
	return resp.UpdateComputer, nil
}
