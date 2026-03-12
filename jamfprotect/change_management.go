// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"fmt"
)

const changeManagementUpdateMutation = `
mutation updateOrganizationConfigFreeze($configFreeze: Boolean!) {
	updateOrganizationConfigFreeze(input: {configFreeze: $configFreeze}) {
		configFreeze
	}
}
`

const changeManagementGetQuery = `
query getConfigFreeze {
	getAppInitializationData {
		configFreeze
	}
}
`

// ChangeManagementConfig holds the config freeze setting.
type ChangeManagementConfig struct {
	ConfigFreeze bool `json:"configFreeze"`
}

// UpdateOrganizationConfigFreeze updates config freeze.
func (c *Client) UpdateOrganizationConfigFreeze(ctx context.Context, configFreeze bool) (ChangeManagementConfig, error) {
	vars := map[string]any{"configFreeze": configFreeze}
	var result struct {
		UpdateOrganizationConfigFreeze ChangeManagementConfig `json:"updateOrganizationConfigFreeze"`
	}
	if err := c.transport.DoGraphQL(ctx, "/app", changeManagementUpdateMutation, vars, &result); err != nil {
		return ChangeManagementConfig{}, fmt.Errorf("UpdateOrganizationConfigFreeze: %w", err)
	}
	return result.UpdateOrganizationConfigFreeze, nil
}

// GetConfigFreeze retrieves the current config freeze setting.
func (c *Client) GetConfigFreeze(ctx context.Context) (ChangeManagementConfig, error) {
	var result struct {
		GetAppInitializationData ChangeManagementConfig `json:"getAppInitializationData"`
	}
	if err := c.transport.DoGraphQL(ctx, "/app", changeManagementGetQuery, nil, &result); err != nil {
		return ChangeManagementConfig{}, fmt.Errorf("GetConfigFreeze: %w", err)
	}
	return result.GetAppInitializationData, nil
}
