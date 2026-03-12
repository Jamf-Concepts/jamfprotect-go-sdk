// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"fmt"
)

const dataRetentionGetQuery = `
query getDataRetention {
	getOrganization {
		...DataRetentionFields
	}
}

fragment DataRetentionFields on Organization {
	retention {
		database {
			log {
				numberOfDays
			}
			alert {
				numberOfDays
			}
		}
		cold {
			alert {
				numberOfDays
			}
		}
		updated
	}
}
`

const dataRetentionUpdateMutation = `
mutation updateOrganizationRetention($databaseLogDays: Int!, $databaseAlertDays: Int!, $coldAlertDays: Int!) {
	updateOrganizationRetention(
		input: {
			retention: {
				database: {
					log: {numberOfDays: $databaseLogDays}
					alert: {numberOfDays: $databaseAlertDays}
				}
				cold: {alert: {numberOfDays: $coldAlertDays}}
			}
		}
	) {
		retention {
			database {
				log { numberOfDays }
				alert { numberOfDays }
			}
			cold {
				alert { numberOfDays }
			}
			updated
		}
	}
}
`

// DataRetentionDays represents a retention days object.
type DataRetentionDays struct {
	NumberOfDays int64 `json:"numberOfDays"`
}

// DataRetentionDatabase represents database retention settings.
type DataRetentionDatabase struct {
	Log   DataRetentionDays `json:"log"`
	Alert DataRetentionDays `json:"alert"`
}

// DataRetentionCold represents cold storage retention settings.
type DataRetentionCold struct {
	Alert DataRetentionDays `json:"alert"`
}

// DataRetentionSettings represents organization retention settings.
type DataRetentionSettings struct {
	Database DataRetentionDatabase `json:"database"`
	Cold     DataRetentionCold     `json:"cold"`
	Updated  string                `json:"updated"`
}

// DataRetentionInput captures updates for retention settings.
type DataRetentionInput struct {
	DatabaseLogDays   int64
	DatabaseAlertDays int64
	ColdAlertDays     int64
}

// GetDataRetention retrieves organization retention settings.
func (c *Client) GetDataRetention(ctx context.Context) (DataRetentionSettings, error) {
	var result struct {
		GetOrganization struct {
			Retention DataRetentionSettings `json:"retention"`
		} `json:"getOrganization"`
	}
	if err := c.transport.DoGraphQL(ctx, "/app", dataRetentionGetQuery, nil, &result); err != nil {
		return DataRetentionSettings{}, fmt.Errorf("GetDataRetention: %w", err)
	}
	return result.GetOrganization.Retention, nil
}

// UpdateDataRetention updates organization retention settings.
func (c *Client) UpdateDataRetention(ctx context.Context, input DataRetentionInput) (DataRetentionSettings, error) {
	vars := map[string]any{
		"databaseLogDays":   input.DatabaseLogDays,
		"databaseAlertDays": input.DatabaseAlertDays,
		"coldAlertDays":     input.ColdAlertDays,
	}
	var result struct {
		UpdateOrganizationRetention struct {
			Retention DataRetentionSettings `json:"retention"`
		} `json:"updateOrganizationRetention"`
	}
	if err := c.transport.DoGraphQL(ctx, "/app", dataRetentionUpdateMutation, vars, &result); err != nil {
		return DataRetentionSettings{}, fmt.Errorf("UpdateDataRetention: %w", err)
	}
	return result.UpdateOrganizationRetention.Retention, nil
}
