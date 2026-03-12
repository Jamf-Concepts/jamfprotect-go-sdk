// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"fmt"
)

const organizationDownloadsQuery = `
query getOrganizationDownloads {
  downloads: getOrganizationDownloads {
    pppc
    rootCA
    csr
		installerUuid
    vanillaPackage {
      version
    }
    websocket_auth
    tamperPreventionProfile
  }
}`

// OrganizationDownloads represents download payloads for Jamf Protect.
type OrganizationDownloads struct {
	PPPC                    string          `json:"pppc"`
	RootCA                  string          `json:"rootCA"`
	CSR                     string          `json:"csr"`
	InstallerUUID           string          `json:"installerUuid"`
	VanillaPackage          *VanillaPackage `json:"vanillaPackage"`
	WebsocketAuth           string          `json:"websocket_auth"`
	TamperPreventionProfile string          `json:"tamperPreventionProfile"`
}

// VanillaPackage represents the installer/uninstaller package metadata.
type VanillaPackage struct {
	Version string `json:"version"`
}

// GetOrganizationDownloads retrieves download payloads for Jamf Protect.
func (c *Client) GetOrganizationDownloads(ctx context.Context) (OrganizationDownloads, error) {
	var result struct {
		Downloads OrganizationDownloads `json:"downloads"`
	}
	if err := c.transport.DoGraphQL(ctx, "/app", organizationDownloadsQuery, nil, &result); err != nil {
		return OrganizationDownloads{}, fmt.Errorf("GetOrganizationDownloads: %w", err)
	}
	return result.Downloads, nil
}
