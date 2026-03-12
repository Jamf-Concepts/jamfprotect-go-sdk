// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"github.com/Jamf-Concepts/jamfprotect-go-sdk/internal/client"
)

// Sentinel errors re-exported from the transport layer.
var (
	ErrAuthentication = client.ErrAuthentication
	ErrGraphQL        = client.ErrGraphQL
	ErrNotFound       = client.ErrNotFound
)
