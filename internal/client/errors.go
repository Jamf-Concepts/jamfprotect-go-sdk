// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package client

import "errors"

// Sentinel errors returned by the client.
var (
	ErrAuthentication = errors.New("jamfprotect: authentication failed")
	ErrGraphQL        = errors.New("jamfprotect: graphql error")
	ErrNotFound       = errors.New("jamfprotect: resource not found")
)
