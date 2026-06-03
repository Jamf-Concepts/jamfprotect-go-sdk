// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package client

import "errors"

// Sentinel errors returned by the client.
var (
	ErrAuthentication = errors.New("jamfprotect: authentication failed")
	ErrGraphQL        = errors.New("jamfprotect: graphql error")
	ErrNotFound       = errors.New("jamfprotect: resource not found")
	// ErrUnexpectedResponse indicates the server returned a non-JSON body where a
	// JSON response was expected — typically an HTML error page from an edge proxy
	// or WAF — and is distinct from a genuine JSON syntax error from the API.
	ErrUnexpectedResponse = errors.New("jamfprotect: unexpected non-JSON response")
)
