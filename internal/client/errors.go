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
	// ErrResponseTooLarge indicates a response body exceeded the client's size
	// limit and was not read in full.
	ErrResponseTooLarge = errors.New("jamfprotect: response body too large")
	// ErrPaginationLimit indicates a paginated list was abandoned because the
	// server repeated a cursor or the page limit was reached.
	ErrPaginationLimit = errors.New("jamfprotect: pagination limit exceeded")
)
