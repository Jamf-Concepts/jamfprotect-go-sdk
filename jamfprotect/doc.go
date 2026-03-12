// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

// Package jamfprotect provides a Go client for the Jamf Protect API.
//
// Create a client with [NewClient] and use the typed methods to manage
// Jamf Protect resources such as plans, analytics, roles, and more.
//
//	c := jamfprotect.NewClient(
//		"https://your-tenant.protect.jamfcloud.com",
//		os.Getenv("JAMFPROTECT_CLIENT_ID"),
//		os.Getenv("JAMFPROTECT_CLIENT_SECRET"),
//	)
//
//	roles, err := c.ListRoles(ctx)
//
// The client handles OAuth2 authentication, token caching, retries with
// exponential backoff, and cursor-based pagination automatically.
//
// Sentinel errors [ErrAuthentication], [ErrGraphQL], and [ErrNotFound]
// can be used with [errors.Is] for error handling:
//
//	role, err := c.GetRole(ctx, id)
//	if errors.Is(err, jamfprotect.ErrNotFound) {
//		// handle missing resource
//	}
package jamfprotect
