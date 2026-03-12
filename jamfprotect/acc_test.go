// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"fmt"
	"os"
	"testing"
	"time"
)

// accClient returns a configured Client for acceptance tests, or skips the test
// if the required environment variables are not set.
func accClient(t *testing.T) *Client {
	t.Helper()

	if os.Getenv("JAMFPROTECT_ACC") == "" {
		t.Skip("set JAMFPROTECT_ACC=1 to run acceptance tests")
	}

	baseURL := os.Getenv("JAMFPROTECT_BASE_URL")
	clientID := os.Getenv("JAMFPROTECT_CLIENT_ID")
	clientSecret := os.Getenv("JAMFPROTECT_CLIENT_SECRET")

	if baseURL == "" || clientID == "" || clientSecret == "" {
		t.Fatal("JAMFPROTECT_BASE_URL, JAMFPROTECT_CLIENT_ID, and JAMFPROTECT_CLIENT_SECRET must be set")
	}

	return NewClient(baseURL, clientID, clientSecret,
		WithUserAgent("jamfprotect-go-sdk/acc-test"),
	)
}

// accName returns a unique name for a test resource.
func accName(prefix string) string {
	return fmt.Sprintf("acc-%s-%d", prefix, time.Now().UnixNano())
}
