// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"testing"
)

func TestListThreatPreventionVersions(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()
		return map[string]any{
			"listThreatPreventionVersions": []map[string]any{
				{"id": "1002", "created": "2026-11-10T09:00:00Z"},
				{"id": "1001", "created": "2026-11-03T09:00:00Z"},
			},
		}
	})

	ctx := context.Background()
	versions, err := client.ListThreatPreventionVersions(ctx)
	if err != nil {
		t.Fatalf("ListThreatPreventionVersions: %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("expected 2 versions, got %d", len(versions))
	}
	if versions[0].ID != "1002" {
		t.Errorf("expected id %q, got %q", "1002", versions[0].ID)
	}
	if versions[0].Created != "2026-11-10T09:00:00Z" {
		t.Errorf("expected created %q, got %q", "2026-11-10T09:00:00Z", versions[0].Created)
	}
}

func TestListThreatPreventionVersions_Empty(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()
		return map[string]any{
			"listThreatPreventionVersions": []map[string]any{},
		}
	})

	ctx := context.Background()
	versions, err := client.ListThreatPreventionVersions(ctx)
	if err != nil {
		t.Fatalf("ListThreatPreventionVersions: %v", err)
	}
	if len(versions) != 0 {
		t.Fatalf("expected 0 versions, got %d", len(versions))
	}
}

func TestListThreatPreventionVersions_Error(t *testing.T) {
	t.Parallel()

	_, client := testServerError(t, "unauthorized")

	ctx := context.Background()
	_, err := client.ListThreatPreventionVersions(ctx)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
