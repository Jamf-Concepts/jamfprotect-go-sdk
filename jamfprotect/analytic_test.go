// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"strings"
	"testing"
)

func basicAnalyticPayload(uuid string) map[string]any {
	return map[string]any{
		"uuid":            uuid,
		"hash":            "h1",
		"name":            "TestAnalytic",
		"label":           "Test Label",
		"inputType":       "GPProcessEvent",
		"filter":          `$event.cmd == "evil"`,
		"description":     "desc",
		"longDescription": "long desc",
		"created":         "2026-01-01T00:00:00Z",
		"updated":         "2026-04-28T00:00:00Z",
		"startup":         false,
		"actions":         nil,
		"analyticActions": []map[string]any{
			{"name": "Log", "parameters": "{}"},
		},
		"tenantActions":  nil,
		"tags":           []string{"alpha"},
		"level":          1,
		"severity":       "Medium",
		"tenantSeverity": nil,
		"snapshotFiles":  []string{},
		"context":        []map[string]any{},
		"categories":     []string{"Execution"},
		"jamf":           false,
		"remediation":    "do something",
		"matchReason":    "",
	}
}

func TestCreateAnalytic(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()

		if !strings.Contains(req.Query, "createAnalytic") {
			t.Errorf("expected createAnalytic mutation, got: %s", req.Query)
		}
		if req.Variables["name"] != "TestAnalytic" {
			t.Errorf("expected name TestAnalytic, got %v", req.Variables["name"])
		}
		if req.Variables["inputType"] != "GPProcessEvent" {
			t.Errorf("expected inputType GPProcessEvent, got %v", req.Variables["inputType"])
		}
		if req.Variables["severity"] != "Medium" {
			t.Errorf("expected severity Medium, got %v", req.Variables["severity"])
		}

		return map[string]any{"createAnalytic": basicAnalyticPayload("new-uuid")}
	})

	got, err := client.CreateAnalytic(context.Background(), AnalyticInput{
		Name:            "TestAnalytic",
		InputType:       "GPProcessEvent",
		Description:     "desc",
		AnalyticActions: []AnalyticActionInput{{Name: "Log", Parameters: "{}"}},
		Tags:            []string{"alpha"},
		Categories:      []string{"Execution"},
		Filter:          `$event.cmd == "evil"`,
		Context:         []AnalyticContextInput{},
		Level:           1,
		Severity:        "Medium",
		SnapshotFiles:   []string{},
	})
	if err != nil {
		t.Fatalf("CreateAnalytic: %v", err)
	}
	if got.UUID != "new-uuid" {
		t.Errorf("expected UUID new-uuid, got %q", got.UUID)
	}
	if got.Name != "TestAnalytic" {
		t.Errorf("expected name TestAnalytic, got %q", got.Name)
	}
	if got.Jamf {
		t.Error("expected Jamf=false for newly-created custom analytic")
	}
}

func TestCreateAnalytic_OptionalFieldsOmitted(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()

		// Optional fields only included when set.
		for _, key := range []string{"label", "longDescription", "startup", "remediation", "matchReason"} {
			if _, present := req.Variables[key]; present {
				t.Errorf("expected variable %q to be omitted, but it was present: %v", key, req.Variables[key])
			}
		}

		return map[string]any{"createAnalytic": basicAnalyticPayload("u1")}
	})

	_, err := client.CreateAnalytic(context.Background(), AnalyticInput{
		Name:            "x",
		InputType:       "GPFSEvent",
		AnalyticActions: []AnalyticActionInput{},
		Tags:            []string{},
		Categories:      []string{},
		Filter:          "",
		Context:         []AnalyticContextInput{},
		Severity:        "Low",
		SnapshotFiles:   []string{},
	})
	if err != nil {
		t.Fatalf("CreateAnalytic: %v", err)
	}
}

func TestCreateAnalytic_OptionalFieldsIncluded(t *testing.T) {
	t.Parallel()

	startup := true
	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()

		if req.Variables["label"] != "Test Label" {
			t.Errorf("expected label, got %v", req.Variables["label"])
		}
		if req.Variables["longDescription"] != "Long description" {
			t.Errorf("expected longDescription, got %v", req.Variables["longDescription"])
		}
		if req.Variables["startup"] != true {
			t.Errorf("expected startup=true, got %v", req.Variables["startup"])
		}
		if req.Variables["remediation"] != "Remediate this" {
			t.Errorf("expected remediation, got %v", req.Variables["remediation"])
		}
		if req.Variables["matchReason"] != "match" {
			t.Errorf("expected matchReason, got %v", req.Variables["matchReason"])
		}

		return map[string]any{"createAnalytic": basicAnalyticPayload("u1")}
	})

	_, err := client.CreateAnalytic(context.Background(), AnalyticInput{
		Name:            "x",
		InputType:       "GPFSEvent",
		Label:           "Test Label",
		LongDescription: "Long description",
		Startup:         &startup,
		Remediation:     "Remediate this",
		MatchReason:     "match",
		AnalyticActions: []AnalyticActionInput{},
		Tags:            []string{},
		Categories:      []string{},
		Filter:          "",
		Context:         []AnalyticContextInput{},
		Severity:        "Low",
		SnapshotFiles:   []string{},
	})
	if err != nil {
		t.Fatalf("CreateAnalytic: %v", err)
	}
}

func TestGetAnalytic(t *testing.T) {
	t.Parallel()

	uuid := "e59e0cdc-eea2-11e9-ba08-a683e73a7372"

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()

		if req.Variables["uuid"] != uuid {
			t.Errorf("expected uuid %q, got %v", uuid, req.Variables["uuid"])
		}
		if !strings.Contains(req.Query, "getAnalytic") {
			t.Errorf("expected getAnalytic query, got: %s", req.Query)
		}

		payload := basicAnalyticPayload(uuid)
		payload["jamf"] = true
		payload["name"] = "AppleJeusMalware"
		payload["tenantActions"] = nil
		payload["tenantSeverity"] = nil
		return map[string]any{"getAnalytic": payload}
	})

	got, err := client.GetAnalytic(context.Background(), uuid)
	if err != nil {
		t.Fatalf("GetAnalytic: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil result")
	}
	if got.UUID != uuid {
		t.Errorf("expected UUID %q, got %q", uuid, got.UUID)
	}
	if got.Name != "AppleJeusMalware" {
		t.Errorf("expected name AppleJeusMalware, got %q", got.Name)
	}
	if !got.Jamf {
		t.Error("expected Jamf=true")
	}
	if got.TenantSeverity != "" {
		t.Errorf("expected empty TenantSeverity, got %q", got.TenantSeverity)
	}
	if got.TenantActions != nil {
		t.Errorf("expected nil TenantActions, got %v", got.TenantActions)
	}
}

func TestGetAnalytic_NotFound(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()
		return map[string]any{"getAnalytic": nil}
	})

	got, err := client.GetAnalytic(context.Background(), "missing")
	if err != nil {
		t.Fatalf("GetAnalytic: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil result, got %v", got)
	}
}

func TestUpdateAnalytic(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()

		if !strings.Contains(req.Query, "updateAnalytic") {
			t.Errorf("expected updateAnalytic mutation, got: %s", req.Query)
		}
		if req.Variables["uuid"] != "u1" {
			t.Errorf("expected uuid u1, got %v", req.Variables["uuid"])
		}
		if req.Variables["name"] != "renamed" {
			t.Errorf("expected name renamed, got %v", req.Variables["name"])
		}

		payload := basicAnalyticPayload("u1")
		payload["name"] = "renamed"
		return map[string]any{"updateAnalytic": payload}
	})

	got, err := client.UpdateAnalytic(context.Background(), "u1", AnalyticInput{
		Name:            "renamed",
		InputType:       "GPProcessEvent",
		Description:     "d",
		AnalyticActions: []AnalyticActionInput{},
		Tags:            []string{},
		Categories:      []string{},
		Filter:          "",
		Context:         []AnalyticContextInput{},
		Level:           1,
		Severity:        "Medium",
		SnapshotFiles:   []string{},
	})
	if err != nil {
		t.Fatalf("UpdateAnalytic: %v", err)
	}
	if got.Name != "renamed" {
		t.Errorf("expected name renamed, got %q", got.Name)
	}
}

// TestUpdateInternalAnalytic verifies the tenant-scoped mutation: only tenant_actions and
// tenant_severity are sent, and uuid is the only other variable.
func TestUpdateInternalAnalytic(t *testing.T) {
	t.Parallel()

	uuid := "e59e0cdc-eea2-11e9-ba08-a683e73a7372"

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()

		if !strings.Contains(req.Query, "updateInternalAnalytic") {
			t.Errorf("expected updateInternalAnalytic mutation, got: %s", req.Query)
		}

		// Verify mutation surface area: only uuid, tenantActions, tenantSeverity.
		allowed := map[string]bool{"uuid": true, "tenantActions": true, "tenantSeverity": true}
		for k := range req.Variables {
			if !allowed[k] {
				t.Errorf("unexpected variable %q sent to updateInternalAnalytic", k)
			}
		}

		if req.Variables["uuid"] != uuid {
			t.Errorf("expected uuid %q, got %v", uuid, req.Variables["uuid"])
		}
		if req.Variables["tenantSeverity"] != "Low" {
			t.Errorf("expected tenantSeverity Low, got %v", req.Variables["tenantSeverity"])
		}

		actions, ok := req.Variables["tenantActions"].([]any)
		if !ok {
			t.Fatalf("tenantActions: expected []any, got %T", req.Variables["tenantActions"])
		}
		if len(actions) != 2 {
			t.Fatalf("expected 2 tenant actions, got %d", len(actions))
		}

		first := actions[0].(map[string]any)
		if first["Name"] != "Report" && first["name"] != "Report" {
			t.Errorf("expected first action name Report, got %v", first)
		}

		payload := basicAnalyticPayload(uuid)
		payload["jamf"] = true
		payload["tenantActions"] = []map[string]any{
			{"name": "Report", "parameters": "{}"},
			{"name": "SmartGroup", "parameters": `{"id":"yes"}`},
		}
		payload["tenantSeverity"] = "Low"
		return map[string]any{"updateInternalAnalytic": payload}
	})

	got, err := client.UpdateInternalAnalytic(context.Background(), uuid, InternalAnalyticInput{
		TenantActions: []AnalyticActionInput{
			{Name: "Report", Parameters: "{}"},
			{Name: "SmartGroup", Parameters: `{"id":"yes"}`},
		},
		TenantSeverity: "Low",
	})
	if err != nil {
		t.Fatalf("UpdateInternalAnalytic: %v", err)
	}
	if got.TenantSeverity != "Low" {
		t.Errorf("expected tenantSeverity Low, got %q", got.TenantSeverity)
	}
	if len(got.TenantActions) != 2 {
		t.Errorf("expected 2 tenant actions, got %d", len(got.TenantActions))
	}
	if !got.Jamf {
		t.Error("expected Jamf=true")
	}
}

// TestUpdateInternalAnalytic_OnlySeverity confirms tenantActions is omitted from variables when nil.
func TestUpdateInternalAnalytic_OnlySeverity(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()

		if _, ok := req.Variables["tenantActions"]; ok {
			t.Errorf("tenantActions should be omitted when nil; got %v", req.Variables["tenantActions"])
		}
		if req.Variables["tenantSeverity"] != "High" {
			t.Errorf("expected tenantSeverity High, got %v", req.Variables["tenantSeverity"])
		}

		payload := basicAnalyticPayload("u1")
		payload["jamf"] = true
		payload["tenantSeverity"] = "High"
		return map[string]any{"updateInternalAnalytic": payload}
	})

	_, err := client.UpdateInternalAnalytic(context.Background(), "u1", InternalAnalyticInput{
		TenantSeverity: "High",
	})
	if err != nil {
		t.Fatalf("UpdateInternalAnalytic: %v", err)
	}
}

// TestUpdateInternalAnalytic_OnlyActions confirms tenantSeverity is omitted from variables when empty.
func TestUpdateInternalAnalytic_OnlyActions(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()

		if _, ok := req.Variables["tenantSeverity"]; ok {
			t.Errorf("tenantSeverity should be omitted when empty; got %v", req.Variables["tenantSeverity"])
		}
		if _, ok := req.Variables["tenantActions"]; !ok {
			t.Error("tenantActions should be present")
		}

		payload := basicAnalyticPayload("u1")
		payload["jamf"] = true
		return map[string]any{"updateInternalAnalytic": payload}
	})

	_, err := client.UpdateInternalAnalytic(context.Background(), "u1", InternalAnalyticInput{
		TenantActions: []AnalyticActionInput{
			{Name: "Log", Parameters: "{}"},
		},
	})
	if err != nil {
		t.Fatalf("UpdateInternalAnalytic: %v", err)
	}
}

func TestUpdateInternalAnalytic_Error(t *testing.T) {
	t.Parallel()

	_, client := testServerError(t, "permission denied")

	_, err := client.UpdateInternalAnalytic(context.Background(), "u1", InternalAnalyticInput{
		TenantSeverity: "High",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "UpdateInternalAnalytic(u1)") {
		t.Errorf("expected error to wrap with UpdateInternalAnalytic(u1), got %v", err)
	}
}

func TestDeleteAnalytic(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()

		if !strings.Contains(req.Query, "deleteAnalytic") {
			t.Errorf("expected deleteAnalytic mutation, got: %s", req.Query)
		}
		if req.Variables["uuid"] != "u1" {
			t.Errorf("expected uuid u1, got %v", req.Variables["uuid"])
		}

		return map[string]any{"deleteAnalytic": map[string]any{"uuid": "u1"}}
	})

	if err := client.DeleteAnalytic(context.Background(), "u1"); err != nil {
		t.Fatalf("DeleteAnalytic: %v", err)
	}
}

func TestListAnalytics(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()

		if !strings.Contains(req.Query, "listAnalytics") {
			t.Errorf("expected listAnalytics query, got: %s", req.Query)
		}

		return map[string]any{
			"listAnalytics": map[string]any{
				"items": []map[string]any{
					basicAnalyticPayload("u1"),
					func() map[string]any {
						p := basicAnalyticPayload("u2")
						p["jamf"] = true
						p["name"] = "JamfManaged"
						return p
					}(),
				},
				"pageInfo": map[string]any{"next": nil, "total": 2},
			},
		}
	})

	got, err := client.ListAnalytics(context.Background())
	if err != nil {
		t.Fatalf("ListAnalytics: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 analytics, got %d", len(got))
	}
	if got[0].Jamf {
		t.Error("expected first analytic Jamf=false")
	}
	if !got[1].Jamf {
		t.Error("expected second analytic Jamf=true")
	}
}

func TestListAnalytics_Empty(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()
		return map[string]any{
			"listAnalytics": map[string]any{
				"items":    []map[string]any{},
				"pageInfo": map[string]any{"next": nil, "total": 0},
			},
		}
	})

	got, err := client.ListAnalytics(context.Background())
	if err != nil {
		t.Fatalf("ListAnalytics: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 analytics, got %d", len(got))
	}
}

func TestBuildAnalyticVariables_RequiredFieldsOnly(t *testing.T) {
	t.Parallel()

	startup := false
	input := AnalyticInput{
		Name:            "n",
		InputType:       "GPFSEvent",
		Description:     "",
		AnalyticActions: []AnalyticActionInput{},
		Tags:            []string{},
		Categories:      []string{},
		Filter:          "",
		Context:         []AnalyticContextInput{},
		Level:           0,
		Severity:        "Low",
		SnapshotFiles:   []string{},
		Startup:         &startup,
	}

	got := buildAnalyticVariables(input)

	required := []string{"name", "inputType", "description", "actions", "analyticActions",
		"tags", "categories", "filter", "context", "level", "severity", "snapshotFiles", "startup"}
	for _, k := range required {
		if _, ok := got[k]; !ok {
			t.Errorf("expected variable %q to be present", k)
		}
	}

	for _, k := range []string{"label", "longDescription", "remediation", "matchReason"} {
		if _, ok := got[k]; ok {
			t.Errorf("expected variable %q to be omitted, got %v", k, got[k])
		}
	}
}

func TestBuildAnalyticVariables_AllOptionalFields(t *testing.T) {
	t.Parallel()

	startup := true
	input := AnalyticInput{
		Name:            "n",
		InputType:       "GPFSEvent",
		Label:           "L",
		LongDescription: "LD",
		Startup:         &startup,
		Remediation:     "R",
		MatchReason:     "M",
		AnalyticActions: []AnalyticActionInput{},
		Tags:            []string{},
		Categories:      []string{},
		Context:         []AnalyticContextInput{},
		SnapshotFiles:   []string{},
	}

	got := buildAnalyticVariables(input)

	for _, k := range []string{"label", "longDescription", "startup", "remediation", "matchReason"} {
		if _, ok := got[k]; !ok {
			t.Errorf("expected variable %q to be present", k)
		}
	}
	if got["startup"] != true {
		t.Errorf("expected startup=true, got %v", got["startup"])
	}
}
