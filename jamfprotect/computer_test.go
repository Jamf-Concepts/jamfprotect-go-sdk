// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// testServer creates a mock HTTP server that handles /token and /app endpoints.
// The graphqlHandler receives decoded GraphQL requests and returns the response data.
func testServer(t *testing.T, graphqlHandler func(t *testing.T, req graphqlRequest) any) (*httptest.Server, *Client) {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-token",
			"expires_in":   3600,
		}); err != nil {
			t.Fatalf("encoding token response: %v", err)
		}
	})
	mux.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
		var req graphqlRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decoding graphql request: %v", err)
		}

		data := graphqlHandler(t, req)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{"data": data}); err != nil {
			t.Fatalf("encoding graphql response: %v", err)
		}
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client := NewClient(srv.URL, "test-id", "test-secret",
		WithHTTPClient(srv.Client()),
	)

	return srv, client
}

type graphqlRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
}

func TestSetComputerPlan(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()

		if req.Variables["uuid"] != "test-uuid" {
			t.Errorf("expected uuid %q, got %q", "test-uuid", req.Variables["uuid"])
		}
		if req.Variables["plan"] != "plan-123" {
			t.Errorf("expected plan %q, got %q", "plan-123", req.Variables["plan"])
		}
		if req.Variables["RBAC_Plan"] != true {
			t.Error("expected RBAC_Plan to be true")
		}
		if req.Variables["RBAC_Insight"] != true {
			t.Error("expected RBAC_Insight to be true")
		}
		if req.Variables["RBAC_ThreatPreventionVersion"] != true {
			t.Error("expected RBAC_ThreatPreventionVersion to be true")
		}

		return map[string]any{
			"setComputerPlan": map[string]any{
				"uuid":             "test-uuid",
				"serial":           "C02TEST",
				"hostName":         "test-host",
				"connectionStatus": "Connected",
				"pendingPlan":      123,
				"plan": map[string]any{
					"id":   "plan-123",
					"name": "Test Plan",
					"hash": "abc123",
				},
			},
		}
	})

	ctx := context.Background()
	computer, err := client.SetComputerPlan(ctx, "test-uuid", "plan-123")
	if err != nil {
		t.Fatalf("SetComputerPlan: %v", err)
	}
	if computer == nil {
		t.Fatal("SetComputerPlan: expected non-nil computer")
	}
	if *computer.UUID != "test-uuid" {
		t.Errorf("expected UUID %q, got %q", "test-uuid", *computer.UUID)
	}
	if computer.Plan == nil {
		t.Fatal("expected non-nil plan")
	}
	if *computer.Plan.ID != "plan-123" {
		t.Errorf("expected plan ID %q, got %q", "plan-123", *computer.Plan.ID)
	}
	if *computer.Plan.Name != "Test Plan" {
		t.Errorf("expected plan name %q, got %q", "Test Plan", *computer.Plan.Name)
	}
}

func TestSetComputerPlan_Error(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-token",
			"expires_in":   3600,
		}); err != nil {
			t.Fatalf("encoding token response: %v", err)
		}
	})
	mux.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"data":   nil,
			"errors": []map[string]any{{"message": "computer not found"}},
		}); err != nil {
			t.Fatalf("encoding graphql response: %v", err)
		}
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client := NewClient(srv.URL, "test-id", "test-secret",
		WithHTTPClient(srv.Client()),
	)

	ctx := context.Background()
	_, err := client.SetComputerPlan(ctx, "nonexistent", "plan-123")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestUpdateComputer(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()

		if req.Variables["uuid"] != "test-uuid" {
			t.Errorf("expected uuid %q, got %q", "test-uuid", req.Variables["uuid"])
		}
		if req.Variables["label"] != "New Label" {
			t.Errorf("expected label %q, got %q", "New Label", req.Variables["label"])
		}
		tags, ok := req.Variables["tags"].([]any)
		if !ok {
			t.Fatalf("expected tags to be a slice, got %T", req.Variables["tags"])
		}
		if len(tags) != 2 || tags[0] != "tag1" || tags[1] != "tag2" {
			t.Errorf("expected tags [tag1 tag2], got %v", tags)
		}
		if req.Variables["RBAC_Plan"] != true {
			t.Error("expected RBAC_Plan to be true")
		}

		return map[string]any{
			"updateComputer": map[string]any{
				"uuid":             "test-uuid",
				"serial":           "C02TEST",
				"hostName":         "test-host",
				"label":            "New Label",
				"tags":             []string{"tag1", "tag2"},
				"connectionStatus": "Connected",
			},
		}
	})

	ctx := context.Background()
	label := "New Label"
	computer, err := client.UpdateComputer(ctx, "test-uuid", ComputerUpdateInput{
		Label: &label,
		Tags:  []string{"tag1", "tag2"},
	})
	if err != nil {
		t.Fatalf("UpdateComputer: %v", err)
	}
	if computer == nil {
		t.Fatal("UpdateComputer: expected non-nil computer")
	}
	if *computer.UUID != "test-uuid" {
		t.Errorf("expected UUID %q, got %q", "test-uuid", *computer.UUID)
	}
	if *computer.Label != "New Label" {
		t.Errorf("expected label %q, got %q", "New Label", *computer.Label)
	}
	if computer.Tags == nil || len(*computer.Tags) != 2 {
		t.Fatalf("expected 2 tags, got %v", computer.Tags)
	}
}

func TestUpdateComputer_LabelOnly(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()

		if _, ok := req.Variables["tags"]; ok {
			t.Error("expected tags to be absent when nil")
		}
		if req.Variables["label"] != "Only Label" {
			t.Errorf("expected label %q, got %q", "Only Label", req.Variables["label"])
		}

		return map[string]any{
			"updateComputer": map[string]any{
				"uuid":     "test-uuid",
				"hostName": "test-host",
				"label":    "Only Label",
			},
		}
	})

	ctx := context.Background()
	label := "Only Label"
	computer, err := client.UpdateComputer(ctx, "test-uuid", ComputerUpdateInput{
		Label: &label,
	})
	if err != nil {
		t.Fatalf("UpdateComputer: %v", err)
	}
	if *computer.Label != "Only Label" {
		t.Errorf("expected label %q, got %q", "Only Label", *computer.Label)
	}
}

func TestUpdateComputer_TagsOnly(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()

		if _, ok := req.Variables["label"]; ok {
			t.Error("expected label to be absent when nil")
		}
		tags, ok := req.Variables["tags"].([]any)
		if !ok {
			t.Fatalf("expected tags to be a slice, got %T", req.Variables["tags"])
		}
		if len(tags) != 1 || tags[0] != "solo" {
			t.Errorf("expected tags [solo], got %v", tags)
		}

		return map[string]any{
			"updateComputer": map[string]any{
				"uuid":     "test-uuid",
				"hostName": "test-host",
				"tags":     []string{"solo"},
			},
		}
	})

	ctx := context.Background()
	computer, err := client.UpdateComputer(ctx, "test-uuid", ComputerUpdateInput{
		Tags: []string{"solo"},
	})
	if err != nil {
		t.Fatalf("UpdateComputer: %v", err)
	}
	if computer.Tags == nil || len(*computer.Tags) != 1 {
		t.Fatalf("expected 1 tag, got %v", computer.Tags)
	}
}

func TestUpdateComputer_ClearTags(t *testing.T) {
	t.Parallel()

	_, client := testServer(t, func(t *testing.T, req graphqlRequest) any {
		t.Helper()

		tags, ok := req.Variables["tags"].([]any)
		if !ok {
			t.Fatalf("expected tags to be a slice, got %T", req.Variables["tags"])
		}
		if len(tags) != 0 {
			t.Errorf("expected empty tags, got %v", tags)
		}

		return map[string]any{
			"updateComputer": map[string]any{
				"uuid":     "test-uuid",
				"hostName": "test-host",
				"tags":     []string{},
			},
		}
	})

	ctx := context.Background()
	computer, err := client.UpdateComputer(ctx, "test-uuid", ComputerUpdateInput{
		Tags: []string{},
	})
	if err != nil {
		t.Fatalf("UpdateComputer: %v", err)
	}
	if computer.Tags == nil || len(*computer.Tags) != 0 {
		t.Fatalf("expected empty tags, got %v", computer.Tags)
	}
}

func TestUpdateComputer_Error(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-token",
			"expires_in":   3600,
		}); err != nil {
			t.Fatalf("encoding token response: %v", err)
		}
	})
	mux.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"data":   nil,
			"errors": []map[string]any{{"message": "permission denied"}},
		}); err != nil {
			t.Fatalf("encoding graphql response: %v", err)
		}
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client := NewClient(srv.URL, "test-id", "test-secret",
		WithHTTPClient(srv.Client()),
	)

	ctx := context.Background()
	label := "test"
	_, err := client.UpdateComputer(ctx, "test-uuid", ComputerUpdateInput{Label: &label})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
