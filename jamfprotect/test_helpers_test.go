// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type graphqlRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
}

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

// testServerError creates a mock HTTP server that returns a GraphQL error.
func testServerError(t *testing.T, message string) (*httptest.Server, *Client) {
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
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"data":   nil,
			"errors": []map[string]any{{"message": message}},
		}); err != nil {
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
