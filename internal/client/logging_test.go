// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRedactBody(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		body    string
		secrets []string
		keep    []string
	}{
		{
			name:    "data forwarding variables",
			body:    `{"query":"mutation updateOrganizationForward","variables":{"sentinel":{"customerId":"ws-1","sharedKey":"SHARED-KEY"},"sentinelV2":{"azureClientId":"app-1","azureClientSecret":"AZ-SECRET"}}}`,
			secrets: []string{"SHARED-KEY", "AZ-SECRET"},
			keep:    []string{"ws-1", "app-1", "updateOrganizationForward"},
		},
		{
			name:    "api client password in response",
			body:    `{"data":{"createApiClient":{"clientId":"cid-1","password":"API-CLIENT-SECRET","name":"ci"}}}`,
			secrets: []string{"API-CLIENT-SECRET"},
			keep:    []string{"cid-1", `"name":"ci"`},
		},
		{
			name:    "downloads enrolment material",
			body:    `{"data":{"downloads":{"csr":"CSR-BLOB","websocket_auth":"WS-BLOB","offlineDeploymentToken":"OFFLINE","installerUuid":"inst-1"}}}`,
			secrets: []string{"CSR-BLOB", "WS-BLOB", "OFFLINE"},
			keep:    []string{"inst-1"},
		},
		{
			name:    "http client params in response",
			body:    `{"data":{"getActionConfigs":{"clients":[{"params":{"headers":[{"header":"Authorization","value":"Bearer WEBHOOK-TOKEN"}],"method":"POST","url":"https://hooks.example.com/services/SECRET-PATH"}}]}}}`,
			secrets: []string{"WEBHOOK-TOKEN", "SECRET-PATH"},
			keep:    []string{"Authorization", "POST"},
		},
		{
			name:    "http client params embedded as AWSJSON",
			body:    `{"query":"mutation createActionConfigs","variables":{"clients":[{"type":"Http","params":"{\"headers\":[{\"header\":\"X-Api-Key\",\"value\":\"EMBEDDED-KEY\"}],\"method\":\"POST\",\"url\":\"https://example.com/hook?token=EMBEDDED-URL\"}"}]}}`,
			secrets: []string{"EMBEDDED-KEY", "EMBEDDED-URL"},
			keep:    []string{"X-Api-Key", "createActionConfigs"},
		},
		{
			name:    "webhook url without headers or method",
			body:    `{"variables":{"clients":[{"type":"Http","params":"{\"url\":\"https://hooks.slack.com/services/T0/B0/SLACK-SECRET\"}"}]}}`,
			secrets: []string{"SLACK-SECRET"},
			keep:    []string{"Http"},
		},
		{
			name:    "header item without header name",
			body:    `{"params":{"headers":[{"value":"ORPHAN-VALUE"}]}}`,
			secrets: []string{"ORPHAN-VALUE"},
		},
		{
			name:    "top-level array",
			body:    `[{"data":{"createApiClient":{"password":"ARRAY-SECRET"}}}]`,
			secrets: []string{"ARRAY-SECRET"},
		},
		{
			name:    "AWSJSON nested in AWSJSON",
			body:    `{"variables":{"outer":"{\"inner\":\"{\\\"sharedKey\\\":\\\"NESTED-SECRET\\\"}\"}"}}`,
			secrets: []string{"NESTED-SECRET"},
		},
		{
			name:    "numbers and html survive a redacted body",
			body:    `{"data":{"big":12345678901234567890,"note":"<b>a&b</b>","password":"NUM-SECRET"}}`,
			secrets: []string{"NUM-SECRET"},
			keep:    []string{"12345678901234567890", "<b>a&b</b>"},
		},
		{
			name: "value outside headers kept",
			body: `{"data":{"filter":{"field":"name","value":"plain-value"}}}`,
			keep: []string{"plain-value"},
		},
		{
			name: "null and empty values kept",
			body: `{"data":{"sentinel":{"sharedKey":"","customerId":null},"apiClient":{"password":null}}}`,
			keep: []string{`"sharedKey":""`, `"password":null`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := string(redactBody([]byte(tt.body)))
			for _, s := range tt.secrets {
				if strings.Contains(got, s) {
					t.Errorf("secret %q not redacted: %s", s, got)
				}
			}
			if len(tt.secrets) > 0 && !strings.Contains(got, redactedValue) {
				t.Errorf("expected redaction marker in %s", got)
			}
			for _, s := range tt.keep {
				if !strings.Contains(got, s) {
					t.Errorf("expected %q to survive redaction: %s", s, got)
				}
			}
		})
	}
}

func TestRedactBody_Unchanged(t *testing.T) {
	t.Parallel()

	for _, body := range []string{
		`{"data":{"listPlans":{"items":[{"id":"1","name":"Default"}]}}}`,
		`<html><body>Request blocked</body></html>`,
		``,
		`{"data":`,
	} {
		if got := string(redactBody([]byte(body))); got != body {
			t.Errorf("expected body unchanged, got %q from %q", got, body)
		}
	}
}

func TestClient_Logger_RedactsGraphQLSecrets(t *testing.T) {
	t.Parallel()

	var wireBody string
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		testEncodeJSON(t, w, map[string]any{"access_token": "tok", "expires_in": 3600})
	})
	mux.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		testDecodeJSON(t, r, &req)
		wireBody = req["variables"].(map[string]any)["sentinel"].(map[string]any)["sharedKey"].(string)
		testWrite(t, w, []byte(`{"data":{"createApiClient":{"clientId":"cid","password":"RESPONSE-SECRET"}}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	logger := &testLogger{}
	client := NewClientWithUserAgent(srv.URL, "cid", "csecret", "test", WithMinRequestInterval(0))
	client.SetLogger(logger)

	var result struct {
		CreateAPIClient struct {
			Password string `json:"password"`
		} `json:"createApiClient"`
	}
	vars := map[string]any{"sentinel": map[string]any{"sharedKey": "REQUEST-SECRET"}}
	if err := client.DoGraphQL(context.Background(), "/app", "mutation { x }", vars, &result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if wireBody != "REQUEST-SECRET" {
		t.Errorf("request sent to the server was modified: %q", wireBody)
	}
	if result.CreateAPIClient.Password != "RESPONSE-SECRET" {
		t.Errorf("response returned to the caller was modified: %q", result.CreateAPIClient.Password)
	}
	if logger.requestCount() == 0 || logger.responseCount() == 0 {
		t.Fatalf("expected request and response to be logged, got %d and %d", logger.requestCount(), logger.responseCount())
	}
	for i := range logger.requestCount() {
		if body := string(logger.requestAt(i).body); strings.Contains(body, "REQUEST-SECRET") {
			t.Errorf("logged request contains secret: %s", body)
		}
	}
	for i := range logger.responseCount() {
		if body := string(logger.responseAt(i).body); strings.Contains(body, "RESPONSE-SECRET") {
			t.Errorf("logged response contains secret: %s", body)
		}
	}
}

type mutatingLogger struct{}

func (mutatingLogger) LogRequest(_ context.Context, _, _ string, _ http.Header, body []byte) {
	clear(body)
}

func (mutatingLogger) LogResponse(_ context.Context, _ int, _ http.Header, body []byte) {
	clear(body)
}

func TestClient_Logger_ReceivesCopies(t *testing.T) {
	t.Parallel()

	var wireQuery string
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		testEncodeJSON(t, w, map[string]any{"access_token": "tok", "expires_in": 3600})
	})
	mux.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		testDecodeJSON(t, r, &req)
		wireQuery, _ = req["query"].(string)
		testWrite(t, w, []byte(`{"data":{"x":"ok"}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := NewClientWithUserAgent(srv.URL, "cid", "csecret", "test", WithMinRequestInterval(0))
	client.SetLogger(mutatingLogger{})

	var result struct {
		X string `json:"x"`
	}
	if err := client.DoGraphQL(context.Background(), "/app", "query { x }", nil, &result); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if wireQuery != "query { x }" {
		t.Errorf("logger mutation reached the request: %q", wireQuery)
	}
	if result.X != "ok" {
		t.Errorf("logger mutation reached the response: %q", result.X)
	}
}
