// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestClient_Unauthorized_ReauthenticationFails(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	tokenCalls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		tokenCalls++
		n := tokenCalls
		mu.Unlock()
		if n > 1 {
			w.WriteHeader(http.StatusUnauthorized)
			testWrite(t, w, []byte(`{"error":"invalid_client"}`))
			return
		}
		testEncodeJSON(t, w, map[string]any{"access_token": "tok", "expires_in": 3600})
	})
	mux.HandleFunc("/app", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		testWrite(t, w, []byte(`{"errors":[{"message":"You are not authorized to make this call."}]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := NewClientWithUserAgent(srv.URL, "cid", "csecret", "test", WithMinRequestInterval(0))
	err := client.DoGraphQL(context.Background(), "/app", "query { x }", nil, nil)
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("expected ErrAuthentication, got: %v", err)
	}
}

func TestClient_Unauthorized_ConcurrentCallers(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	tokenCalls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		tokenCalls++
		mu.Unlock()
		testEncodeJSON(t, w, map[string]any{"access_token": "fresh", "expires_in": 3600})
	})
	mux.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "fresh" {
			w.WriteHeader(http.StatusUnauthorized)
			testWrite(t, w, []byte(`{"errors":[{"message":"You are not authorized to make this call."}]}`))
			return
		}
		testEncodeJSON(t, w, map[string]any{"data": map[string]any{}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cache := &mockTokenCache{
		loadFn: func(_ string) (string, time.Time, bool) {
			return "stale", time.Now().Add(time.Hour), true
		},
		storeFn: func(_ string, _ string, _ time.Time) error {
			return nil
		},
	}
	client := NewClientWithUserAgent(srv.URL, "cid", "csecret", "test",
		WithTokenCache(cache, "test-key"), WithMinRequestInterval(0))

	const callers = 20
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Go(func() {
			errs <- client.DoGraphQL(context.Background(), "/app", "query { x }", nil, nil)
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("caller failed: %v", err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if tokenCalls == 0 || tokenCalls > callers {
		t.Errorf("expected between 1 and %d token fetches, got %d", callers, tokenCalls)
	}
}
