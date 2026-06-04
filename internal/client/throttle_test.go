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

func TestThrottle_EnforcesInterval(t *testing.T) {
	t.Parallel()

	th := &throttle{interval: 50 * time.Millisecond}
	ctx := context.Background()

	start := time.Now()
	for range 3 {
		if err := th.wait(ctx); err != nil {
			t.Fatalf("wait: %v", err)
		}
	}
	elapsed := time.Since(start)

	if elapsed < 100*time.Millisecond {
		t.Fatalf("expected >=100ms for 3 calls at 50ms interval, got %v", elapsed)
	}
}

func TestThrottle_FirstCallImmediate(t *testing.T) {
	t.Parallel()

	th := &throttle{interval: time.Hour}
	start := time.Now()
	if err := th.wait(context.Background()); err != nil {
		t.Fatalf("wait: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("expected first call to be immediate, took %v", elapsed)
	}
}

func TestThrottle_ContextCancellation(t *testing.T) {
	t.Parallel()

	th := &throttle{interval: time.Hour}
	if err := th.wait(context.Background()); err != nil {
		t.Fatalf("priming wait: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := th.wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestClient_MinRequestInterval(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var appTimes []time.Time

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		testEncodeJSON(t, w, map[string]any{"access_token": "tok", "expires_in": 3600})
	})
	mux.HandleFunc("/app", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		appTimes = append(appTimes, time.Now())
		mu.Unlock()
		testEncodeJSON(t, w, map[string]any{"data": map[string]any{}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := NewClientWithUserAgent(srv.URL, "cid", "csecret", "test",
		WithMinRequestInterval(80*time.Millisecond))

	for range 3 {
		if err := client.DoGraphQL(context.Background(), "/app", "query { x }", nil, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(appTimes) != 3 {
		t.Fatalf("expected 3 app requests, got %d", len(appTimes))
	}
	for i := 1; i < len(appTimes); i++ {
		if gap := appTimes[i].Sub(appTimes[i-1]); gap < 70*time.Millisecond {
			t.Errorf("gap %d too small: %v (expected >=70ms)", i, gap)
		}
	}
}

func TestClient_MinRequestInterval_DefaultOn(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var appTimes []time.Time

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		testEncodeJSON(t, w, map[string]any{"access_token": "tok", "expires_in": 3600})
	})
	mux.HandleFunc("/app", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		appTimes = append(appTimes, time.Now())
		mu.Unlock()
		testEncodeJSON(t, w, map[string]any{"data": map[string]any{}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := NewClient(srv.URL, "cid", "csecret")

	for range 2 {
		if err := client.DoGraphQL(context.Background(), "/app", "query { x }", nil, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(appTimes) != 2 {
		t.Fatalf("expected 2 app requests, got %d", len(appTimes))
	}
	if gap := appTimes[1].Sub(appTimes[0]); gap < 70*time.Millisecond {
		t.Fatalf("expected default ~100ms spacing with no option set, got %v", gap)
	}
}

func TestClient_MinRequestInterval_Disabled(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		testEncodeJSON(t, w, map[string]any{"access_token": "tok", "expires_in": 3600})
	})
	mux.HandleFunc("/app", func(w http.ResponseWriter, _ *http.Request) {
		testEncodeJSON(t, w, map[string]any{"data": map[string]any{}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := NewClientWithUserAgent(srv.URL, "cid", "csecret", "test",
		WithMinRequestInterval(0))

	start := time.Now()
	for range 5 {
		if err := client.DoGraphQL(context.Background(), "/app", "query { x }", nil, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("expected no throttling, 5 requests took %v", elapsed)
	}
}
