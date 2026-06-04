// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// defaultMinRequestInterval is the minimum gap enforced between outbound GraphQL
// requests unless overridden with WithMinRequestInterval.
const defaultMinRequestInterval = 100 * time.Millisecond

// throttle enforces a minimum interval between outbound requests. It is safe for
// concurrent use; each caller reserves the next available slot.
type throttle struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

// wait blocks until the caller's reserved slot is reached or ctx is cancelled.
func (t *throttle) wait(ctx context.Context) error {
	t.mu.Lock()
	now := time.Now()
	slot := t.next
	if slot.Before(now) {
		slot = now
	}
	t.next = slot.Add(t.interval)
	t.mu.Unlock()

	delay := time.Until(slot)
	if delay <= 0 {
		return nil
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// throttlingDoer is an httpDoer that spaces outbound requests using a throttle.
type throttlingDoer struct {
	base     httpDoer
	throttle *throttle
}

// Do implements the httpDoer interface, waiting for the throttle before delegating.
func (d *throttlingDoer) Do(req *http.Request) (*http.Response, error) {
	if err := d.throttle.wait(req.Context()); err != nil {
		return nil, err
	}
	return d.base.Do(req)
}
