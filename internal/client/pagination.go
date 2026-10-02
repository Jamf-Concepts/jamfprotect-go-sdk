// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"maps"
)

// defaultMaxPages bounds how many pages one paginated call follows. At the
// server's default page size of 100 this allows one million items.
const defaultMaxPages = 10000

// CursorGuard stops pagination that would never terminate. It rejects any
// cursor already returned earlier in the same run and caps the page count.
type CursorGuard struct {
	maxPages int
	pages    int
	seen     map[[sha256.Size]byte]struct{}
}

// NewCursorGuard returns a CursorGuard for one paginated call, using the
// client's page limit.
func (c *Client) NewCursorGuard() *CursorGuard {
	return &CursorGuard{maxPages: c.maxPages, seen: make(map[[sha256.Size]byte]struct{})}
}

// Next records that a page was received with the given next cursor and
// reports ErrPaginationLimit if following it would revisit a cursor or exceed
// the page limit.
func (g *CursorGuard) Next(cursor string) error {
	g.pages++
	if g.pages >= g.maxPages {
		return fmt.Errorf("%w: reached the %d-page limit", ErrPaginationLimit, g.maxPages)
	}
	sum := sha256.Sum256([]byte(cursor))
	if _, ok := g.seen[sum]; ok {
		return fmt.Errorf("%w: server repeated a cursor after %d pages", ErrPaginationLimit, g.pages)
	}
	g.seen[sum] = struct{}{}
	return nil
}

// PaginatedResult is the common shape returned by all paginated list queries.
type PaginatedResult[T any] struct {
	Items    []T `json:"items"`
	PageInfo struct {
		Next  *string `json:"next"`
		Total int     `json:"total"`
	} `json:"pageInfo"`
}

// ListAll executes a paginated GraphQL list query, accumulating all pages.
// The resultKey must match the JSON field name of the list operation in the
// GraphQL response (e.g. "listGroups", "listRoles").
func ListAll[T any](
	ctx context.Context,
	c *Client,
	endpoint string,
	query string,
	baseVars map[string]any,
	resultKey string,
) ([]T, error) {
	var allItems []T
	var nextToken *string
	guard := c.NewCursorGuard()

	for {
		vars := maps.Clone(baseVars)
		if nextToken != nil {
			vars["nextToken"] = *nextToken
		}

		raw := make(map[string]json.RawMessage)
		if err := c.DoGraphQL(ctx, endpoint, query, vars, &raw); err != nil {
			return nil, err
		}

		data, ok := raw[resultKey]
		if !ok {
			return nil, fmt.Errorf("response missing expected key %q", resultKey)
		}

		var page PaginatedResult[T]
		if err := json.Unmarshal(data, &page); err != nil {
			return nil, fmt.Errorf("decoding %s: %w", resultKey, err)
		}

		allItems = append(allItems, page.Items...)
		if page.PageInfo.Next == nil {
			break
		}
		if err := guard.Next(*page.PageInfo.Next); err != nil {
			return nil, fmt.Errorf("paginating %s: %w", resultKey, err)
		}
		nextToken = page.PageInfo.Next
	}

	return allItems, nil
}
