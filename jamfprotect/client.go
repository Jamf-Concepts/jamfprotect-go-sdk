// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"net/http"

	"github.com/Jamf-Concepts/jamfprotect-go-sdk/internal/client"
)

// Client provides typed methods for all Jamf Protect API operations.
type Client struct {
	transport *client.Client
}

// NewClient creates a new Jamf Protect API client.
func NewClient(baseURL, clientID, clientSecret string, opts ...Option) *Client {
	cfg := &clientConfig{
		userAgent: "jamfprotect-go-sdk/dev",
	}
	for _, opt := range opts {
		opt(cfg)
	}

	var transportOpts []client.Option
	if cfg.httpClient != nil {
		transportOpts = append(transportOpts, client.WithHTTPClient(cfg.httpClient))
	}

	var cache client.TokenCache
	if cfg.tokenCache != nil {
		cache = cfg.tokenCache
	} else if cfg.cacheDir != "" {
		cache = client.NewFileTokenCache(cfg.cacheDir)
	}
	if cache != nil {
		transportOpts = append(transportOpts, client.WithTokenCache(cache, client.CacheKey(baseURL, clientID)))
	}

	transport := client.NewClientWithUserAgent(baseURL, clientID, clientSecret, cfg.userAgent, transportOpts...)
	if cfg.logger != nil {
		transport.SetLogger(cfg.logger)
	}

	return &Client{transport: transport}
}

// BaseURL returns the base URL configured for the client.
func (c *Client) BaseURL() string {
	return c.transport.BaseURL()
}

// AccessToken returns a valid access token, refreshing if necessary.
// Tokens returned by Jamf Protect do not include a "Bearer" prefix.
func (c *Client) AccessToken(ctx context.Context) (*Token, error) {
	t, err := c.transport.AccessToken(ctx)
	if err != nil {
		return nil, err
	}
	return &Token{
		AccessToken: t.AccessToken,
		TokenType:   t.TokenType,
		Expiry:      t.Expiry,
	}, nil
}

// clientConfig holds configuration applied via Option functions.
type clientConfig struct {
	userAgent  string
	httpClient *http.Client
	logger     Logger
	tokenCache TokenCache
	cacheDir   string
}

// Option configures a Client.
type Option func(*clientConfig)

// WithUserAgent sets a custom user agent string.
func WithUserAgent(userAgent string) Option {
	return func(cfg *clientConfig) {
		if userAgent != "" {
			cfg.userAgent = userAgent
		}
	}
}

// WithHTTPClient overrides the default HTTP client.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(cfg *clientConfig) {
		cfg.httpClient = httpClient
	}
}

// WithLogger sets a logger for HTTP request/response logging.
func WithLogger(logger Logger) Option {
	return func(cfg *clientConfig) {
		cfg.logger = logger
	}
}

// WithTokenCache sets a custom token cache for persisting tokens across process restarts.
func WithTokenCache(cache TokenCache) Option {
	return func(cfg *clientConfig) {
		cfg.tokenCache = cache
	}
}

// WithFileTokenCache enables file-based token caching in the given directory.
func WithFileTokenCache(dir string) Option {
	return func(cfg *clientConfig) {
		cfg.cacheDir = dir
	}
}
