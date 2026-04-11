# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Go SDK for [Jamf Protect](https://www.jamf.com/products/jamf-protect/). Extracted from [terraform-provider-jamfprotect](https://github.com/Jamf-Concepts/terraform-provider-jamfprotect) to enable reuse across tools (Terraform provider, CLI tools, other integrations).

The module path is `github.com/Jamf-Concepts/jamfprotect-go-sdk`.

## Architecture

The SDK has two layers:

- **`jamfprotect` (exported)** — Public API. Provides a `Client` with typed methods for each Jamf Protect resource. Consumers import only this package.
- **`internal/client`** — GraphQL transport, OAuth2 token management, pagination, error handling. Not importable by external consumers.

The transport client handles:
- OAuth2 client credentials flow against `POST {base_url}/token` (sends `client_id` + `password`, receives `access_token` without Bearer prefix)
- Thread-safe token caching with `sync.Mutex` + `singleflight.Group`
- Retryable HTTP with exponential backoff (3 retries, 1-30s)
- Two GraphQL endpoints: `/graphql` (limited, introspection enabled) and `/app` (full API, introspection disabled — SDK uses `/app`)

## Commands

```bash
go build ./...           # Build
go test ./...            # Unit tests
go test -v -count=1 ./... # Verbose unit tests
go test -run TestFuncName ./path/to/pkg  # Single test
go vet ./...             # Vet
gofmt -s -w -e .         # Format
golangci-lint run        # Lint
```

## Dependencies Policy

Only use native Go and `golang.org/x` packages. Do not introduce third-party dependencies without discussion. Current transport dependencies: `hashicorp/go-retryablehttp`, `golang.org/x/sync`.

## Code Style

- Every exported constant, function, variable set, and type must have a short comment describing its purpose.
- Do not add comments inside type definitions or function bodies.
- Wrap errors with `fmt.Errorf("context: %w", err)` to preserve error chains.
- Sentinel errors: `ErrAuthentication`, `ErrGraphQL`, `ErrNotFound` (defined in internal/client).

## Service Method Conventions

Each resource has typed CRUD methods on the client following this pattern:

```go
func (c *Client) CreateRole(ctx context.Context, input RoleInput) (Role, error)
func (c *Client) GetRole(ctx context.Context, id string) (*Role, error)
func (c *Client) UpdateRole(ctx context.Context, id string, input RoleInput) (Role, error)
func (c *Client) DeleteRole(ctx context.Context, id string) error
func (c *Client) ListRoles(ctx context.Context) ([]Role, error)
```

Each resource file contains GraphQL queries/mutations as constants, Go types for request/response payloads, and the CRUD method implementations. GraphQL fragments are appended to query constants for field reuse.

### Resource Coverage

**Full CRUD:** ActionConfig, Analytic, AnalyticSet, ApiClient, CustomPreventList, ExceptionSet, Group, Plan, RemovableStorageControlSet, Role, TelemetryV2, UnifiedLoggingFilter, User

**Read + Write (partial):** Computer (list, get, update, delete, setComputerPlan), Connection (list-only), DataForwarding (get/update), DataRetention (get/update), ChangeManagement (get/update), Downloads (get-only)

**Alerts:** GetAlert, ListAlerts, UpdateAlerts (bulk status), GetAlertStatusCounts

**Insights/Compliance:** ListInsights, UpdateInsightStatus, ListInsightComputers, GetFleetComplianceScore

**Audit Logs:** ListAuditLogsByDate (2-day max sliding window), ListAuditLogsByUser, ListAuditLogsByOp

**Auth:** GetCurrentPermissions (RBAC introspection)

## RBAC Variables

Some GraphQL queries require RBAC permission-scoping variables (e.g., `RBAC_Connection`, `RBAC_Role`, `RBAC_Plan`). These are merged into query variables using `mergeVars()`.

## Environment Variables

- `JAMFPROTECT_URL` — Base URL (e.g., `https://your-tenant.protect.jamfcloud.com`)
- `JAMFPROTECT_CLIENT_ID` — API client ID
- `JAMFPROTECT_CLIENT_SECRET` — API client secret

Acceptance tests use `JAMFPROTECT_BASE_URL` (not `JAMFPROTECT_URL`) plus `JAMFPROTECT_CLIENT_ID` and `JAMFPROTECT_CLIENT_SECRET`.

## Schema

The GraphQL schema is at `bin/schema.graphql`. The audit of SDK coverage against the schema is at `bin/AUDIT.md`.
