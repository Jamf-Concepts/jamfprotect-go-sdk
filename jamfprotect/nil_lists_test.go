// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"regexp"
	"testing"
)

// optionalLists maps an operation to the list variables its builder omits when the input slice is nil.
var optionalLists = map[string][]string{
	"CreateGroup":            {"roleIds"},
	"UpdateGroup":            {"roleIds"},
	"CreateUser":             {"roleIds", "groupIds"},
	"UpdateUser":             {"roleIds", "groupIds"},
	"CreateExceptionSet":     {"esExceptions"},
	"UpdateExceptionSet":     {"esExceptions"},
	"CreateAnalytic":         {"actions", "tenantActions"},
	"UpdateAnalytic":         {"actions", "tenantActions"},
	"UpdateInternalAnalytic": {"tenantActions"},
	"CreateActionConfig":     {"clients"},
	"UpdateActionConfig":     {"clients"},
	"UpdateComputer":         {"tags"},
}

// listVarPattern matches GraphQL variable declarations with a list type.
var listVarPattern = regexp.MustCompile(`\$(\w+):\s*\[`)

// TestZeroInputsSendEmptyLists checks that every list variable declared by a create or update
// operation reaches the server as an empty array, never null, when the input slices are nil.
// Variables listed in optionalLists must instead be omitted. ApiClient role IDs are deliberately
// not optional: the server grants Full Admin to an API client created without them.
func TestZeroInputsSendEmptyLists(t *testing.T) {
	t.Parallel()

	cases := map[string]func(*Client) error{
		"CreateActionConfig": func(c *Client) error {
			_, err := c.CreateActionConfig(context.Background(), ActionConfigInput{})
			return err
		},
		"UpdateActionConfig": func(c *Client) error {
			_, err := c.UpdateActionConfig(context.Background(), "id", ActionConfigInput{})
			return err
		},
		"CreateApiClient": func(c *Client) error { _, err := c.CreateApiClient(context.Background(), ApiClientInput{}); return err },
		"UpdateApiClient": func(c *Client) error {
			_, err := c.UpdateApiClient(context.Background(), "id", ApiClientInput{})
			return err
		},
		"UpdateAlerts":   func(c *Client) error { _, err := c.UpdateAlerts(context.Background(), AlertUpdateInput{}); return err },
		"CreateAnalytic": func(c *Client) error { _, err := c.CreateAnalytic(context.Background(), AnalyticInput{}); return err },
		"UpdateAnalytic": func(c *Client) error {
			_, err := c.UpdateAnalytic(context.Background(), "id", AnalyticInput{})
			return err
		},
		"UpdateInternalAnalytic": func(c *Client) error {
			_, err := c.UpdateInternalAnalytic(context.Background(), "id", InternalAnalyticInput{})
			return err
		},
		"CreateAnalyticSet": func(c *Client) error {
			_, err := c.CreateAnalyticSet(context.Background(), AnalyticSetInput{})
			return err
		},
		"UpdateAnalyticSet": func(c *Client) error {
			_, err := c.UpdateAnalyticSet(context.Background(), "id", AnalyticSetInput{})
			return err
		},
		"UpdateComputer": func(c *Client) error {
			_, err := c.UpdateComputer(context.Background(), "id", ComputerUpdateInput{})
			return err
		},
		"CreateCustomPreventList": func(c *Client) error {
			_, err := c.CreateCustomPreventList(context.Background(), CustomPreventListInput{})
			return err
		},
		"UpdateCustomPreventList": func(c *Client) error {
			_, err := c.UpdateCustomPreventList(context.Background(), "id", CustomPreventListInput{})
			return err
		},
		"CreateGroup": func(c *Client) error { _, err := c.CreateGroup(context.Background(), GroupInput{}); return err },
		"UpdateGroup": func(c *Client) error { _, err := c.UpdateGroup(context.Background(), "id", GroupInput{}); return err },
		"CreateExceptionSet": func(c *Client) error {
			_, err := c.CreateExceptionSet(context.Background(), ExceptionSetInput{})
			return err
		},
		"UpdateExceptionSet": func(c *Client) error {
			_, err := c.UpdateExceptionSet(context.Background(), "id", ExceptionSetInput{})
			return err
		},
		"CreateUser": func(c *Client) error { _, err := c.CreateUser(context.Background(), UserInput{}); return err },
		"UpdateUser": func(c *Client) error { _, err := c.UpdateUser(context.Background(), "id", UserInput{}); return err },
		"CreatePlan": func(c *Client) error { _, err := c.CreatePlan(context.Background(), PlanInput{}); return err },
		"UpdatePlan": func(c *Client) error { _, err := c.UpdatePlan(context.Background(), "id", PlanInput{}); return err },
		"CreateRole": func(c *Client) error { _, err := c.CreateRole(context.Background(), RoleInput{}); return err },
		"UpdateRole": func(c *Client) error { _, err := c.UpdateRole(context.Background(), "id", RoleInput{}); return err },
		"CreateTelemetryV2": func(c *Client) error {
			_, err := c.CreateTelemetryV2(context.Background(), TelemetryV2Input{})
			return err
		},
		"UpdateTelemetryV2": func(c *Client) error {
			_, err := c.UpdateTelemetryV2(context.Background(), "id", TelemetryV2Input{})
			return err
		},
		"CreateRemovableStorageControlSet": func(c *Client) error {
			_, err := c.CreateRemovableStorageControlSet(context.Background(), RemovableStorageControlSetInput{})
			return err
		},
		"UpdateRemovableStorageControlSet": func(c *Client) error {
			_, err := c.UpdateRemovableStorageControlSet(context.Background(), "id", RemovableStorageControlSetInput{})
			return err
		},
		"CreateUnifiedLoggingFilterSet": func(c *Client) error {
			_, err := c.CreateUnifiedLoggingFilterSet(context.Background(), UnifiedLoggingFilterSetInput{})
			return err
		},
		"UpdateUnifiedLoggingFilterSet": func(c *Client) error {
			_, err := c.UpdateUnifiedLoggingFilterSet(context.Background(), "id", UnifiedLoggingFilterSetInput{})
			return err
		},
		"CreatePreventListSet": func(c *Client) error {
			_, err := c.CreatePreventListSet(context.Background(), PreventListSetInput{})
			return err
		},
		"UpdatePreventListSet": func(c *Client) error {
			_, err := c.UpdatePreventListSet(context.Background(), "id", PreventListSetInput{})
			return err
		},
		"CreateUnifiedLoggingFilter": func(c *Client) error {
			_, err := c.CreateUnifiedLoggingFilter(context.Background(), UnifiedLoggingFilterInput{})
			return err
		},
		"UpdateUnifiedLoggingFilter": func(c *Client) error {
			_, err := c.UpdateUnifiedLoggingFilter(context.Background(), "id", UnifiedLoggingFilterInput{})
			return err
		},
	}

	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var query string
			var vars map[string]any
			_, c := testServer(t, func(_ *testing.T, req graphqlRequest) any {
				query, vars = req.Query, req.Variables
				return map[string]any{}
			})
			if err := call(c); err != nil {
				t.Fatalf("call error: %v", err)
			}

			declared := listVarPattern.FindAllStringSubmatch(query, -1)
			if len(declared) == 0 {
				t.Skip("operation declares no list variables")
			}
			optional := make(map[string]bool)
			for _, k := range optionalLists[name] {
				optional[k] = true
			}
			for _, m := range declared {
				v, present := vars[m[1]]
				switch {
				case optional[m[1]] && present:
					t.Errorf("optional list variable %q = %#v, want omitted", m[1], v)
				case optional[m[1]]:
				case !present:
					t.Errorf("list variable %q missing from request", m[1])
				default:
					if _, ok := v.([]any); !ok {
						t.Errorf("list variable %q = %#v, want empty array", m[1], v)
					}
				}
			}
		})
	}
}

// TestNestedInputLists checks list fields nested inside an object-typed input variable.
func TestNestedInputLists(t *testing.T) {
	t.Parallel()

	empty := []string{}
	tests := []struct {
		name    string
		call    func(*Client) error
		present []string
		absent  []string
	}{
		{
			name: "CreateTelemetryV2 nil lists",
			call: func(c *Client) error {
				_, err := c.CreateTelemetryV2(context.Background(), TelemetryV2Input{})
				return err
			},
			present: []string{"events", "logFiles"},
		},
		{
			name: "UpdateTelemetryV2 nil lists",
			call: func(c *Client) error {
				_, err := c.UpdateTelemetryV2(context.Background(), "id", TelemetryV2Input{})
				return err
			},
			present: []string{"events", "logFiles"},
		},
		{
			name:   "CreatePlan nil lists",
			call:   func(c *Client) error { _, err := c.CreatePlan(context.Background(), PlanInput{}); return err },
			absent: []string{"exceptionSets", "analyticSets", "unifiedLoggingFilterSets", "preventListSets"},
		},
		{
			name: "UpdatePlan empty lists",
			call: func(c *Client) error {
				_, err := c.UpdatePlan(context.Background(), "id", PlanInput{
					ExceptionSets:            empty,
					AnalyticSets:             []PlanAnalyticSetInput{},
					UnifiedLoggingFilterSets: empty,
					PreventListSets:          empty,
				})
				return err
			},
			present: []string{"exceptionSets", "analyticSets", "unifiedLoggingFilterSets", "preventListSets"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var vars map[string]any
			_, c := testServer(t, func(_ *testing.T, req graphqlRequest) any {
				vars = req.Variables
				return map[string]any{}
			})
			if err := tt.call(c); err != nil {
				t.Fatalf("call error: %v", err)
			}
			container := vars
			if in, ok := vars["input"].(map[string]any); ok {
				container = in
			}
			for _, k := range tt.present {
				if _, ok := container[k].([]any); !ok {
					t.Errorf("%q = %#v, want empty array", k, container[k])
				}
			}
			for _, k := range tt.absent {
				if v, ok := container[k]; ok {
					t.Errorf("%q = %#v, want omitted", k, v)
				}
			}
		})
	}
}

// TestOptionalListsSentWhenEmpty checks that an empty non-nil slice is sent as [] so it clears the field.
func TestOptionalListsSentWhenEmpty(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tests := []struct {
		name string
		call func(*Client) error
		keys []string
	}{
		{"UpdateGroup", func(c *Client) error { _, err := c.UpdateGroup(ctx, "id", GroupInput{RoleIDs: []string{}}); return err }, []string{"roleIds"}},
		{"UpdateUser", func(c *Client) error {
			_, err := c.UpdateUser(ctx, "id", UserInput{RoleIDs: []string{}, GroupIDs: []string{}})
			return err
		}, []string{"roleIds", "groupIds"}},
		{"UpdateExceptionSet", func(c *Client) error {
			_, err := c.UpdateExceptionSet(ctx, "id", ExceptionSetInput{EsExceptions: []EsExceptionInput{}})
			return err
		}, []string{"esExceptions"}},
		{"UpdateAnalytic", func(c *Client) error {
			_, err := c.UpdateAnalytic(ctx, "id", AnalyticInput{Actions: []string{}})
			return err
		}, []string{"actions"}},
		{"UpdateActionConfig", func(c *Client) error {
			_, err := c.UpdateActionConfig(ctx, "id", ActionConfigInput{Clients: []map[string]any{}})
			return err
		}, []string{"clients"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var vars map[string]any
			_, c := testServer(t, func(_ *testing.T, req graphqlRequest) any {
				vars = req.Variables
				return map[string]any{}
			})
			if err := tt.call(c); err != nil {
				t.Fatalf("call error: %v", err)
			}
			for _, k := range tt.keys {
				if _, ok := vars[k].([]any); !ok {
					t.Errorf("%q = %#v, want empty array", k, vars[k])
				}
			}
		})
	}
}
