// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"flag"
	"go/format"
	"os"
	"path/filepath"
	"testing"
	"text/template"
)

// updateGolden refreshes the *.golden files when set. Run with:
//
//	go test -run TestGolden -update ./tools/generate/
var updateGolden = flag.Bool("update", false, "update golden files instead of asserting")

// renderResource is a thin wrapper around buildIR + the resource template.
// Mirrors the production emitFile pipeline but returns bytes for diffing.
func renderResource(t *testing.T, cfg Config, res ResourceConfig, sdl string) []byte {
	t.Helper()
	schema := loadTestSchema(t, sdl)
	ir, err := buildIR(cfg, schema, res)
	if err != nil {
		t.Fatalf("buildIR: %v", err)
	}
	tmpl, err := template.New("resource").Parse(resourceTmpl)
	if err != nil {
		t.Fatalf("parse template: %v", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, ir); err != nil {
		t.Fatalf("render template: %v", err)
	}
	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		t.Fatalf("format source: %v\n--- raw ---\n%s", err, buf.String())
	}
	return formatted
}

func assertGolden(t *testing.T, path string, got []byte) {
	t.Helper()
	if *updateGolden {
		if err := os.WriteFile(path, got, 0644); err != nil {
			t.Fatalf("write golden %s: %v", path, err)
		}
		t.Logf("updated golden: %s", path)
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s (run with -update to create): %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("output does not match %s\n--- got ---\n%s\n--- want ---\n%s",
			path, got, want)
	}
}

// TestGolden_CRUDResource covers the full CRUD shape: a Role-style resource
// with get, create, update, delete, list (paginated). The golden file pins
// the entire generated Go output — buildIR, template render, all four code
// emission concerns (fragment, response types, input types, methods) — so
// refactors that move bytes silently get caught.
func TestGolden_CRUDResource(t *testing.T) {
	sdl := `
		type Query {
			getRole(id: ID!): Role
			listRoles(input: RoleListInput): RoleList
		}
		type Mutation {
			createRole(input: RoleInput!): Role
			updateRole(id: ID!, input: RoleInput!): Role
			deleteRole(id: ID!): Role
		}
		type Role {
			id: ID!
			name: String!
			description: String
			created: AWSDateTime
		}
		input RoleInput {
			name: String!
			description: String
		}
		input RoleListInput {
			next: String
			pageSize: Int
			filter: RoleFilterInput
		}
		input RoleFilterInput {
			name: String
		}
		type RoleList {
			items: [Role]
			pageInfo: PageInfo
		}
		type PageInfo { next: String total: Int }
	`
	cfg := Config{
		Scalars: map[string]string{"AWSDateTime": "string"},
	}
	res := ResourceConfig{
		File:     "role.go",
		TypeName: "Role",
		Fields:   []string{"id", "name", "description", "created"},
		Operations: []OperationConfig{
			{Name: "GetRole", GQLName: "getRole", Kind: "get"},
			{Name: "CreateRole", GQLName: "createRole", Kind: "create", InputType: "RoleInput"},
			{Name: "UpdateRole", GQLName: "updateRole", Kind: "update", InputType: "RoleInput"},
			{Name: "DeleteRole", GQLName: "deleteRole", Kind: "delete"},
			{
				Name: "ListRoles", GQLName: "listRoles", Kind: "list",
				Pagination: true,
				PaginationVars: map[string]any{
					"pageSize": float64(100),
					"filter":   map[string]any{},
				},
			},
		},
	}
	got := renderResource(t, cfg, res, sdl)
	assertGolden(t, filepath.Join("testdata", "role.go.golden"), got)
}

// TestGolden_DashboardLike exercises the trickier kinds added in the recent
// generator expansion: list_items with optional inline args, singleton_get
// with gqlVars + fieldArgs + extraVarValues (GetCount), singleton_get with
// resultPathLeaf (GetComputerCount), nullableResponseFields, extraResponseTypes,
// nestedTypes for non-main types, and NoMainFragment auto-suppression.
func TestGolden_DashboardLike(t *testing.T) {
	sdl := `
		type Query {
			getMiniCount(input: MiniCountInput): MiniCount
			getMiniComputerCount: MiniComputerCount
			listMiniRiskies(input: MiniRiskyInput): MiniRiskyConnection
		}
		input MiniCountInput { computers: MiniFilterInput }
		input MiniFilterInput { or: [MiniFilterInput] }
		input MiniRiskyInput { limit: Int, createdInterval: String }
		type MiniCount { computers: Int alerts: Int }
		type MiniComputerCount { computers: Int }
		type MiniRiskyConnection { items: [MiniRisky] }
		type MiniRisky { computer: MiniComputer alertCounts: [MiniAlertCount] }
		type MiniComputer { uuid: ID! hostName: String }
		type MiniAlertCount { severity: String count: Int }
	`
	cfg := Config{}
	res := ResourceConfig{
		File:                   "mini_dashboard.go",
		TypeName:               "MiniCount",
		Fields:                 []string{"computers", "alerts"},
		NullableResponseFields: []string{"computers", "alerts"},
		NestedTypes: []NestedTypeConfig{
			{SchemaName: "MiniComputer", GoName: "MiniRiskyRef", Fields: []string{"uuid", "hostName"}},
			{SchemaName: "MiniAlertCount", GoName: "MiniRiskyAlerts", Fields: []string{"severity", "count"}},
		},
		ExtraResponseTypes: []ExtraResponseType{
			{GoName: "MiniRisky", SchemaName: "MiniRisky", Fields: []string{"computer", "alertCounts"}},
			{GoName: "MiniRiskyRef", SchemaName: "MiniComputer", Fields: []string{"uuid", "hostName"}},
			{GoName: "MiniRiskyAlerts", SchemaName: "MiniAlertCount", Fields: []string{"severity", "count"}},
		},
		Operations: []OperationConfig{
			{
				Name: "GetMiniCount", GQLName: "getMiniCount", Kind: "singleton_get",
				ResultKey: "getMiniCount", NoFragment: true,
				InlineFields: []string{"computers", "alerts"},
				GQLVars:      map[string]string{"input": "MiniCountInput"},
				FieldArgs:    "input: $input",
				ExtraVarValues: map[string]any{
					"input": map[string]any{
						"computers": map[string]any{"or": []any{}},
					},
				},
				ReturnNullable: new(false),
			},
			{
				Name: "GetMiniComputerCount", GQLName: "getMiniComputerCount", Kind: "singleton_get",
				ResultKey:  "getMiniComputerCount",
				ReturnType: "int64", ReturnNullable: new(false),
				ResultPath: "getMiniComputerCount.computers", ResultPathLeaf: true, NoFragment: true,
			},
			{
				Name: "ListMiniRiskies", GQLName: "listMiniRiskies", Kind: "list_items",
				ResultKey: "listMiniRiskies", ReturnType: "MiniRisky", NoFragment: true,
				InlineArgs: []InlineArg{
					{Name: "limit", GoType: "int", GQLVar: "limit", GQLType: "Int", IsOptional: true},
					{Name: "createdInterval", GoType: "string", GQLVar: "createdInterval", GQLType: "String", IsOptional: true},
				},
			},
		},
	}
	got := renderResource(t, cfg, res, sdl)
	assertGolden(t, filepath.Join("testdata", "mini_dashboard.go.golden"), got)
}
