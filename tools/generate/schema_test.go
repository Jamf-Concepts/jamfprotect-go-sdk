// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package main

import (
	"testing"

	"github.com/vektah/gqlparser/v2"
	"github.com/vektah/gqlparser/v2/ast"
)

func TestToPascalCase(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"id", "ID"},
		{"userId", "UserID"},
		{"computerIds", "ComputerIDs"},
		{"apiClient", "APIClient"},
		{"httpUrl", "HTTPURL"},
		{"jsonRpcUrl", "JSONRpcURL"},
		{"role", "Role"},
		{"role_name", "RoleName"},
		{"NGTP_BETA", "NGTPBETA"},
		{"pppcEnabled", "PPPCEnabled"},
		{"certId", "CertID"},
		{"uuids", "UUIDs"},
		{"ips", "IPs"},
		{"osVersion", "OSVersion"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			if got := toPascalCase(c.in); got != c.want {
				t.Errorf("toPascalCase(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestLcFirst(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"Role", "role"},
		{"RoleInput", "roleInput"},
		{"A", "a"},
	}
	for _, c := range cases {
		if got := lcFirst(c.in); got != c.want {
			t.Errorf("lcFirst(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSplitCamelWords(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"camelCase", []string{"camel", "Case"}},
		{"snake_case", []string{"snake", "case"}},
		{"mixedCase_words", []string{"mixed", "Case", "words"}},
		{"ALL_CAPS", []string{"ALL", "CAPS"}},
		{"id", []string{"id"}},
		{"", nil},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got := splitCamelWords(c.in)
			if len(got) != len(c.want) {
				t.Fatalf("splitCamelWords(%q) = %v, want %v", c.in, got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("splitCamelWords(%q)[%d] = %q, want %q", c.in, i, got[i], c.want[i])
				}
			}
		})
	}
}

func loadTestSchema(t *testing.T, sdl string) *ast.Schema {
	t.Helper()
	schema, err := gqlparser.LoadSchema(
		&ast.Source{Name: "scalars", Input: scalarPreamble},
		&ast.Source{Name: "test", Input: sdl},
	)
	if err != nil {
		t.Fatalf("load test schema: %v", err)
	}
	return schema
}

func TestResolveGoType(t *testing.T) {
	schema := loadTestSchema(t, `
		type Query { _empty: String }
		type Role { id: ID! name: String }
		type Computer { id: ID! }
	`)
	scalars := map[string]string{"AWSDateTime": "string"}

	cases := []struct {
		name      string
		fieldType *ast.Type
		overrides map[string]string
		want      string
	}{
		{"nonnull ID", &ast.Type{NamedType: "ID", NonNull: true}, nil, "string"},
		{"nullable String", &ast.Type{NamedType: "String"}, nil, "string"},
		{"nullable Object → pointer", &ast.Type{NamedType: "Role"}, nil, "*Role"},
		{"nonnull Object → value", &ast.Type{NamedType: "Role", NonNull: true}, nil, "Role"},
		{"list of Object", &ast.Type{Elem: &ast.Type{NamedType: "Role"}}, nil, "[]Role"},
		{"nested override", &ast.Type{NamedType: "Computer"}, map[string]string{"Computer": "AlertComputer"}, "*AlertComputer"},
		{"scalar mapping", &ast.Type{NamedType: "AWSDateTime"}, nil, "string"},
		{"Int", &ast.Type{NamedType: "Int", NonNull: true}, nil, "int64"},
		{"Boolean", &ast.Type{NamedType: "Boolean", NonNull: true}, nil, "bool"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := resolveGoType(c.fieldType, schema, scalars, c.overrides)
			if got != c.want {
				t.Errorf("resolveGoType = %q, want %q", got, c.want)
			}
		})
	}
}

func TestResolveInputGoType(t *testing.T) {
	schema := loadTestSchema(t, `
		type Query { _empty: String }
		input Order { field: String! direction: String! }
	`)
	scalars := map[string]string{}

	cases := []struct {
		name      string
		fieldType *ast.Type
		want      string
	}{
		{"nullable InputObject → value", &ast.Type{NamedType: "Order"}, "Order"},
		{"nonnull InputObject → value", &ast.Type{NamedType: "Order", NonNull: true}, "Order"},
		{"list of String", &ast.Type{Elem: &ast.Type{NamedType: "String"}}, "[]string"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := resolveInputGoType(c.fieldType, schema, scalars)
			if got != c.want {
				t.Errorf("resolveInputGoType = %q, want %q", got, c.want)
			}
		})
	}
}

func TestBuildInputTreeRenamesNext(t *testing.T) {
	schema := loadTestSchema(t, `
		type Query { _empty: String }
		input ListRolesInput {
			next: String
			pageSize: Int
			order: OrderInput
		}
		input OrderInput { direction: String! field: String! }
	`)
	nodes, err := buildInputTree(schema, "ListRolesInput", nil)
	if err != nil {
		t.Fatalf("buildInputTree: %v", err)
	}
	leaves := leafVars(nodes)
	var sawNextToken bool
	for _, l := range leaves {
		if l.GQLField == "next" {
			if l.VarName != "nextToken" {
				t.Errorf("expected next → nextToken rename, got %q", l.VarName)
			}
			sawNextToken = true
		}
	}
	if !sawNextToken {
		t.Errorf("did not find next field in leaves")
	}
}

func TestBuildInputTreeOpaqueField(t *testing.T) {
	schema := loadTestSchema(t, `
		type Query { _empty: String }
		input FilterInput { kind: String! }
		input WrapInput { filter: FilterInput pageSize: Int }
	`)
	nodes, err := buildInputTree(schema, "WrapInput", map[string]bool{"filter": true})
	if err != nil {
		t.Fatalf("buildInputTree: %v", err)
	}
	leaves := leafVars(nodes)
	if len(leaves) != 2 {
		t.Fatalf("expected 2 leaves with opaque filter, got %d: %+v", len(leaves), leaves)
	}
	var sawFilterLeaf bool
	for _, l := range leaves {
		if l.GQLField == "filter" {
			sawFilterLeaf = true
		}
	}
	if !sawFilterLeaf {
		t.Errorf("filter should be a leaf when opaque")
	}
}

func TestBuildConstructorStr(t *testing.T) {
	nodes := []inputNode{
		{GQLField: "next", VarName: "nextToken"},
		{GQLField: "order", Children: []inputNode{
			{GQLField: "direction", VarName: "direction"},
			{GQLField: "field", VarName: "field"},
		}},
		{GQLField: "pageSize", VarName: "pageSize"},
	}
	got := buildConstructorStr(nodes)
	want := "{next: $nextToken, order: {direction: $direction, field: $field}, pageSize: $pageSize}"
	if got != want {
		t.Errorf("buildConstructorStr =\n  %q\nwant\n  %q", got, want)
	}
}
