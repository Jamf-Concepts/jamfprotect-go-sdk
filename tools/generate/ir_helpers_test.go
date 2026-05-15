// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package main

import "testing"

func TestFormatGoLiteral(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"nil", nil, "nil"},
		{"string", "hello", `"hello"`},
		{"string with quote", `he said "hi"`, `"he said \"hi\""`},
		{"true", true, "true"},
		{"false", false, "false"},
		{"int-valued float", float64(42), "42"},
		{"int-valued float negative", float64(-7), "-7"},
		{"true float", 1.5, "1.5"},
		{"empty map", map[string]any{}, "map[string]any{}"},
		{"empty slice", []any{}, "[]any{}"},
		{"single-key map", map[string]any{"a": "x"}, `map[string]any{"a": "x"}`},
		{
			"multi-key map sorted",
			map[string]any{"b": 1.0, "a": 2.0, "c": 3.0},
			`map[string]any{"a": 2, "b": 1, "c": 3}`,
		},
		{
			"slice of scalars",
			[]any{"a", "b", float64(3)},
			`[]any{"a", "b", 3}`,
		},
		{
			"nested map — match-all filter literal",
			map[string]any{"or": []any{}},
			`map[string]any{"or": []any{}}`,
		},
		{
			"deeply nested map",
			map[string]any{
				"input": map[string]any{
					"computers": map[string]any{"or": []any{}},
					"alerts":    map[string]any{"or": []any{}},
				},
			},
			`map[string]any{"input": map[string]any{"alerts": map[string]any{"or": []any{}}, "computers": map[string]any{"or": []any{}}}}`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := formatGoLiteral(c.in)
			if got != c.want {
				t.Errorf("formatGoLiteral(%v):\n got  %s\n want %s", c.in, got, c.want)
			}
		})
	}
}

func TestFormatGoLiteralDeterministic(t *testing.T) {
	// Map iteration order is random in Go; formatGoLiteral must sort keys.
	in := map[string]any{
		"z": 1.0, "y": 2.0, "x": 3.0, "w": 4.0,
		"v": 5.0, "u": 6.0, "t": 7.0, "s": 8.0,
	}
	first := formatGoLiteral(in)
	for i := 0; i < 50; i++ {
		if got := formatGoLiteral(in); got != first {
			t.Fatalf("non-deterministic output:\n run 1: %s\n run %d: %s", first, i+2, got)
		}
	}
}

func TestPrimitiveZeroExpr(t *testing.T) {
	cases := []struct {
		t, want string
	}{
		{"int", "0"},
		{"int64", "0"},
		{"float64", "0"},
		{"bool", "false"},
		{"string", `""`},
		{"Role", "Role{}"},
		{"CountResponse", "CountResponse{}"},
	}
	for _, c := range cases {
		if got := primitiveZeroExpr(c.t); got != c.want {
			t.Errorf("primitiveZeroExpr(%q) = %q, want %q", c.t, got, c.want)
		}
	}
}

func TestZeroVal(t *testing.T) {
	cases := []struct {
		t, want string
	}{
		{"int64", "int64{}"}, // zeroVal does NOT special-case scalars; that's primitiveZeroExpr.
		{"*Role", "nil"},
		{"[]Role", "nil"},
		{"Role", "Role{}"},
	}
	for _, c := range cases {
		if got := zeroVal(c.t); got != c.want {
			t.Errorf("zeroVal(%q) = %q, want %q", c.t, got, c.want)
		}
	}
}

func TestInlineArgZeroCheck(t *testing.T) {
	cases := []struct {
		name string
		arg  InlineArg
		want string
	}{
		{"bool", InlineArg{Name: "enabled", GoType: "bool"}, "enabled"},
		{"int", InlineArg{Name: "limit", GoType: "int"}, "limit > 0"},
		{"int64", InlineArg{Name: "size", GoType: "int64"}, "size > 0"},
		{"float64", InlineArg{Name: "ratio", GoType: "float64"}, "ratio > 0"},
		{"pointer", InlineArg{Name: "opts", GoType: "*Options"}, "opts != nil"},
		{"slice", InlineArg{Name: "ids", GoType: "[]string"}, "ids != nil"},
		{"string", InlineArg{Name: "name", GoType: "string"}, `name != ""`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := inlineArgZeroCheck(c.arg); got != c.want {
				t.Errorf("inlineArgZeroCheck(%+v) = %q, want %q", c.arg, got, c.want)
			}
		})
	}
}

func TestBuildMapLit(t *testing.T) {
	cases := []struct {
		name string
		in   map[string]any
		want string
	}{
		{"empty returns empty string", map[string]any{}, ""},
		{"single key", map[string]any{"a": "x"}, `map[string]any{"a": "x"}`},
		{
			"sorted multi-key",
			map[string]any{"b": "y", "a": "x"},
			`map[string]any{"a": "x", "b": "y"}`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := buildMapLit(c.in); got != c.want {
				t.Errorf("buildMapLit = %q, want %q", got, c.want)
			}
		})
	}
}

func TestMergeVarsExpr(t *testing.T) {
	cases := []struct {
		name                          string
		baseLit, extraVarLit, rbacMap string
		want                          string
	}{
		{
			"base only",
			"map[string]any{\"id\": id}", "", "",
			"vars := map[string]any{\"id\": id}",
		},
		{
			"base + extra",
			"map[string]any{\"id\": id}", "map[string]any{\"k\": \"v\"}", "",
			"vars := mergeVars(map[string]any{\"id\": id}, map[string]any{\"k\": \"v\"})",
		},
		{
			"base + rbac",
			"map[string]any{\"id\": id}", "", "rbacRole",
			"vars := mergeVars(map[string]any{\"id\": id}, rbacRole)",
		},
		{
			"base + extra + rbac",
			"map[string]any{\"id\": id}", "map[string]any{\"k\": \"v\"}", "rbacRole",
			"vars := mergeVars(map[string]any{\"id\": id}, map[string]any{\"k\": \"v\"}, rbacRole)",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := mergeVarsExpr(c.baseLit, c.extraVarLit, c.rbacMap); got != c.want {
				t.Errorf("mergeVarsExpr = %q, want %q", got, c.want)
			}
		})
	}
}
