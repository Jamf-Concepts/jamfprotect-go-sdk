// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"sort"
	"strings"
)

func buildMapLit(m map[string]any) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%q: %s", k, formatGoLiteral(m[k])))
	}
	return "map[string]any{" + strings.Join(parts, ", ") + "}"
}

// mergeVarsExpr builds a Go expression that produces a vars map from base literal, optional

func mergeVarsExpr(baseLit, extraVarLit, rbacMap string) string {
	args := []string{baseLit}
	if extraVarLit != "" {
		args = append(args, extraVarLit)
	}
	if rbacMap != "" {
		args = append(args, rbacMap)
	}
	if len(args) == 1 {
		return "vars := " + args[0]
	}
	return "vars := mergeVars(" + strings.Join(args, ", ") + ")"
}

func inlineArgZeroCheck(a InlineArg) string {
	switch a.GoType {
	case "bool":
		return a.Name
	case "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64", "float32", "float64":
		return a.Name + " > 0"
	}
	if strings.HasPrefix(a.GoType, "*") || strings.HasPrefix(a.GoType, "[]") {
		return a.Name + " != nil"
	}
	return a.Name + ` != ""`
}

func primitiveZeroExpr(t string) string {
	switch t {
	case "int64", "int32", "int", "int16", "int8", "uint64", "uint32", "uint":
		return "0"
	case "float64", "float32":
		return "0"
	case "bool":
		return "false"
	case "string":
		return `""`
	default:
		return t + "{}"
	}
}

func formatGoLiteral(v any) string {
	if v == nil {
		return "nil"
	}
	switch val := v.(type) {
	case float64:
		if val == float64(int64(val)) {
			return fmt.Sprintf("%d", int64(val))
		}
		return fmt.Sprintf("%g", val)
	case string:
		return fmt.Sprintf("%q", val)
	case bool:
		return fmt.Sprintf("%t", val)
	case map[string]any:
		if len(val) == 0 {
			return "map[string]any{}"
		}
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%q: %s", k, formatGoLiteral(val[k])))
		}
		return "map[string]any{" + strings.Join(parts, ", ") + "}"
	case []any:
		parts := make([]string, len(val))
		for i, elem := range val {
			parts[i] = formatGoLiteral(elem)
		}
		return "[]any{" + strings.Join(parts, ", ") + "}"
	default:
		return fmt.Sprintf("%v", val)
	}
}

// buildUnionMergedStruct builds a merged flat IRStruct from a GraphQL interface type's common
// fields plus all variant-specific fields listed in uf. Returns the struct and a slice of

// sortedStringKeys returns the keys of a map[string][]string in sorted order.
func sortedStringKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// zeroVal returns the correct Go zero-value expression for a return type.
func zeroVal(t string) string {
	if strings.HasPrefix(t, "*") || strings.HasPrefix(t, "[]") {
		return "nil"
	}
	return t + "{}"
}
