// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"os"
	"strings"
	"unicode"

	"github.com/vektah/gqlparser/v2"
	"github.com/vektah/gqlparser/v2/ast"
)

// scalarPreamble declares AppSync custom scalars that gqlparser requires to be
// explicitly defined even though they are built-in to AppSync itself.
const scalarPreamble = `
scalar AWSDateTime
scalar AWSJSON
scalar AWSEmail
scalar AWSIPAddress
scalar AWSPhone
scalar AWSURL
scalar AWSDate
scalar AWSTimestamp
scalar Long
`

func loadSchema(path string) (*ast.Schema, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read schema: %w", err)
	}
	schema, parseErr := gqlparser.LoadSchema(
		&ast.Source{Name: "scalars", Input: scalarPreamble},
		&ast.Source{Name: path, Input: string(data)},
	)
	if parseErr != nil {
		return nil, fmt.Errorf("parse schema: %v", parseErr)
	}
	return schema, nil
}

// goInitialisms are Go naming conventions applied by toPascalCase.
var goInitialisms = map[string]bool{
	"id": true, "url": true, "uri": true, "http": true, "https": true,
	"api": true, "json": true, "xml": true, "sql": true, "uuid": true, "html": true,
}

// toPascalCase converts a camelCase identifier to Go PascalCase,
// applying standard Go initialisms (e.g. id → ID).
func toPascalCase(s string) string {
	if s == "" {
		return ""
	}
	words := splitCamelWords(s)
	var b strings.Builder
	for _, w := range words {
		lower := strings.ToLower(w)
		if goInitialisms[lower] {
			b.WriteString(strings.ToUpper(w))
		} else {
			b.WriteRune(unicode.ToUpper(rune(w[0])))
			b.WriteString(w[1:])
		}
	}
	return b.String()
}

// lcFirst returns s with the first rune lowercased.
func lcFirst(s string) string {
	if s == "" {
		return ""
	}
	r := []rune(s)
	r[0] = unicode.ToLower(r[0])
	return string(r)
}

// splitCamelWords splits a camelCase string into words at lower→upper case transitions.
func splitCamelWords(s string) []string {
	var words []string
	var cur strings.Builder
	runes := []rune(s)
	for i, r := range runes {
		if i > 0 && unicode.IsUpper(r) && !unicode.IsUpper(runes[i-1]) {
			if cur.Len() > 0 {
				words = append(words, cur.String())
				cur.Reset()
			}
		}
		cur.WriteRune(r)
	}
	if cur.Len() > 0 {
		words = append(words, cur.String())
	}
	return words
}

// baseTypeName extracts the named type from a potentially list/non-null type wrapper.
func baseTypeName(t *ast.Type) string {
	if t.Elem != nil {
		return t.Elem.NamedType
	}
	return t.NamedType
}

// resolveGoType maps a GraphQL type to its Go equivalent for response struct fields.
// Nullability is ignored — struct fields are always value types.
func resolveGoType(t *ast.Type, schema *ast.Schema, scalars map[string]string, nestedOverrides map[string]string) string {
	if t.Elem != nil {
		return "[]" + resolveNamedGoType(t.Elem.NamedType, schema, scalars, nestedOverrides)
	}
	return resolveNamedGoType(t.NamedType, schema, scalars, nestedOverrides)
}

// resolveInputGoType maps a GraphQL type to its Go equivalent for input struct fields.
func resolveInputGoType(t *ast.Type, schema *ast.Schema, scalars map[string]string) string {
	if t.Elem != nil {
		return "[]" + resolveInputNamedGoType(t.Elem.NamedType, schema, scalars)
	}
	return resolveInputNamedGoType(t.NamedType, schema, scalars)
}

func resolveNamedGoType(name string, schema *ast.Schema, scalars map[string]string, nestedOverrides map[string]string) string {
	if mapped, ok := scalars[name]; ok {
		return mapped
	}
	if override, ok := nestedOverrides[name]; ok {
		return override
	}
	if def := schema.Types[name]; def != nil && def.Kind == ast.Enum {
		return "string"
	}
	switch name {
	case "String", "ID":
		return "string"
	case "Int":
		return "int64"
	case "Float":
		return "float64"
	case "Boolean":
		return "bool"
	}
	return toPascalCase(name)
}

func resolveInputNamedGoType(name string, schema *ast.Schema, scalars map[string]string) string {
	if mapped, ok := scalars[name]; ok {
		return mapped
	}
	if def := schema.Types[name]; def != nil && def.Kind == ast.Enum {
		return "string"
	}
	switch name {
	case "String", "ID":
		return "string"
	case "Int":
		return "int64"
	case "Float":
		return "float64"
	case "Boolean":
		return "bool"
	}
	return toPascalCase(name)
}

// inputNode is a node in a flattened GraphQL input type tree.
// Leaves hold variable declarations; branches hold nested input objects.
type inputNode struct {
	GQLField string
	VarName  string      // non-empty for leaves only
	TypeStr  string      // GQL type string for leaves only
	Children []inputNode // non-empty for branches only
}

func (n inputNode) isLeaf() bool { return len(n.Children) == 0 }

// buildInputTree flattens a GraphQL input type into an inputNode tree.
// The cursor field "next" is renamed to "nextToken" to match client.ListAll expectations.
// opaqueFields lists top-level fields that should be treated as leaf variables even when
// they are InputObject types (e.g. a filter arg passed as a whole object).
func buildInputTree(schema *ast.Schema, typeName string, opaqueFields map[string]bool) ([]inputNode, error) {
	def := schema.Types[typeName]
	if def == nil {
		return nil, fmt.Errorf("input type %q not found in schema", typeName)
	}
	visited := map[string]bool{typeName: true}
	return inputNodesFromDef(schema, def, opaqueFields, visited), nil
}

// inputNodesFromDef recursively builds inputNode trees.
// visited prevents infinite recursion on self-referential input types.
// opaqueFields only applies at the top level; nested expansions use nil.
func inputNodesFromDef(schema *ast.Schema, def *ast.Definition, opaqueFields map[string]bool, visited map[string]bool) []inputNode {
	var nodes []inputNode
	for _, f := range def.Fields {
		base := baseTypeName(f.Type)
		childDef := schema.Types[base]
		isInputObj := childDef != nil && childDef.Kind == ast.InputObject
		if isInputObj && !opaqueFields[f.Name] && !visited[base] {
			visited[base] = true
			nodes = append(nodes, inputNode{
				GQLField: f.Name,
				Children: inputNodesFromDef(schema, childDef, nil, visited),
			})
			delete(visited, base)
		} else {
			varName := f.Name
			if varName == "next" {
				varName = "nextToken"
			}
			nodes = append(nodes, inputNode{
				GQLField: f.Name,
				VarName:  varName,
				TypeStr:  f.Type.String(),
			})
		}
	}
	return nodes
}

// leafVars returns all leaf inputNodes (variable declarations) in DFS order.
func leafVars(nodes []inputNode) []inputNode {
	var leaves []inputNode
	for _, n := range nodes {
		if n.isLeaf() {
			leaves = append(leaves, n)
		} else {
			leaves = append(leaves, leafVars(n.Children)...)
		}
	}
	return leaves
}

// buildConstructorStr builds an inline GraphQL input object constructor, e.g.:
// {next: $nextToken, order: {direction: $direction, field: $field}, pageSize: $pageSize}
func buildConstructorStr(nodes []inputNode) string {
	parts := make([]string, 0, len(nodes))
	for _, n := range nodes {
		if n.isLeaf() {
			parts = append(parts, n.GQLField+": $"+n.VarName)
		} else {
			parts = append(parts, n.GQLField+": "+buildConstructorStr(n.Children))
		}
	}
	return "{" + strings.Join(parts, ", ") + "}"
}
