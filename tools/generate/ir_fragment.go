// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
)

func buildFragment(schema *ast.Schema, res ResourceConfig, nestedFieldLists map[string][]string, nestedDirectives map[string]map[string]string, pathOverrides map[string]NestedTypeConfig) (string, error) {
	schemaTypeName := res.SchemaTypeName()
	def := schema.Types[schemaTypeName]
	if def == nil {
		return "", fmt.Errorf("type %q not found in schema", schemaTypeName)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\nfragment %sFields on %s {\n", res.TypeName, schemaTypeName)
	for _, fieldName := range res.Fields {
		f := def.Fields.ForName(fieldName)
		if f == nil {
			return "", fmt.Errorf("field %q not on type %s", fieldName, schemaTypeName)
		}
		base := baseTypeName(f.Type)
		fieldDef := schema.Types[base]
		directive := res.DirectiveFields[fieldName]

		// Interface and union fields with explicit union config emit inline fragments.
		if fieldDef != nil && (fieldDef.Kind == ast.Interface || fieldDef.Kind == ast.Union) {
			if uf, ok := res.UnionFields[fieldName]; ok {
				b.WriteString("\t" + fieldName + " {\n")
				for _, cf := range uf.Common {
					b.WriteString("\t\t" + cf + "\n")
				}
				for _, typeName := range sortedStringKeys(uf.Variants) {
					b.WriteString("\t\t... on " + typeName + " {\n")
					writeFragmentSubFields(schema, typeName, uf.Variants[typeName], nil, nestedFieldLists, nestedDirectives, pathOverrides, fieldName, 3, &b, res.UnionFields)
					b.WriteString("\t\t}\n")
				}
				b.WriteString("\t}\n")
				continue
			}
		}

		if fieldDef != nil && (fieldDef.Kind == ast.Object || fieldDef.Kind == ast.Interface) {
			if directive != "" {
				b.WriteString("\t" + fieldName + " " + directive + " {\n")
			} else {
				b.WriteString("\t" + fieldName + " {\n")
			}
			// Resolve sub-fields for this nested type: check path override first, then schema-name fallback.
			subFields := nestedFieldLists[base]
			subDirectives := nestedDirectives[base]
			if override, ok := pathOverrides[fieldName]; ok {
				if len(override.Fields) > 0 {
					subFields = override.Fields
				}
				if len(override.DirectiveFields) > 0 {
					subDirectives = override.DirectiveFields
				}
			}
			writeFragmentSubFields(schema, base, subFields, subDirectives, nestedFieldLists, nestedDirectives, pathOverrides, fieldName, 2, &b, res.UnionFields)
			b.WriteString("\t}\n")
		} else {
			if directive != "" {
				b.WriteString("\t" + fieldName + " " + directive + "\n")
			} else {
				b.WriteString("\t" + fieldName + "\n")
			}
		}
	}
	b.WriteString("}\n")
	return b.String(), nil
}

// writeFragmentSubFields recursively writes field selections for a schema type at the
// given indentation depth. Object sub-fields are expanded using nestedFieldLists.
// Union/interface fields with a matching entry in unionFields emit inline fragments.
// currentPath tracks the dot-path from the main type root, enabling path-based overrides.
func writeFragmentSubFields(schema *ast.Schema, typeName string, allowedFields []string, directives map[string]string, nestedFieldLists map[string][]string, nestedDirectives map[string]map[string]string, pathOverrides map[string]NestedTypeConfig, currentPath string, depth int, b *strings.Builder, unionFields map[string]UnionFieldConfig) {
	def := schema.Types[typeName]
	if def == nil {
		return
	}
	indent := strings.Repeat("\t", depth)

	var fieldNames []string
	if len(allowedFields) > 0 {
		fieldNames = allowedFields
	} else {
		for _, f := range def.Fields {
			fieldNames = append(fieldNames, f.Name)
		}
	}

	for _, fieldName := range fieldNames {
		f := def.Fields.ForName(fieldName)
		if f == nil {
			continue
		}
		base := baseTypeName(f.Type)
		fieldDef := schema.Types[base]
		directive := directives[fieldName]
		childPath := currentPath + "." + fieldName

		// Interface and union fields with union config emit inline fragments.
		if fieldDef != nil && (fieldDef.Kind == ast.Interface || fieldDef.Kind == ast.Union) {
			if uf, ok := unionFields[fieldName]; ok {
				fmt.Fprintf(b, "%s%s {\n", indent, fieldName)
				for _, cf := range uf.Common {
					fmt.Fprintf(b, "%s\t%s\n", indent, cf)
				}
				for _, variantName := range sortedStringKeys(uf.Variants) {
					fmt.Fprintf(b, "%s\t... on %s {\n", indent, variantName)
					writeFragmentSubFields(schema, variantName, uf.Variants[variantName], nil, nestedFieldLists, nestedDirectives, pathOverrides, childPath, depth+2, b, unionFields)
					fmt.Fprintf(b, "%s\t}\n", indent)
				}
				fmt.Fprintf(b, "%s}\n", indent)
				continue
			}
		}

		if fieldDef != nil && (fieldDef.Kind == ast.Object || fieldDef.Kind == ast.Interface) {
			if directive != "" {
				fmt.Fprintf(b, "%s%s %s {\n", indent, fieldName, directive)
			} else {
				fmt.Fprintf(b, "%s%s {\n", indent, fieldName)
			}
			subFields := nestedFieldLists[base]
			subDirectives := nestedDirectives[base]
			if override, ok := pathOverrides[childPath]; ok {
				if len(override.Fields) > 0 {
					subFields = override.Fields
				}
				if len(override.DirectiveFields) > 0 {
					subDirectives = override.DirectiveFields
				}
			}
			writeFragmentSubFields(schema, base, subFields, subDirectives, nestedFieldLists, nestedDirectives, pathOverrides, childPath, depth+1, b, unionFields)
			fmt.Fprintf(b, "%s}\n", indent)
		} else {
			if directive != "" {
				fmt.Fprintf(b, "%s%s %s\n", indent, fieldName, directive)
			} else {
				fmt.Fprintf(b, "%s%s\n", indent, fieldName)
			}
		}
	}
}
