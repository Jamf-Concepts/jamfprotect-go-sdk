// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
)

func buildResponseTypes(schema *ast.Schema, res ResourceConfig, nestedGoNames map[string]string, nestedFieldRenames map[string]map[string]string, nestedFieldLists map[string][]string, nestedNullableFields map[string]map[string]bool, nullableResponseFields map[string]bool, pathOverrides map[string]NestedTypeConfig, scalars map[string]string) (IRStruct, []IRStruct, error) {
	schemaTypeName := res.SchemaTypeName()
	def := schema.Types[schemaTypeName]
	if def == nil {
		return IRStruct{}, nil, fmt.Errorf("type %q not found in schema", schemaTypeName)
	}

	seenNested := make(map[string]bool)
	seenNested[schemaTypeName] = true // prevent the main type from being generated as nested

	seenPaths := make(map[string]bool)

	// Seed the BFS queue with Object fields of the main type.
	// pathPrefix is the dot-path from the root used to look up path-overrides; it's
	// always carried forward even when there's no override.
	type queueItem struct {
		schemaName, goName string
		pathPrefix         string
		usingPathOverride  bool // true when this queue item was enqueued because of a path override
	}
	var queue []queueItem
	var mainFields []IRField
	var nestedTypes []IRStruct

	for _, fieldName := range res.Fields {
		f := def.Fields.ForName(fieldName)
		if f == nil {
			return IRStruct{}, nil, fmt.Errorf("field %q not on type %s", fieldName, schemaTypeName)
		}
		base := baseTypeName(f.Type)
		fieldDef := schema.Types[base]

		// Interface and union fields with explicit union config build a merged flat struct.
		if fieldDef != nil && (fieldDef.Kind == ast.Interface || fieldDef.Kind == ast.Union) {
			if uf, ok := res.UnionFields[fieldName]; ok {
				var unionGoType string
				if f.Type.Elem != nil {
					unionGoType = "[]" + uf.GoStruct
				} else {
					unionGoType = uf.GoStruct
				}
				if nullableResponseFields[fieldName] {
					unionGoType = ensurePointer(unionGoType)
				}
				mainFields = append(mainFields, IRField{
					Name:    toPascalCase(fieldName),
					JSONTag: fieldName,
					Type:    unionGoType,
				})
				if !seenNested[base] {
					seenNested[base] = true
					mergedStruct, subObjectBases, mergeErr := buildUnionMergedStruct(schema, fieldDef, uf, scalars, nestedGoNames)
					if mergeErr != nil {
						return IRStruct{}, nil, fmt.Errorf("union field %q: %w", fieldName, mergeErr)
					}
					nestedTypes = append(nestedTypes, mergedStruct)
					for _, subBase := range subObjectBases {
						if seenNested[subBase] {
							continue
						}
						seenNested[subBase] = true
						subGoName := subBase
						if o, ok := nestedGoNames[subBase]; ok {
							subGoName = o
						}
						queue = append(queue, queueItem{subBase, subGoName, fieldName + "." + subBase, false})
					}
				}
				continue
			}
		}

		// Check for path-based override first.
		var goType string
		if override, ok := pathOverrides[fieldName]; ok {
			goType = wrapTypeForPathOverride(f.Type, override.GoName)
		} else {
			goType = resolveGoType(f.Type, schema, scalars, nestedGoNames)
		}
		if nullableResponseFields[fieldName] {
			goType = ensurePointer(goType)
		}
		mainFields = append(mainFields, IRField{
			Name:    toPascalCase(fieldName),
			JSONTag: fieldName,
			Type:    goType,
		})

		if fieldDef != nil && (fieldDef.Kind == ast.Object || fieldDef.Kind == ast.Interface) {
			if override, ok := pathOverrides[fieldName]; ok {
				if !seenPaths[fieldName] {
					seenPaths[fieldName] = true
					queue = append(queue, queueItem{base, override.GoName, fieldName, true})
				}
			} else if !seenNested[base] {
				seenNested[base] = true
				goTypeName := base
				if o, ok := nestedGoNames[base]; ok {
					goTypeName = o
				}
				queue = append(queue, queueItem{base, goTypeName, fieldName, false})
			}
		}
	}

	seenGoNames := make(map[string]bool)

	// BFS: generate each nested struct and enqueue its own Object sub-fields.
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		// Skip duplicate generation when multiple schema types share a Go name.
		if seenGoNames[item.goName] {
			continue
		}
		seenGoNames[item.goName] = true

		var fieldsList []string
		var renames map[string]string
		var nullable map[string]bool
		if item.usingPathOverride {
			if override, ok := pathOverrides[item.pathPrefix]; ok {
				fieldsList = override.Fields
				renames = override.FieldRenames
				if len(override.NullableFields) > 0 {
					nullable = make(map[string]bool)
					for _, nf := range override.NullableFields {
						nullable[nf] = true
					}
				}
			}
		} else {
			fieldsList = nestedFieldLists[item.schemaName]
			renames = nestedFieldRenames[item.schemaName]
			nullable = nestedNullableFields[item.schemaName]
		}
		ns, err := buildNestedStruct(schema, item.schemaName, item.goName, renames, fieldsList, nullable, scalars, nestedGoNames, pathOverrides, item.pathPrefix)
		if err != nil {
			return IRStruct{}, nil, err
		}
		nestedTypes = append(nestedTypes, ns)

		// Enqueue Object fields of this nested type (respecting its allowed field list).
		itemDef := schema.Types[item.schemaName]
		allowedSet := make(map[string]bool)
		for _, af := range fieldsList {
			allowedSet[af] = true
		}
		fieldOrder := fieldsList
		if len(fieldOrder) == 0 {
			for _, f := range itemDef.Fields {
				fieldOrder = append(fieldOrder, f.Name)
			}
		}
		for _, fName := range fieldOrder {
			subf := itemDef.Fields.ForName(fName)
			if subf == nil {
				continue
			}
			if len(allowedSet) > 0 && !allowedSet[subf.Name] {
				continue
			}
			base := baseTypeName(subf.Type)
			childDef := schema.Types[base]
			// Union fields with a union config generate a merged flat struct in-place.
			if childDef != nil && childDef.Kind == ast.Union {
				if uf, ok := res.UnionFields[fName]; ok && !seenNested[base] {
					seenNested[base] = true
					mergedStruct, subObjectBases, mergeErr := buildUnionMergedStruct(schema, childDef, uf, scalars, nestedGoNames)
					if mergeErr != nil {
						return IRStruct{}, nil, fmt.Errorf("union field %q in %s: %w", fName, item.schemaName, mergeErr)
					}
					nestedTypes = append(nestedTypes, mergedStruct)
					for _, subBase := range subObjectBases {
						if !seenNested[subBase] {
							seenNested[subBase] = true
							subGoName := subBase
							if o, ok := nestedGoNames[subBase]; ok {
								subGoName = o
							}
							queue = append(queue, queueItem{subBase, subGoName, item.pathPrefix + "." + subBase, false})
						}
					}
				}
				continue
			}
			if childDef == nil || (childDef.Kind != ast.Object && childDef.Kind != ast.Interface) {
				continue
			}
			childPath := item.pathPrefix + "." + subf.Name
			if override, ok := pathOverrides[childPath]; ok {
				if !seenPaths[childPath] {
					seenPaths[childPath] = true
					queue = append(queue, queueItem{base, override.GoName, childPath, true})
				}
				continue
			}
			if seenNested[base] {
				continue
			}
			seenNested[base] = true
			goTypeName := base
			if override, ok := nestedGoNames[base]; ok {
				goTypeName = override
			}
			queue = append(queue, queueItem{base, goTypeName, childPath, false})
		}
	}

	mainStruct := IRStruct{
		Comment: fmt.Sprintf("// %s represents a Jamf Protect %s.", res.TypeName, lcFirst(res.TypeName)),
		Name:    res.TypeName,
		Fields:  mainFields,
	}

	// Generate any extra response types defined in config (e.g. minimal list-item types).
	// These use GoName as the dedup key since the SchemaName may already be the main type.
	seenExtraGoNames := make(map[string]bool)
	for _, ert := range res.ExtraResponseTypes {
		if seenExtraGoNames[ert.GoName] {
			continue
		}
		seenExtraGoNames[ert.GoName] = true
		ns, err := buildNestedStruct(schema, ert.SchemaName, ert.GoName, nil, ert.Fields, nil, scalars, nestedGoNames, pathOverrides, "")
		if err != nil {
			return IRStruct{}, nil, fmt.Errorf("extra response type %q: %w", ert.GoName, err)
		}
		nestedTypes = append(nestedTypes, ns)
	}

	return mainStruct, nestedTypes, nil
}

// ensurePointer wraps a Go type in a pointer, unless it already is one or is a slice.
// Slices become *[]T (pointer to slice).
func ensurePointer(goType string) string {
	if strings.HasPrefix(goType, "*") {
		return goType
	}
	return "*" + goType
}

// wrapTypeForPathOverride takes a schema field type and an override Go type name and produces
// the Go type expression preserving list/nullability wrapping from the schema field.
func wrapTypeForPathOverride(t *ast.Type, overrideGoName string) string {
	if t.Elem != nil {
		return "[]" + overrideGoName
	}
	if !t.NonNull {
		return "*" + overrideGoName
	}
	return overrideGoName
}

func buildNestedStruct(schema *ast.Schema, schemaTypeName, goTypeName string, fieldRenames map[string]string, allowedFields []string, nullableFields map[string]bool, scalars map[string]string, nestedOverrides map[string]string, pathOverrides map[string]NestedTypeConfig, parentPath string) (IRStruct, error) {
	def := schema.Types[schemaTypeName]
	if def == nil {
		return IRStruct{}, fmt.Errorf("type %q not found in schema", schemaTypeName)
	}
	allowed := make(map[string]bool, len(allowedFields))
	for _, f := range allowedFields {
		allowed[f] = true
	}
	// Iterate in allowedFields order when provided, otherwise schema order.
	var iterNames []string
	if len(allowedFields) > 0 {
		iterNames = allowedFields
	} else {
		for _, f := range def.Fields {
			iterNames = append(iterNames, f.Name)
		}
	}
	var fields []IRField
	for _, fName := range iterNames {
		f := def.Fields.ForName(fName)
		if f == nil {
			continue
		}
		goName := toPascalCase(f.Name)
		if renamed, ok := fieldRenames[f.Name]; ok {
			goName = renamed
		}
		var fGoType string
		childPath := ""
		if parentPath != "" {
			childPath = parentPath + "." + f.Name
		}
		if childPath != "" {
			if override, ok := pathOverrides[childPath]; ok {
				fGoType = wrapTypeForPathOverride(f.Type, override.GoName)
			}
		}
		if fGoType == "" {
			fGoType = resolveGoType(f.Type, schema, scalars, nestedOverrides)
		}
		if nullableFields[f.Name] {
			fGoType = ensurePointer(fGoType)
		}
		fields = append(fields, IRField{
			Name:    goName,
			JSONTag: f.Name,
			Type:    fGoType,
		})
	}
	return IRStruct{
		Comment: fmt.Sprintf("// %s contains %s data.", goTypeName, schemaTypeName),
		Name:    goTypeName,
		Fields:  fields,
	}, nil
}

func buildUnionMergedStruct(schema *ast.Schema, interfaceDef *ast.Definition, uf UnionFieldConfig, scalars map[string]string, nestedOverrides map[string]string) (IRStruct, []string, error) {
	seen := make(map[string]bool)
	var fields []IRField
	var subObjectBases []string

	addField := func(fDef *ast.Definition, fName string) error {
		f := fDef.Fields.ForName(fName)
		if f == nil {
			return fmt.Errorf("field %q not on type %s", fName, fDef.Name)
		}
		goType := resolveGoType(f.Type, schema, scalars, nestedOverrides)
		fields = append(fields, IRField{Name: toPascalCase(fName), JSONTag: fName, Type: goType})
		base := baseTypeName(f.Type)
		if childDef := schema.Types[base]; childDef != nil && (childDef.Kind == ast.Object || childDef.Kind == ast.Interface) {
			subObjectBases = append(subObjectBases, base)
		}
		return nil
	}

	for _, fName := range uf.Common {
		if seen[fName] {
			continue
		}
		seen[fName] = true
		if err := addField(interfaceDef, fName); err != nil {
			return IRStruct{}, nil, fmt.Errorf("common %w", err)
		}
	}

	for _, typeName := range sortedStringKeys(uf.Variants) {
		variantDef := schema.Types[typeName]
		if variantDef == nil {
			return IRStruct{}, nil, fmt.Errorf("variant type %q not found in schema", typeName)
		}
		for _, fName := range uf.Variants[typeName] {
			if seen[fName] {
				continue
			}
			seen[fName] = true
			if err := addField(variantDef, fName); err != nil {
				return IRStruct{}, nil, fmt.Errorf("variant %s: %w", typeName, err)
			}
		}
	}

	return IRStruct{
		Comment: fmt.Sprintf("// %s contains %s data.", uf.GoStruct, interfaceDef.Name),
		Name:    uf.GoStruct,
		Fields:  fields,
	}, subObjectBases, nil
}
