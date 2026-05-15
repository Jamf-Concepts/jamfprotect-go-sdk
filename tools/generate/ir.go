// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"sort"

	"github.com/vektah/gqlparser/v2/ast"
)

func buildIR(cfg Config, schema *ast.Schema, res ResourceConfig) (IRResource, error) {
	// Schema-name-keyed maps (the default; first NestedTypeConfig wins per schema name).
	nestedGoNames := make(map[string]string)
	nestedFieldRenames := make(map[string]map[string]string)
	nestedFieldLists := make(map[string][]string) // schemaName → allowed fields (nil = all)
	nestedDirectives := make(map[string]map[string]string)
	nestedNullableFields := make(map[string]map[string]bool)
	// Path-keyed maps for context-specific overrides (e.g. "computer.plan" → AlertComputerPlan).
	pathOverrides := make(map[string]NestedTypeConfig)

	for _, nt := range res.NestedTypes {
		if nt.Path != "" {
			pathOverrides[nt.Path] = nt
			continue
		}
		if _, exists := nestedGoNames[nt.SchemaName]; !exists {
			nestedGoNames[nt.SchemaName] = nt.GoName
		}
		if len(nt.FieldRenames) > 0 {
			nestedFieldRenames[nt.SchemaName] = nt.FieldRenames
		}
		if len(nt.Fields) > 0 {
			nestedFieldLists[nt.SchemaName] = nt.Fields
		}
		if len(nt.DirectiveFields) > 0 {
			nestedDirectives[nt.SchemaName] = nt.DirectiveFields
		}
		if len(nt.NullableFields) > 0 {
			m := make(map[string]bool)
			for _, f := range nt.NullableFields {
				m[f] = true
			}
			nestedNullableFields[nt.SchemaName] = m
		}
	}

	nullableResponseFields := make(map[string]bool)
	for _, f := range res.NullableResponseFields {
		nullableResponseFields[f] = true
	}

	fragConst := lcFirst(res.TypeName) + "Fields"

	fragment, err := buildFragment(schema, res, nestedFieldLists, nestedDirectives, pathOverrides)
	if err != nil {
		return IRResource{}, fmt.Errorf("fragment: %w", err)
	}

	mainType, nestedTypes, err := buildResponseTypes(schema, res, nestedGoNames, nestedFieldRenames, nestedFieldLists, nestedNullableFields, nullableResponseFields, pathOverrides, cfg.Scalars)
	if err != nil {
		return IRResource{}, fmt.Errorf("response types: %w", err)
	}

	inputTypes, buildVarsFuncs, err := buildInputTypesAndHelpers(schema, res, cfg.Scalars)
	if err != nil {
		return IRResource{}, fmt.Errorf("input types: %w", err)
	}

	ops, err := buildOperations(schema, res, fragConst, cfg.Scalars, nestedFieldLists, nestedDirectives, pathOverrides)
	if err != nil {
		return IRResource{}, fmt.Errorf("operations: %w", err)
	}

	needClient := false
	for _, op := range ops {
		if op.Pagination {
			needClient = true
			break
		}
	}
	noMainFragment := true
	for _, op := range ops {
		if op.FragConst != "" {
			noMainFragment = false
			break
		}
	}

	var typedEnums []IRTypedEnum
	for _, te := range res.TypedEnums {
		doc := te.Doc
		if doc == "" {
			doc = fmt.Sprintf("// %s identifies a %s value.", te.GoName, te.GoName)
		}
		var consts []IRTypedEnumConst
		// Sort by Go const name for stable output.
		var keys []string
		for k := range te.Constants {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, schemaVal := range keys {
			consts = append(consts, IRTypedEnumConst{Name: te.Constants[schemaVal], Value: schemaVal})
		}
		typedEnums = append(typedEnums, IRTypedEnum{GoName: te.GoName, Doc: doc, Constants: consts})
	}

	return IRResource{
		TypeName:       res.TypeName,
		File:           res.File,
		FragConst:      fragConst,
		Fragment:       fragment,
		GoType:         mainType,
		NestedTypes:    nestedTypes,
		InputTypes:     inputTypes,
		Operations:     ops,
		BuildVarsFuncs: buildVarsFuncs,
		TypedEnums:     typedEnums,
		NeedClient:     needClient,
		ExtraTopLevel:  res.ExtraTopLevel,
		NoMainFragment: noMainFragment,
	}, nil
}
