// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"

	"github.com/vektah/gqlparser/v2/ast"
)

// validateConfig checks each resource config entry against the live schema.
// Failures here are fatal at generation time, not compile time.
func validateConfig(schema *ast.Schema, cfg Config) error {
	for _, res := range cfg.Resources {
		if err := validateResource(schema, res); err != nil {
			return fmt.Errorf("[%s]: %w", res.File, err)
		}
	}
	return nil
}

func validateResource(schema *ast.Schema, res ResourceConfig) error {
	schemaTypeName := res.SchemaTypeName()
	def := schema.Types[schemaTypeName]
	if def == nil {
		return fmt.Errorf("type %q not found in schema", schemaTypeName)
	}

	mainFieldSet := fieldSet(def)
	for _, f := range res.Fields {
		if !mainFieldSet[f] {
			return fmt.Errorf("field %q not found on type %s", f, schemaTypeName)
		}
	}
	for f := range res.DirectiveFields {
		if !mainFieldSet[f] {
			return fmt.Errorf("directiveFields key %q not found on type %s", f, schemaTypeName)
		}
	}
	for _, f := range res.NullableResponseFields {
		if !mainFieldSet[f] {
			return fmt.Errorf("nullableResponseFields entry %q not found on type %s", f, schemaTypeName)
		}
	}

	for _, nt := range res.NestedTypes {
		ntDef := schema.Types[nt.SchemaName]
		if ntDef == nil {
			return fmt.Errorf("nested schema type %q not found in schema", nt.SchemaName)
		}
		ntFields := fieldSet(ntDef)
		for _, f := range nt.Fields {
			if !ntFields[f] {
				return fmt.Errorf("nestedType %s field %q not found in schema", nt.SchemaName, f)
			}
		}
		for f := range nt.FieldRenames {
			if !ntFields[f] {
				return fmt.Errorf("nestedType %s fieldRenames key %q not found in schema", nt.SchemaName, f)
			}
		}
		for f := range nt.DirectiveFields {
			if !ntFields[f] {
				return fmt.Errorf("nestedType %s directiveFields key %q not found in schema", nt.SchemaName, f)
			}
		}
		for _, f := range nt.NullableFields {
			if !ntFields[f] {
				return fmt.Errorf("nestedType %s nullableFields entry %q not found in schema", nt.SchemaName, f)
			}
		}
	}

	for _, ert := range res.ExtraResponseTypes {
		ertDef := schema.Types[ert.SchemaName]
		if ertDef == nil {
			return fmt.Errorf("extraResponseType schema name %q not found in schema", ert.SchemaName)
		}
		ertFields := fieldSet(ertDef)
		for _, f := range ert.Fields {
			if !ertFields[f] {
				return fmt.Errorf("extraResponseType %s field %q not found in schema", ert.SchemaName, f)
			}
		}
	}

	for _, te := range res.TypedEnums {
		enumDef := schema.Types[te.SchemaName]
		if enumDef == nil {
			return fmt.Errorf("typedEnum schema name %q not found in schema", te.SchemaName)
		}
		if enumDef.Kind != ast.Enum {
			return fmt.Errorf("typedEnum %s is not an enum in schema (kind=%s)", te.SchemaName, enumDef.Kind)
		}
		enumVals := enumValueSet(enumDef)
		for v := range te.Constants {
			if !enumVals[v] {
				return fmt.Errorf("typedEnum %s constant value %q not in schema enum", te.SchemaName, v)
			}
		}
	}

	for _, op := range res.Operations {
		if err := validateOperation(schema, res, op); err != nil {
			return fmt.Errorf("operation %s: %w", op.Name, err)
		}
	}

	return nil
}

func validateOperation(schema *ast.Schema, res ResourceConfig, op OperationConfig) error {
	gqlName := op.GQLName
	if gqlName == "" {
		gqlName = lcFirst(op.Name)
	}

	var rootField *ast.FieldDefinition
	if schema.Mutation != nil {
		rootField = schema.Mutation.Fields.ForName(gqlName)
	}
	if rootField == nil && schema.Query != nil {
		rootField = schema.Query.Fields.ForName(gqlName)
	}
	if rootField == nil {
		return fmt.Errorf("gql field %q not found in schema Query or Mutation", gqlName)
	}

	if op.InputType != "" {
		inDef := schema.Types[op.InputType]
		if inDef == nil {
			return fmt.Errorf("inputType %q not found in schema", op.InputType)
		}
		if inDef.Kind != ast.InputObject {
			return fmt.Errorf("inputType %q is not an input object (kind=%s)", op.InputType, inDef.Kind)
		}
		inFields := fieldSet(inDef)
		for _, f := range op.InputFields {
			if !inFields[f] {
				return fmt.Errorf("inputFields entry %q not found on input type %s", f, op.InputType)
			}
		}
	}

	if op.GQLReturnType != "" && schema.Types[op.GQLReturnType] == nil {
		return fmt.Errorf("gqlReturnType %q not found in schema", op.GQLReturnType)
	}

	argSet := make(map[string]bool, len(rootField.Arguments))
	for _, a := range rootField.Arguments {
		argSet[a.Name] = true
	}
	for _, tla := range op.TopLevelArgs {
		if !argSet[tla.GQLVar] {
			return fmt.Errorf("topLevelArgs gqlVar %q not found as arg of root field %s", tla.GQLVar, gqlName)
		}
	}
	// InlineArgs are not validated against root field args: depending on op
	// kind they are either passed as top-level field args or expanded as
	// fields of a wrapping input object. Either form is valid.

	if len(op.ListItemFields) > 0 {
		itemType := listItemType(rootField, schema)
		if itemType == nil {
			return fmt.Errorf("listItemFields set but cannot resolve item type for %s", gqlName)
		}
		itemFields := fieldSet(itemType)
		for _, f := range op.ListItemFields {
			if !itemFields[f] {
				return fmt.Errorf("listItemFields entry %q not found on item type %s", f, itemType.Name)
			}
		}
	}

	_ = res
	return nil
}

func fieldSet(def *ast.Definition) map[string]bool {
	set := make(map[string]bool, len(def.Fields))
	for _, f := range def.Fields {
		set[f.Name] = true
	}
	return set
}

func enumValueSet(def *ast.Definition) map[string]bool {
	set := make(map[string]bool, len(def.EnumValues))
	for _, v := range def.EnumValues {
		set[v.Name] = true
	}
	return set
}

// listItemType returns the item Definition for a root field whose return wraps
// a paginated container with an "items" list field (the common Jamf Protect shape).
// Returns nil when the shape is unrecognized.
func listItemType(rootField *ast.FieldDefinition, schema *ast.Schema) *ast.Definition {
	container := schema.Types[baseTypeName(rootField.Type)]
	if container == nil {
		return nil
	}
	items := container.Fields.ForName("items")
	if items == nil {
		return nil
	}
	return schema.Types[baseTypeName(items.Type)]
}
