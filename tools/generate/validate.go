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

	for _, f := range res.Fields {
		if def.Fields.ForName(f) == nil {
			return fmt.Errorf("field %q not found on type %s", f, schemaTypeName)
		}
	}

	for _, nt := range res.NestedTypes {
		if schema.Types[nt.SchemaName] == nil {
			return fmt.Errorf("nested schema type %q not found in schema", nt.SchemaName)
		}
	}

	for _, op := range res.Operations {
		gqlName := op.GQLName
		if gqlName == "" {
			gqlName = lcFirst(op.Name)
		}
		inMutation := schema.Mutation != nil && schema.Mutation.Fields.ForName(gqlName) != nil
		inQuery := schema.Query != nil && schema.Query.Fields.ForName(gqlName) != nil
		if !inMutation && !inQuery {
			return fmt.Errorf("operation %q (gql: %q) not found in schema Query or Mutation", op.Name, gqlName)
		}
		if op.InputType != "" && schema.Types[op.InputType] == nil {
			return fmt.Errorf("inputType %q not found in schema", op.InputType)
		}
	}

	return nil
}
