// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/formatter"
)

// preambleScalars are defined in scalarPreamble (schema.go) and must not be
// re-emitted in the filtered schema — gqlparser would reject the double-definition.
var preambleScalars = map[string]bool{
	"AWSDateTime": true, "AWSJSON": true, "AWSEmail": true, "AWSIPAddress": true,
	"AWSPhone": true, "AWSURL": true, "AWSDate": true, "AWSTimestamp": true, "Long": true,
}

// filteredEntry tracks a type to include with an optional field allowlist.
// fieldAllow == nil means include all fields.
type filteredEntry struct {
	fieldAllow map[string]bool
}

// schemaFilter collects types referenced by config and builds a filtered SchemaDocument.
type schemaFilter struct {
	schema   *ast.Schema
	types    map[string]*filteredEntry
	queryOps []*ast.FieldDefinition
	mutOps   []*ast.FieldDefinition
}

func newSchemaFilter(schema *ast.Schema) *schemaFilter {
	return &schemaFilter{
		schema: schema,
		types:  make(map[string]*filteredEntry),
	}
}

// addType records a type with an optional field restriction. Subsequent calls for
// the same type union the field sets; a nil fields arg upgrades to all-fields.
func (sf *schemaFilter) addType(name string, fields []string) {
	if preambleScalars[name] || isBuiltinType(name) {
		return
	}
	if sf.schema.Types[name] == nil {
		return
	}
	existing, seen := sf.types[name]
	if !seen {
		if fields == nil {
			sf.types[name] = &filteredEntry{}
		} else {
			allow := make(map[string]bool, len(fields))
			for _, f := range fields {
				allow[f] = true
			}
			sf.types[name] = &filteredEntry{fieldAllow: allow}
		}
		return
	}
	if existing.fieldAllow == nil || fields == nil {
		existing.fieldAllow = nil // upgrade to all-fields
		return
	}
	for _, f := range fields {
		existing.fieldAllow[f] = true
	}
}

func (sf *schemaFilter) addTypeAll(name string) { sf.addType(name, nil) }

// addTypeAllTransitive adds a type with all fields and recurses into its field types.
// Uses sf.types as the visited set to prevent cycles.
func (sf *schemaFilter) addTypeAllTransitive(name string) {
	if preambleScalars[name] || isBuiltinType(name) {
		return
	}
	def := sf.schema.Types[name]
	if def == nil {
		return
	}
	if _, seen := sf.types[name]; seen {
		return
	}
	sf.types[name] = &filteredEntry{} // mark visited before recursing
	for _, f := range def.Fields {
		sf.addTypeAllTransitive(baseTypeName(f.Type))
	}
	// Also follow enum values' types — enums have no fields, so this is a no-op there.
}

// walkResource seeds the filter with all types referenced by a resource config.
func (sf *schemaFilter) walkResource(r ResourceConfig) {
	sf.addType(r.SchemaTypeName(), r.Fields)

	for _, nt := range r.NestedTypes {
		if len(nt.Fields) > 0 {
			sf.addType(nt.SchemaName, nt.Fields)
		} else {
			sf.addTypeAll(nt.SchemaName)
		}
	}

	for _, ert := range r.ExtraResponseTypes {
		if len(ert.Fields) > 0 {
			sf.addType(ert.SchemaName, ert.Fields)
		} else {
			sf.addTypeAll(ert.SchemaName)
		}
	}

	for _, te := range r.TypedEnums {
		sf.addTypeAll(te.SchemaName)
	}

	for _, op := range r.Operations {
		sf.walkOperation(op)
	}
}

// walkOperation adds the root op field to the appropriate root list and seeds its arg types.
func (sf *schemaFilter) walkOperation(op OperationConfig) {
	gqlName := op.GQLName
	if gqlName == "" {
		gqlName = lcFirst(op.Name)
	}

	if f := findSchemaField(sf.schema.Query, gqlName); f != nil {
		if !hasOpName(sf.queryOps, gqlName) {
			sf.queryOps = append(sf.queryOps, stripPrivate(f))
		}
		sf.addTypeAllTransitive(baseTypeName(f.Type))
		for _, arg := range f.Arguments {
			sf.addTypeAllTransitive(baseTypeName(arg.Type))
		}
	} else if f := findSchemaField(sf.schema.Mutation, gqlName); f != nil {
		if !hasOpName(sf.mutOps, gqlName) {
			sf.mutOps = append(sf.mutOps, stripPrivate(f))
		}
		sf.addTypeAllTransitive(baseTypeName(f.Type))
		for _, arg := range f.Arguments {
			sf.addTypeAllTransitive(baseTypeName(arg.Type))
		}
	}

	if op.InputType != "" {
		sf.addTypeAllTransitive(op.InputType)
	}
}

// walkTransitive expands the collected set: for each type, walk its included
// fields and add referenced types (all-fields) until no new types are added.
func (sf *schemaFilter) walkTransitive() {
	changed := true
	for changed {
		changed = false
		// Snapshot names to avoid mutating map while iterating.
		names := make([]string, 0, len(sf.types))
		for n := range sf.types {
			names = append(names, n)
		}
		for _, name := range names {
			entry := sf.types[name]
			def := sf.schema.Types[name]
			if def == nil {
				continue
			}
			for _, f := range def.Fields {
				if entry.fieldAllow != nil && !entry.fieldAllow[f.Name] {
					continue
				}
				ft := baseTypeName(f.Type)
				if preambleScalars[ft] || isBuiltinType(ft) {
					continue
				}
				if _, seen := sf.types[ft]; !seen {
					sf.addTypeAll(ft)
					changed = true
				}
			}
		}
	}
}

// buildDoc assembles the ast.SchemaDocument from collected types and ops.
func (sf *schemaFilter) buildDoc() *ast.SchemaDocument {
	doc := &ast.SchemaDocument{}

	// schema { query: Query mutation: Mutation } block.
	if len(sf.queryOps) > 0 || len(sf.mutOps) > 0 {
		sd := &ast.SchemaDefinition{}
		if len(sf.queryOps) > 0 {
			sd.OperationTypes = append(sd.OperationTypes, &ast.OperationTypeDefinition{
				Operation: ast.Query,
				Type:      "Query",
			})
		}
		if len(sf.mutOps) > 0 {
			sd.OperationTypes = append(sd.OperationTypes, &ast.OperationTypeDefinition{
				Operation: ast.Mutation,
				Type:      "Mutation",
			})
		}
		doc.Schema = append(doc.Schema, sd)
	}

	// Collected type definitions, sorted for determinism.
	names := make([]string, 0, len(sf.types))
	for n := range sf.types {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, name := range names {
		entry := sf.types[name]
		def := sf.schema.Types[name]
		if def == nil || def.BuiltIn {
			continue
		}
		doc.Definitions = append(doc.Definitions, buildFilteredDef(def, entry.fieldAllow))
	}

	// Root types at the end, sorted by name for determinism.
	if len(sf.mutOps) > 0 {
		sort.Slice(sf.mutOps, func(i, j int) bool { return sf.mutOps[i].Name < sf.mutOps[j].Name })
		doc.Definitions = append(doc.Definitions, buildRootDef("Mutation", sf.mutOps))
	}
	if len(sf.queryOps) > 0 {
		sort.Slice(sf.queryOps, func(i, j int) bool { return sf.queryOps[i].Name < sf.queryOps[j].Name })
		doc.Definitions = append(doc.Definitions, buildRootDef("Query", sf.queryOps))
	}

	return doc
}

// buildFilteredDef copies a Definition, applying the field allowlist and
// stripping descriptions and directives for privacy.
func buildFilteredDef(def *ast.Definition, fieldAllow map[string]bool) *ast.Definition {
	d := &ast.Definition{
		Kind: def.Kind,
		Name: def.Name,
	}
	switch def.Kind {
	case ast.Enum:
		for _, v := range def.EnumValues {
			d.EnumValues = append(d.EnumValues, &ast.EnumValueDefinition{Name: v.Name})
		}
	case ast.Scalar:
		// nothing to copy
	default:
		for _, f := range def.Fields {
			if fieldAllow != nil && !fieldAllow[f.Name] {
				continue
			}
			d.Fields = append(d.Fields, &ast.FieldDefinition{
				Name: f.Name,
				Type: f.Type,
				// Description and Directives intentionally omitted for privacy.
			})
		}
	}
	return d
}

// buildRootDef builds a Query or Mutation object type with the given op fields.
func buildRootDef(name string, fields []*ast.FieldDefinition) *ast.Definition {
	return &ast.Definition{
		Kind:   ast.Object,
		Name:   name,
		Fields: fields,
	}
}

// findSchemaField looks up a field by name on a schema root definition.
func findSchemaField(def *ast.Definition, name string) *ast.FieldDefinition {
	if def == nil {
		return nil
	}
	for _, f := range def.Fields {
		if f.Name == name {
			return f
		}
	}
	return nil
}

// hasOpName reports whether the field list already contains a field with the given name.
func hasOpName(fields []*ast.FieldDefinition, name string) bool {
	for _, f := range fields {
		if f.Name == name {
			return true
		}
	}
	return false
}

// stripPrivate returns a copy of a FieldDefinition with descriptions and directives removed.
func stripPrivate(f *ast.FieldDefinition) *ast.FieldDefinition {
	result := &ast.FieldDefinition{
		Name: f.Name,
		Type: f.Type,
	}
	if len(f.Arguments) > 0 {
		result.Arguments = make(ast.ArgumentDefinitionList, len(f.Arguments))
		for i, a := range f.Arguments {
			result.Arguments[i] = &ast.ArgumentDefinition{
				Name:         a.Name,
				Type:         a.Type,
				DefaultValue: a.DefaultValue,
			}
		}
	}
	return result
}

// isBuiltinType reports whether name is a GraphQL built-in scalar or meta-type.
func isBuiltinType(name string) bool {
	switch name {
	case "String", "Boolean", "Int", "Float", "ID",
		"__Schema", "__Type", "__Field", "__InputValue",
		"__EnumValue", "__Directive", "__DirectiveLocation", "__TypeKind":
		return true
	}
	return false
}

// emitFilteredSchema writes a minimal SDL schema to outPath containing only the
// types and fields referenced by cfg. Descriptions and field directives are omitted.
func emitFilteredSchema(schema *ast.Schema, cfg Config, outPath string) error {
	sf := newSchemaFilter(schema)
	for _, res := range cfg.Resources {
		sf.walkResource(res)
	}
	sf.walkTransitive()
	doc := sf.buildDoc()

	var buf bytes.Buffer
	f := formatter.NewFormatter(&buf, formatter.WithoutDescription())
	f.FormatSchemaDocument(doc)

	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	if err := os.WriteFile(outPath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("write filtered schema: %w", err)
	}
	return nil
}
