// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config is the top-level generator configuration.
type Config struct {
	SchemaPath         string             `json:"schemaPath"`
	FilteredSchemaPath string             `json:"filteredSchemaPath,omitempty"`
	OutputDir          string             `json:"outputDir"`
	Scalars            map[string]string  `json:"scalars"`
	Resources          []ResourceConfig   `json:"resources"`
	Statics            []StaticEmitConfig `json:"statics,omitempty"`
}

// StaticEmitConfig defines a verbatim file to format-validate and copy into the output directory.
type StaticEmitConfig struct {
	Source string `json:"source"` // path relative to config file directory
	Dest   string `json:"dest"`   // filename in outputDir
}

// ResourceConfig defines one resource file to generate.
type ResourceConfig struct {
	File                   string              `json:"file"`
	TypeName               string              `json:"typeName"`              // Go type name
	GQLTypeName            string              `json:"gqlTypeName,omitempty"` // schema type name when it differs from TypeName
	IDField                string              `json:"idField,omitempty"`     // primary key field; defaults to "id"
	Fields                 []string            `json:"fields"`
	InputFields            []string            `json:"inputFields,omitempty"` // override which schema input fields to include; defaults to all
	NestedTypes            []NestedTypeConfig  `json:"nestedTypes,omitempty"`
	Operations             []OperationConfig   `json:"operations"`
	DirectiveFields        map[string]string   `json:"directiveFields,omitempty"`        // fieldName → GQL directive string (e.g. "@include(if: $RBAC_Plan)")
	ExtraVars              map[string]string   `json:"extraVars,omitempty"`              // extra GQL var declarations added to non-delete operation signatures
	ExtraVarValues         map[string]any      `json:"extraVarValues,omitempty"`         // static var values merged into get/create/update method bodies
	RBACMap                string              `json:"rbacMap,omitempty"`                // package-level RBAC map name passed to mergeVars in method bodies
	NullableInputFields    []string            `json:"nullableInputFields,omitempty"`    // input fields that should use pointer types despite being scalars
	OptionalInputFields    []string            `json:"optionalInputFields,omitempty"`    // input fields omitted from buildVars when zero/nil (conditional inclusion)
	InputTypeRenames       map[string]string   `json:"inputTypeRenames,omitempty"`       // schema InputObject name → Go type name for nested generated input types
	UnionFields            map[string]UnionFieldConfig `json:"unionFields,omitempty"`    // fieldName → union/interface field expansion config
	ExtraResponseTypes     []ExtraResponseType `json:"extraResponseTypes,omitempty"`     // additional Go response types not tied to a field (e.g. list-item types)
	NullableResponseFields []string            `json:"nullableResponseFields,omitempty"` // top-level response fields that should use pointer types even for scalars
	TypedEnums             []TypedEnumConfig   `json:"typedEnums,omitempty"`             // typed Go enum aliases with named constants
	IsList                 bool                `json:"isList,omitempty"`                 // generate a [TypeName] return at the main type fragment ref level
	ExtraTopLevel          string              `json:"extraTopLevel,omitempty"`          // verbatim Go code appended after the main type definition (for one-off helpers)
}

// TypedEnumConfig declares a Go typed string alias with named constants for a schema enum.
type TypedEnumConfig struct {
	SchemaName string            `json:"schemaName"`
	GoName     string            `json:"goName"`
	Constants  map[string]string `json:"constants"` // schema enum value → Go const name (e.g. "NGTP_BETA": "BetaNameNGTP")
	Doc        string            `json:"doc,omitempty"`
}

// SchemaTypeName returns the GraphQL schema type name for this resource.
func (r ResourceConfig) SchemaTypeName() string {
	if r.GQLTypeName != "" {
		return r.GQLTypeName
	}
	return r.TypeName
}

// ExtraResponseType generates an additional Go response struct not tied to a field of the main type.
type ExtraResponseType struct {
	GoName     string   `json:"goName"`
	SchemaName string   `json:"schemaName"`
	Fields     []string `json:"fields,omitempty"` // restrict to a subset of schema fields
}

// UnionFieldConfig describes how to expand a GraphQL interface/union field
// in both the GQL fragment and the Go response struct.
type UnionFieldConfig struct {
	Common   []string            `json:"common"`   // fields from the interface itself
	Variants map[string][]string `json:"variants"` // concrete type name → extra fields
	GoStruct string              `json:"goStruct"` // Go struct name for the merged response type
}

// NestedTypeConfig overrides Go naming for a nested schema type within a resource.
type NestedTypeConfig struct {
	SchemaName      string            `json:"schemaName"`
	GoName          string            `json:"goName"`
	Fields          []string          `json:"fields,omitempty"` // restrict to a subset of schema fields; defaults to all
	FieldRenames    map[string]string `json:"fieldRenames,omitempty"`
	DirectiveFields map[string]string `json:"directiveFields,omitempty"` // sub-field GQL directives (e.g. "assignedRoles": "@include(if: $RBAC_Role)")
	Path            string            `json:"path,omitempty"`            // optional dot-path under main type (e.g. "computer.plan") for path-specific overrides
	NullableFields  []string          `json:"nullableFields,omitempty"`  // sub-fields that should use pointer types even for nullable scalars
}

// OperationConfig defines one GraphQL operation on a resource.
type OperationConfig struct {
	Name            string         `json:"name"`
	GQLName         string         `json:"gqlName,omitempty"`
	Kind            string         `json:"kind,omitempty"`
	Endpoint        string         `json:"endpoint,omitempty"`
	InputType       string         `json:"inputType,omitempty"`
	InputTypeGoName string         `json:"inputTypeGoName,omitempty"` // Go struct name when it differs from InputType
	RBAC            string         `json:"rbac,omitempty"`
	Pagination      bool           `json:"pagination,omitempty"`
	PaginationVars  map[string]any `json:"paginationVars,omitempty"`
	ReturnType      string         `json:"returnType,omitempty"`
	ReturnNullable  *bool          `json:"returnNullable,omitempty"`
	ResultKey       string         `json:"resultKey,omitempty"`
	WrappedInput    bool           `json:"wrappedInput,omitempty"`    // use $input: TypeName! single var instead of expanding fields
	InputFields     []string       `json:"inputFields,omitempty"`     // per-op override for which schema input fields appear in the mutation
	ListItemFields  []string       `json:"listItemFields,omitempty"`  // inline fields for list items instead of the fragment (for minimal list queries)
	InlineArgs      []InlineArg    `json:"inlineArgs,omitempty"`      // primitive Go args for singleton_update / inline ops (no struct input)
	ResultPath      string         `json:"resultPath,omitempty"`      // dot-path for nested-result extraction (e.g. "getAppInitializationData.betaAcceptanceStatus")
	ResultPathTypes []string       `json:"resultPathTypes,omitempty"` // optional Go type names for each intermediate level in ResultPath
	GQLReturnType   string         `json:"gqlReturnType,omitempty"`   // when the op's GQL return type differs from the resource's main schema type
	InlineFields    []string       `json:"inlineFields,omitempty"`    // inline scalar fields used instead of fragment ref (per-op subset)
	ExtraVarValues  map[string]any `json:"extraVarValues,omitempty"`  // per-op extra var values merged into method body
	NoFragment      bool           `json:"noFragment,omitempty"`      // suppress fragment append (for ops with custom return shape)
	DateRangeArg    string         `json:"dateRangeArg,omitempty"`    // for date_paginated: Go arg name (e.g. "dateRange") of type *NameDateRange
	ReturnIsList    bool           `json:"returnIsList,omitempty"`    // when true, the op returns []ReturnType instead of ReturnType (for singleton_get/singleton_update on list-shaped results)
	TopLevelArgs    []TopLevelArg  `json:"topLevelArgs,omitempty"`    // extra GQL args forwarded as top-level field args alongside input (e.g. uuid in listInsightComputers)
	FieldArgs       string         `json:"fieldArgs,omitempty"`       // verbatim GQL field argument string appended to the field call (e.g. "date: $date")
}

// InlineArg is a primitive Go argument for singleton_update or inline-arg operations.
type InlineArg struct {
	Name       string `json:"name"`                 // Go arg name (camelCase)
	GoType     string `json:"goType"`               // Go type (e.g. "bool", "string")
	GQLVar     string `json:"gqlVar"`               // GQL variable name (e.g. "configFreeze")
	GQLType    string `json:"gqlType"`              // GQL type declaration (e.g. "Boolean!")
	IsID       bool   `json:"isId,omitempty"`       // true if this is the resource ID arg (not wrapped in input)
	IsOptional bool   `json:"isOptional,omitempty"` // when true, only include var when non-zero/non-nil
}

// TopLevelArg is a primitive Go argument forwarded as both a GQL top-level var and a field arg
// (outside of the standard input:{} constructor). Used for paginated queries like listInsightComputers
// where uuid is a top-level field argument alongside the paginated input.
type TopLevelArg struct {
	Name    string `json:"name"`    // Go arg name (camelCase)
	GoType  string `json:"goType"`  // Go type (e.g. "string")
	GQLVar  string `json:"gqlVar"`  // GQL variable name (e.g. "uuid")
	GQLType string `json:"gqlType"` // GQL type declaration (e.g. "ID!")
}

func loadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}
