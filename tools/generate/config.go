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
	SchemaPath string            `json:"schemaPath"`
	OutputDir  string            `json:"outputDir"`
	Scalars    map[string]string `json:"scalars"`
	Resources  []ResourceConfig  `json:"resources"`
}

// ResourceConfig defines one resource file to generate.
type ResourceConfig struct {
	File            string            `json:"file"`
	TypeName        string            `json:"typeName"`              // Go type name
	GQLTypeName     string            `json:"gqlTypeName,omitempty"` // schema type name when it differs from TypeName
	IDField         string            `json:"idField,omitempty"`     // primary key field; defaults to "id"
	Fields          []string          `json:"fields"`
	InputFields     []string          `json:"inputFields,omitempty"` // override which schema input fields to include; defaults to all
	NestedTypes     []NestedTypeConfig `json:"nestedTypes,omitempty"`
	Operations      []OperationConfig  `json:"operations"`
	DirectiveFields     map[string]string  `json:"directiveFields,omitempty"`     // fieldName → GQL directive string (e.g. "@include(if: $RBAC_Plan)")
	ExtraVars           map[string]string  `json:"extraVars,omitempty"`           // extra GQL var declarations added to non-delete operation signatures
	ExtraVarValues      map[string]any     `json:"extraVarValues,omitempty"`      // static var values merged into get/create/update method bodies
	RBACMap             string             `json:"rbacMap,omitempty"`             // package-level RBAC map name passed to mergeVars in method bodies
	NullableInputFields []string           `json:"nullableInputFields,omitempty"` // input fields that should use pointer types despite being scalars
}

// SchemaTypeName returns the GraphQL schema type name for this resource.
func (r ResourceConfig) SchemaTypeName() string {
	if r.GQLTypeName != "" {
		return r.GQLTypeName
	}
	return r.TypeName
}

// NestedTypeConfig overrides Go naming for a nested schema type within a resource.
type NestedTypeConfig struct {
	SchemaName   string            `json:"schemaName"`
	GoName       string            `json:"goName"`
	Fields       []string          `json:"fields,omitempty"`       // restrict to a subset of schema fields; defaults to all
	FieldRenames map[string]string `json:"fieldRenames,omitempty"`
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
	WrappedInput    bool           `json:"wrappedInput,omitempty"`  // use $input: TypeName! single var instead of expanding fields
	InputFields     []string       `json:"inputFields,omitempty"`   // per-op override for which schema input fields appear in the mutation
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
