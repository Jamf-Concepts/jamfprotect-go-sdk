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
	File        string             `json:"file"`
	TypeName    string             `json:"typeName"`
	IDField     string             `json:"idField,omitempty"`     // primary key field; defaults to "id"
	Fields      []string           `json:"fields"`
	InputFields []string           `json:"inputFields,omitempty"` // override which schema input fields to include; defaults to all
	NestedTypes []NestedTypeConfig `json:"nestedTypes,omitempty"`
	Operations  []OperationConfig  `json:"operations"`
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
	Name           string         `json:"name"`
	GQLName        string         `json:"gqlName,omitempty"`
	Kind           string         `json:"kind,omitempty"`
	Endpoint       string         `json:"endpoint,omitempty"`
	InputType      string         `json:"inputType,omitempty"`
	RBAC           string         `json:"rbac,omitempty"`
	Pagination     bool           `json:"pagination,omitempty"`
	PaginationVars map[string]any `json:"paginationVars,omitempty"`
	ReturnType     string         `json:"returnType,omitempty"`
	ReturnNullable *bool          `json:"returnNullable,omitempty"`
	ResultKey      string         `json:"resultKey,omitempty"`
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
