// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"maps"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
)

func buildOperations(schema *ast.Schema, res ResourceConfig, fragConst string, scalars map[string]string, nestedFieldLists map[string][]string, nestedDirectives map[string]map[string]string, pathOverrides map[string]NestedTypeConfig) ([]IROperation, error) {
	var ops []IROperation
	for _, opCfg := range res.Operations {
		op, err := buildOperation(schema, res, opCfg, fragConst, scalars, nestedFieldLists, nestedDirectives, pathOverrides)
		if err != nil {
			return nil, fmt.Errorf("op %s: %w", opCfg.Name, err)
		}
		ops = append(ops, op)
	}
	return ops, nil
}

func buildOperation(schema *ast.Schema, res ResourceConfig, op OperationConfig, fragConst string, scalars map[string]string, nestedFieldLists map[string][]string, nestedDirectives map[string]map[string]string, pathOverrides map[string]NestedTypeConfig) (IROperation, error) {
	gqlName := op.GQLName
	if gqlName == "" {
		gqlName = lcFirst(op.Name)
	}

	kind := op.Kind
	if kind == "" {
		switch {
		case strings.HasPrefix(op.Name, "Get"):
			kind = "get"
		case strings.HasPrefix(op.Name, "List"):
			kind = "list"
		case strings.HasPrefix(op.Name, "Create"):
			kind = "create"
		case strings.HasPrefix(op.Name, "Update"):
			kind = "update"
		case strings.HasPrefix(op.Name, "Delete"):
			kind = "delete"
		default:
			return IROperation{}, fmt.Errorf("cannot infer kind from %q", op.Name)
		}
	}

	endpoint := op.Endpoint
	if endpoint == "" {
		endpoint = "/app"
	}

	returnNullable := false
	if op.ReturnNullable != nil {
		returnNullable = *op.ReturnNullable
	} else {
		returnNullable = kind == "get" || kind == "singleton_get"
	}

	resultKey := op.ResultKey
	if resultKey == "" {
		resultKey = gqlName
	}

	returnType := op.ReturnType
	if returnType == "" {
		returnType = res.TypeName
	}

	isMutation := kind == "create" || kind == "update" || kind == "delete" ||
		kind == "mutation_list" || kind == "singleton_update" || kind == "update_inline" ||
		kind == "multi_wrapped_update"
	suffix := "Query"
	if isMutation {
		suffix = "Mutation"
	}
	constName := lcFirst(op.Name) + suffix

	queryStr, err := buildQueryStr(schema, op, res, gqlName, kind, nestedFieldLists, nestedDirectives, pathOverrides)
	if err != nil {
		return IROperation{}, err
	}

	idField := res.IDField
	if idField == "" {
		idField = "id"
	}
	// Per-op extra var values override / extend resource-level extra var values.
	combinedExtraVars := make(map[string]any)
	maps.Copy(combinedExtraVars, res.ExtraVarValues)
	maps.Copy(combinedExtraVars, op.ExtraVarValues)
	sig, doc, body, err := buildMethodParts(op, kind, endpoint, returnType, returnNullable, resultKey, constName, idField, res.RBACMap, combinedExtraVars)
	if err != nil {
		return IROperation{}, err
	}

	// Delete ops, list ops with inline item fields, ops with inline fields, noFragment, and noSelection
	// don't use the fragment — omit fragConst so AppSync doesn't reject the unused fragment definition.
	opFragConst := fragConst
	if kind == "delete" || (kind == "list" && len(op.ListItemFields) > 0) || len(op.InlineFields) > 0 || op.NoFragment || op.NoSelection {
		opFragConst = ""
	}
	// list_simple doesn't necessarily need the fragment; honor NoFragment if set.
	if kind == "list_simple" && op.NoFragment {
		opFragConst = ""
	}
	return IROperation{
		DocComment: doc,
		MethodName: op.Name,
		Signature:  sig,
		MethodBody: body,
		ConstName:  constName,
		QueryStr:   queryStr,
		FragConst:  opFragConst,
		Pagination: op.Pagination,
	}, nil
}

func inlineArgsSignature(args []InlineArg) (string, []string) {
	var parts []string
	var names []string
	for _, a := range args {
		parts = append(parts, ", "+a.Name+" "+a.GoType)
		names = append(names, a.Name)
	}
	return strings.Join(parts, ""), names
}
