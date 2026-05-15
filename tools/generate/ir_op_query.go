// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
)

func extraVarDeclStr(extraVars map[string]string) string {
	if len(extraVars) == 0 {
		return ""
	}
	keys := make([]string, 0, len(extraVars))
	for k := range extraVars {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, "$"+k+": "+extraVars[k])
	}
	return strings.Join(parts, ", ")
}

func buildQueryStr(schema *ast.Schema, op OperationConfig, res ResourceConfig, gqlName, kind string, nestedFieldLists map[string][]string, nestedDirectives map[string]map[string]string, pathOverrides map[string]NestedTypeConfig) (string, error) {
	fragRef := "..." + res.TypeName + "Fields"
	idField := res.IDField
	if idField == "" {
		idField = "id"
	}

	// Extra var declarations are added to ops that use the fragment.
	// Delete ops and list ops with custom inline fields don't use the fragment, so skip extraVars.
	extraDecls := ""
	if kind != "delete" && !(kind == "list" && len(op.ListItemFields) > 0) {
		extraDecls = extraVarDeclStr(res.ExtraVars)
	}

	// Build a "body" — what goes inside the response selection. Defaults to fragment ref.
	bodySelection := fragRef
	if len(op.InlineFields) > 0 {
		bodySelection = strings.Join(op.InlineFields, "\n\t\t")
	}

	switch kind {
	case "get":
		varDecls := "$" + idField + ": ID!"
		if extraDecls != "" {
			varDecls += ", " + extraDecls
		}
		return fmt.Sprintf("\nquery %s(%s) {\n\t%s(%s: $%s) {\n\t\t%s\n\t}\n}\n", gqlName, varDecls, gqlName, idField, idField, fragRef), nil

	case "delete":
		// Return only the id field — no fragment reference avoids directive variable validation.
		return fmt.Sprintf("\nmutation %s($%s: ID!) {\n\t%s(%s: $%s) {\n\t\t%s\n\t}\n}\n", gqlName, idField, gqlName, idField, idField, idField), nil

	case "create":
		if op.InputType == "" {
			return "", fmt.Errorf("create op %q requires inputType", op.Name)
		}
		if op.WrappedInput {
			allDecls := "$input: " + op.InputType + "!"
			if extraDecls != "" {
				allDecls += ", " + extraDecls
			}
			return fmt.Sprintf("\nmutation %s(%s) {\n\t%s(input: $input) {\n\t\t%s\n\t}\n}\n", gqlName, allDecls, gqlName, fragRef), nil
		}
		opInputFields := res.InputFields
		if len(op.InputFields) > 0 {
			opInputFields = op.InputFields
		}
		return buildCreateStr(schema, op.InputType, gqlName, fragRef, opInputFields, extraDecls)

	case "update":
		if op.InputType == "" {
			return "", fmt.Errorf("update op %q requires inputType", op.Name)
		}
		if op.WrappedInput {
			allDecls := "$" + idField + ": ID!, $input: " + op.InputType + "!"
			if extraDecls != "" {
				allDecls += ", " + extraDecls
			}
			return fmt.Sprintf("\nmutation %s(%s) {\n\t%s(%s: $%s, input: $input) {\n\t\t%s\n\t}\n}\n", gqlName, allDecls, gqlName, idField, idField, fragRef), nil
		}
		opInputFields := res.InputFields
		if len(op.InputFields) > 0 {
			opInputFields = op.InputFields
		}
		return buildUpdateStr(schema, op.InputType, gqlName, fragRef, idField, opInputFields, extraDecls)

	case "singleton_get":
		// Use alias when resultKey differs from gqlName (e.g. "downloads: getOrganizationDownloads").
		opResultKey := op.ResultKey
		if opResultKey == "" {
			opResultKey = gqlName
		}
		fieldRef := gqlName
		if opResultKey != gqlName {
			fieldRef = opResultKey + ": " + gqlName
		}
		var allVarDecls []string
		if extraDecls != "" {
			allVarDecls = append(allVarDecls, extraDecls)
		}
		for _, a := range op.InlineArgs {
			allVarDecls = append(allVarDecls, "$"+a.GQLVar+": "+a.GQLType)
		}
		// Knob C: optional struct input — declare $input: T (no !) for singleton_get.
		if op.InputType != "" && op.WrappedInput {
			allVarDecls = append(allVarDecls, "$input: "+op.InputType)
		}
		// GQLVars: extra var declarations with no Go-arg counterpart (values come from ExtraVarValues).
		gqlVarKeys := make([]string, 0, len(op.GQLVars))
		for k := range op.GQLVars {
			gqlVarKeys = append(gqlVarKeys, k)
		}
		sort.Strings(gqlVarKeys)
		for _, k := range gqlVarKeys {
			allVarDecls = append(allVarDecls, "$"+k+": "+op.GQLVars[k])
		}
		varDecls := ""
		if len(allVarDecls) > 0 {
			varDecls = "(" + strings.Join(allVarDecls, ", ") + ")"
		}
		// fieldRef may include field args (e.g. getFleetComplianceBaselineScore(date: $date)).
		fieldCallRef := fieldRef
		if op.FieldArgs != "" {
			fieldCallRef = fieldRef + "(" + op.FieldArgs + ")"
		}
		// NoSelection: scalar return — emit the field call with no selection set.
		if op.NoSelection {
			return fmt.Sprintf("\nquery %s%s {\n\t%s\n}\n", gqlName, varDecls, fieldCallRef), nil
		}
		// ResultPathLeaf: the last segment of ResultPath is a scalar leaf field — emit
		// nested object wrappers for all but the last, then the leaf as a plain field.
		if op.ResultPathLeaf && op.ResultPath != "" {
			parts := strings.Split(op.ResultPath, ".")
			cur := parts[len(parts)-1]
			for i := len(parts) - 2; i >= 0; i-- {
				depth := i + 1
				inner := strings.Repeat("\t", depth+1)
				outer := strings.Repeat("\t", depth)
				cur = fmt.Sprintf("%s {\n%s%s\n%s}", parts[i], inner, cur, outer)
			}
			return fmt.Sprintf("\nquery %s%s {\n\t%s\n}\n", gqlName, varDecls, cur), nil
		}
		// Wrap nested-result paths around the bodySelection.
		body := wrapResultPath(op.ResultPath, fieldCallRef, bodySelection)
		// If ResultPath wasn't given, default to single-level wrap with fieldRef.
		if op.ResultPath == "" {
			body = fmt.Sprintf("%s {\n\t\t%s\n\t}", fieldCallRef, bodySelection)
		}
		return fmt.Sprintf("\nquery %s%s {\n\t%s\n}\n", gqlName, varDecls, body), nil

	case "list":
		if op.Pagination {
			return buildPaginatedListStr(schema, gqlName, fragRef, op.PaginationVars, extraDecls, op.ListItemFields, op.TopLevelArgs)
		}
		return buildSimpleListStr(gqlName, fragRef), nil

	case "list_simple":
		// Top-level list returning [T] directly (no items/pageInfo wrapper, no pagination).
		// e.g. listInsights returns [Insight] directly.
		return fmt.Sprintf("\nquery %s {\n\t%s {\n\t\t%s\n\t}\n}\n", gqlName, gqlName, bodySelection), nil

	case "list_items":
		// Non-paginated list with {items: [T]} wrapper. Inline args are passed as an inline
		// input literal {arg1: $arg1, arg2: $arg2, ...}. No pageInfo, no client.ListAll.
		// When no inlineFields are configured, auto-derive bodySelection from an
		// extraResponseType matching ReturnType (so list_items can return a non-main type).
		itemsBody := bodySelection
		if len(op.InlineFields) == 0 && op.ReturnType != "" && op.ReturnType != res.TypeName {
			for _, ert := range res.ExtraResponseTypes {
				if ert.GoName != op.ReturnType {
					continue
				}
				var b strings.Builder
				writeFragmentSubFields(schema, ert.SchemaName, ert.Fields, nil, nestedFieldLists, nestedDirectives, pathOverrides, "", 3, &b, res.UnionFields)
				itemsBody = strings.TrimRight(b.String(), "\n")
				itemsBody = strings.TrimLeft(itemsBody, "\t")
				break
			}
		}
		return buildListItemsStr(op, gqlName, itemsBody, extraDecls), nil

	case "mutation_list":
		// Mutation returning {items: [T]}. Build like create, but wrap in items.
		if op.InputType == "" && len(op.InlineArgs) == 0 {
			return "", fmt.Errorf("mutation_list op %q requires inputType or inlineArgs", op.Name)
		}
		if len(op.InlineArgs) > 0 {
			return buildInlineArgsMutationStr(op, gqlName, bodySelection, true, extraDecls, idField)
		}
		opInputFields := res.InputFields
		if len(op.InputFields) > 0 {
			opInputFields = op.InputFields
		}
		return buildMutationListStr(schema, op.InputType, gqlName, bodySelection, opInputFields, extraDecls, op.ResultPath)

	case "singleton_update":
		// Mutation taking primitive args, wrapped in input: {field: $field}.
		if len(op.InlineArgs) == 0 {
			return "", fmt.Errorf("singleton_update op %q requires inlineArgs", op.Name)
		}
		// When resultPath has extra parts beyond gqlName, wrap bodySelection in those path parts.
		if suffix := resultPathSuffix(op.ResultPath, gqlName); suffix != "" {
			bodySelection = wrapBodyInMutationSuffix(suffix, bodySelection)
		}
		return buildInlineArgsMutationStr(op, gqlName, bodySelection, false, extraDecls, idField)

	case "multi_wrapped_update":
		if len(op.MultiWrappedInputs) == 0 {
			return "", fmt.Errorf("multi_wrapped_update op %q requires multiWrappedInputs", op.Name)
		}
		return buildMultiWrappedMutationStr(op, gqlName, bodySelection), nil

	case "update_inline":
		// Update mutation taking primitive args (idField + others), wrapped in input.
		if len(op.InlineArgs) == 0 {
			return "", fmt.Errorf("update_inline op %q requires inlineArgs", op.Name)
		}
		return buildInlineArgsMutationStr(op, gqlName, bodySelection, false, extraDecls, idField)

	case "date_paginated":
		// Date-range cursor-paginated list. No fragment override; uses bodySelection (which defaults to fragRef).
		return buildDatePaginatedStr(gqlName, bodySelection, extraDecls)

	default:
		return "", fmt.Errorf("unsupported kind %q", kind)
	}
}

// wrapResultPath builds nested object selections for a dot-path like "getAppInitializationData.betaAcceptanceStatus".

func wrapResultPath(path, gqlName, body string) string {
	if path == "" {
		return fmt.Sprintf("%s {\n\t\t%s\n\t}", gqlName, body)
	}
	parts := strings.Split(path, ".")
	// Walk from innermost outward, wrapping each level.
	cur := body
	for i := len(parts) - 1; i >= 0; i-- {
		indent := strings.Repeat("\t", i+1)
		closeIndent := strings.Repeat("\t", i+1)
		_ = closeIndent
		cur = fmt.Sprintf("%s {\n%s\t%s\n%s}", parts[i], indent, cur, indent)
	}
	return cur
}

func buildMutationListStr(schema *ast.Schema, inputTypeName, gqlName, bodySelection string, allowedFields []string, extraDecls, resultPath string) (string, error) {
	def := schema.Types[inputTypeName]
	if def == nil {
		return "", fmt.Errorf("input type %q not found", inputTypeName)
	}
	allowed := make(map[string]bool, len(allowedFields))
	for _, f := range allowedFields {
		allowed[f] = true
	}
	varDecls := make([]string, 0, len(def.Fields))
	inputParts := make([]string, 0, len(def.Fields))
	for _, f := range def.Fields {
		if len(allowed) > 0 && !allowed[f.Name] {
			continue
		}
		varDecls = append(varDecls, "$"+f.Name+": "+f.Type.String())
		inputParts = append(inputParts, f.Name+": $"+f.Name)
	}
	vars := strings.Join(varDecls, ", ")
	if extraDecls != "" {
		vars += ", " + extraDecls
	}
	input := "{" + strings.Join(inputParts, ", ") + "}"
	// Build the selection: if resultPath is set, use the second part as the wrapping field name.
	wrapField := "items"
	if resultPath != "" {
		parts := strings.Split(resultPath, ".")
		if len(parts) >= 2 {
			wrapField = parts[len(parts)-1]
		}
	}
	return fmt.Sprintf("\nmutation %s(%s) {\n\t%s(input: %s) {\n\t\t%s {\n\t\t\t%s\n\t\t}\n\t}\n}\n", gqlName, vars, gqlName, input, wrapField, bodySelection), nil
}

// resultPathSuffix strips the gqlName prefix from resultPath and returns the remainder.

func resultPathSuffix(resultPath, gqlName string) string {
	prefix := gqlName + "."
	if strings.HasPrefix(resultPath, prefix) {
		return resultPath[len(prefix):]
	}
	return ""
}

// wrapBodyInMutationSuffix wraps bodySelection in nested blocks for the given dot-path suffix.

func wrapBodyInMutationSuffix(suffix, body string) string {
	parts := strings.Split(suffix, ".")
	cur := body
	for i := len(parts) - 1; i >= 0; i-- {
		depth := 2 + i
		inner := strings.Repeat("\t", depth+1)
		outer := strings.Repeat("\t", depth)
		cur = fmt.Sprintf("%s {\n%s%s\n%s}", parts[i], inner, cur, outer)
	}
	return cur
}

type inputTreeNode struct {
	key      string
	children []*inputTreeNode
	varName  string // non-empty for leaf nodes
}

// buildNestedInputLiteralStr builds a nested GQL input literal from args with InputPath.
// E.g. args with paths "retention.database.log.numberOfDays" etc. produce
// {retention: {database: {log: {numberOfDays: $databaseLogDays}, ...}, ...}}.
func buildNestedInputLiteralStr(args []InlineArg) string {
	root := &inputTreeNode{}
	for _, a := range args {
		if a.InputPath == "" || a.IsID {
			continue
		}
		parts := strings.Split(a.InputPath, ".")
		cur := root
		for _, p := range parts[:len(parts)-1] {
			var found *inputTreeNode
			for _, ch := range cur.children {
				if ch.key == p {
					found = ch
					break
				}
			}
			if found == nil {
				found = &inputTreeNode{key: p}
				cur.children = append(cur.children, found)
			}
			cur = found
		}
		cur.children = append(cur.children, &inputTreeNode{key: parts[len(parts)-1], varName: a.GQLVar})
	}
	return serializeInputTree(root.children)
}

// serializeInputTree renders an inputTreeNode slice as a GQL object literal.
func serializeInputTree(nodes []*inputTreeNode) string {
	parts := make([]string, 0, len(nodes))
	for _, n := range nodes {
		if len(n.children) == 0 {
			parts = append(parts, n.key+": $"+n.varName)
		} else {
			parts = append(parts, n.key+": "+serializeInputTree(n.children))
		}
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// buildMultiWrappedMutationStr builds a mutation with N typed input variables, each a separate

func buildMultiWrappedMutationStr(op OperationConfig, gqlName, bodySelection string) string {
	var varDecls []string
	var inputParts []string
	for _, mw := range op.MultiWrappedInputs {
		varDecls = append(varDecls, "$"+mw.GQLVar+": "+mw.SchemaType)
		inputParts = append(inputParts, mw.GQLVar+": $"+mw.GQLVar)
	}
	vars := strings.Join(varDecls, ", ")
	input := "{" + strings.Join(inputParts, ", ") + "}"
	return fmt.Sprintf("\nmutation %s(%s) {\n\t%s(input: %s) {\n\t\t%s\n\t}\n}\n", gqlName, vars, gqlName, input, bodySelection)
}

func buildInlineArgsMutationStr(op OperationConfig, gqlName, bodySelection string, wrapInItems bool, extraDecls, idField string) (string, error) {
	var varDecls []string
	var idArgPart string
	var inputParts []string
	hasInputPath := false
	for _, a := range op.InlineArgs {
		if a.InputPath != "" {
			hasInputPath = true
		}
	}
	for _, a := range op.InlineArgs {
		varDecls = append(varDecls, "$"+a.GQLVar+": "+a.GQLType)
		if a.IsID {
			idArgPart = a.GQLVar + ": $" + a.GQLVar
		} else if !hasInputPath {
			inputParts = append(inputParts, a.GQLVar+": $"+a.GQLVar)
		}
	}
	vars := strings.Join(varDecls, ", ")
	if extraDecls != "" {
		vars += ", " + extraDecls
	}
	var argPart string
	if hasInputPath {
		argPart = "input: " + buildNestedInputLiteralStr(op.InlineArgs)
	} else if idArgPart != "" {
		if len(inputParts) > 0 {
			argPart = idArgPart + ", input: {" + strings.Join(inputParts, ", ") + "}"
		} else {
			argPart = idArgPart
		}
	} else {
		argPart = "input: {" + strings.Join(inputParts, ", ") + "}"
	}
	if wrapInItems {
		wrapField := "items"
		if op.ResultPath != "" {
			parts := strings.Split(op.ResultPath, ".")
			if len(parts) >= 2 {
				wrapField = parts[len(parts)-1]
			}
		}
		return fmt.Sprintf("\nmutation %s(%s) {\n\t%s(%s) {\n\t\t%s {\n\t\t\t%s\n\t\t}\n\t}\n}\n", gqlName, vars, gqlName, argPart, wrapField, bodySelection), nil
	}
	return fmt.Sprintf("\nmutation %s(%s) {\n\t%s(%s) {\n\t\t%s\n\t}\n}\n", gqlName, vars, gqlName, argPart, bodySelection), nil
}

func buildDatePaginatedStr(gqlName, bodySelection, extraDecls string) (string, error) {
	varDecls := "$next: String, $pageSize: Int, $order: AuditLogsOrderInput, $condition: AuditLogsDateConditionInput"
	if extraDecls != "" {
		varDecls += ", " + extraDecls
	}
	return fmt.Sprintf("\nquery %s(\n\t%s\n) {\n\t%s(\n\t\tinput: {next: $next, pageSize: $pageSize, order: $order, condition: $condition}\n\t) {\n\t\titems {\n\t\t\t%s\n\t\t}\n\t\tpageInfo {\n\t\t\tnext\n\t\t\ttotal\n\t\t}\n\t}\n}\n", gqlName, varDecls, gqlName, bodySelection), nil
}

func buildCreateStr(schema *ast.Schema, inputTypeName, gqlName, fragRef string, allowedFields []string, extraDecls string) (string, error) {
	def := schema.Types[inputTypeName]
	if def == nil {
		return "", fmt.Errorf("input type %q not found", inputTypeName)
	}
	allowed := make(map[string]bool, len(allowedFields))
	for _, f := range allowedFields {
		allowed[f] = true
	}
	varDecls := make([]string, 0, len(def.Fields))
	inputParts := make([]string, 0, len(def.Fields))
	for _, f := range def.Fields {
		if len(allowed) > 0 && !allowed[f.Name] {
			continue
		}
		varDecls = append(varDecls, "$"+f.Name+": "+f.Type.String())
		inputParts = append(inputParts, f.Name+": $"+f.Name)
	}
	vars := strings.Join(varDecls, ", ")
	if extraDecls != "" {
		vars += ", " + extraDecls
	}
	input := "{" + strings.Join(inputParts, ", ") + "}"
	return fmt.Sprintf("\nmutation %s(%s) {\n\t%s(\n\t\tinput: %s\n\t) {\n\t\t%s\n\t}\n}\n", gqlName, vars, gqlName, input, fragRef), nil
}

func buildUpdateStr(schema *ast.Schema, inputTypeName, gqlName, fragRef, idField string, allowedFields []string, extraDecls string) (string, error) {
	def := schema.Types[inputTypeName]
	if def == nil {
		return "", fmt.Errorf("input type %q not found", inputTypeName)
	}
	allowed := make(map[string]bool, len(allowedFields))
	for _, f := range allowedFields {
		allowed[f] = true
	}
	varDecls := []string{"$" + idField + ": ID!"}
	inputParts := make([]string, 0, len(def.Fields))
	for _, f := range def.Fields {
		if len(allowed) > 0 && !allowed[f.Name] {
			continue
		}
		varDecls = append(varDecls, "$"+f.Name+": "+f.Type.String())
		inputParts = append(inputParts, f.Name+": $"+f.Name)
	}
	vars := strings.Join(varDecls, ", ")
	if extraDecls != "" {
		vars += ", " + extraDecls
	}
	input := "{" + strings.Join(inputParts, ", ") + "}"
	return fmt.Sprintf("\nmutation %s(%s) {\n\t%s(\n\t\t%s: $%s\n\t\tinput: %s\n\t) {\n\t\t%s\n\t}\n}\n", gqlName, vars, gqlName, idField, idField, input, fragRef), nil
}

func buildPaginatedListStr(schema *ast.Schema, gqlName, fragRef string, paginationVars map[string]any, extraDecls string, listItemFields []string, topLevelArgs []TopLevelArg) (string, error) {
	queryDef := schema.Query.Fields.ForName(gqlName)
	if queryDef == nil {
		return "", fmt.Errorf("query %q not found in schema", gqlName)
	}
	inputArg := queryDef.Arguments.ForName("input")
	if inputArg == nil {
		return "", fmt.Errorf("query %q has no 'input' argument", gqlName)
	}
	inputTypeName := inputArg.Type.NamedType
	// Fields whose paginationVars value is a map or null are passed as opaque object variables.
	opaqueFields := make(map[string]bool)
	for k, v := range paginationVars {
		if v == nil {
			opaqueFields[k] = true
		} else if _, ok := v.(map[string]any); ok {
			opaqueFields[k] = true
		}
	}
	nodes, err := buildInputTree(schema, inputTypeName, opaqueFields)
	if err != nil {
		return "", err
	}
	leaves := leafVars(nodes)
	varDecls := make([]string, 0, len(leaves)+len(topLevelArgs))
	for _, a := range topLevelArgs {
		varDecls = append(varDecls, "$"+a.GQLVar+": "+a.GQLType)
	}
	for _, leaf := range leaves {
		varDecls = append(varDecls, "$"+leaf.VarName+": "+leaf.TypeStr)
	}
	allDecls := strings.Join(varDecls, ", ")
	if extraDecls != "" {
		allDecls += ", " + extraDecls
	}
	constructor := buildConstructorStr(nodes)
	itemsContent := fragRef
	if len(listItemFields) > 0 {
		itemsContent = strings.Join(listItemFields, "\n\t\t\t")
	}
	var topArgStr strings.Builder
	for _, a := range topLevelArgs {
		topArgStr.WriteString(a.GQLVar + ": $" + a.GQLVar + "\n\t\t")
	}
	return fmt.Sprintf(
		"\nquery %s(%s) {\n\t%s(\n\t\t%sinput: %s\n\t) {\n\t\titems {\n\t\t\t%s\n\t\t}\n\t\tpageInfo {\n\t\t\tnext\n\t\t\ttotal\n\t\t}\n\t}\n}\n",
		gqlName, allDecls, gqlName, topArgStr.String(), constructor, itemsContent,
	), nil
}

// buildListItemsStr builds a query for list_items: field(input: {a: $a, b: $b}) { items { body } }.

func buildListItemsStr(op OperationConfig, gqlName, bodySelection, extraDecls string) string {
	argsByVar := make(map[string]InlineArg, len(op.InlineArgs))
	keys := make([]string, 0, len(op.InlineArgs))
	for _, a := range op.InlineArgs {
		argsByVar[a.GQLVar] = a
		keys = append(keys, a.GQLVar)
	}
	sort.Strings(keys)
	varDecls := make([]string, 0, len(keys))
	inputParts := make([]string, 0, len(keys))
	for _, k := range keys {
		a := argsByVar[k]
		varDecls = append(varDecls, "$"+a.GQLVar+": "+a.GQLType)
		inputParts = append(inputParts, a.GQLVar+": $"+a.GQLVar)
	}
	vars := strings.Join(varDecls, ", ")
	if extraDecls != "" {
		if vars != "" {
			vars += ", "
		}
		vars += extraDecls
	}
	varSig := ""
	if vars != "" {
		varSig = "(" + vars + ")"
	}
	fieldCall := gqlName
	if len(inputParts) > 0 {
		fieldCall = gqlName + "(input: {" + strings.Join(inputParts, ", ") + "})"
	}
	return fmt.Sprintf("\nquery %s%s {\n\t%s {\n\t\titems {\n\t\t\t%s\n\t\t}\n\t}\n}\n", gqlName, varSig, fieldCall, bodySelection)
}

func buildSimpleListStr(gqlName, fragRef string) string {
	return fmt.Sprintf("\nquery %s {\n\t%s {\n\t\titems {\n\t\t\t%s\n\t\t}\n\t}\n}\n", gqlName, gqlName, fragRef)
}
