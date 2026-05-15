// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"sort"
	"strings"
)

func buildMethodParts(op OperationConfig, kind, endpoint, returnType string, returnNullable bool, resultKey, constName, idField, rbacMap string, extraVarValues map[string]any) (sig, doc, body string, err error) {
	switch kind {
	case "get":
		sig = fmt.Sprintf("(ctx context.Context, %s string) (*%s, error)", idField, returnType)
		doc = fmt.Sprintf("// %s retrieves a %s by ID.", op.Name, lcFirst(returnType))
		body = buildGetBody(op.Name, returnType, resultKey, endpoint, constName, idField, rbacMap, extraVarValues)

	case "create":
		goInputName := op.InputType
		if op.InputTypeGoName != "" {
			goInputName = op.InputTypeGoName
		}
		sig = fmt.Sprintf("(ctx context.Context, input %s) (%s, error)", goInputName, returnType)
		doc = fmt.Sprintf("// %s creates a new %s.", op.Name, lcFirst(returnType))
		buildFn := "build" + strings.TrimSuffix(goInputName, "Input") + "Variables"
		body = buildCreateBody(op.Name, returnType, resultKey, endpoint, constName, buildFn, rbacMap, op.WrappedInput, extraVarValues)

	case "update":
		goInputName := op.InputType
		if op.InputTypeGoName != "" {
			goInputName = op.InputTypeGoName
		}
		sig = fmt.Sprintf("(ctx context.Context, %s string, input %s) (%s, error)", idField, goInputName, returnType)
		doc = fmt.Sprintf("// %s updates an existing %s.", op.Name, lcFirst(returnType))
		buildFn := "build" + strings.TrimSuffix(goInputName, "Input") + "Variables"
		body = buildUpdateBody(op.Name, returnType, resultKey, endpoint, constName, buildFn, idField, rbacMap, op.WrappedInput, extraVarValues)

	case "delete":
		sig = fmt.Sprintf("(ctx context.Context, %s string) error", idField)
		doc = fmt.Sprintf("// %s deletes a %s by ID.", op.Name, lcFirst(returnType))
		body = buildDeleteBody(op.Name, endpoint, constName, idField)

	case "singleton_get":
		retTypeExpr := returnType
		if op.ReturnIsList {
			retTypeExpr = "[]" + returnType
		}
		// Knob C: optional struct input appended after inline args.
		if op.InputType != "" {
			goInputName := op.InputType
			if op.InputTypeGoName != "" {
				goInputName = op.InputTypeGoName
			}
			if len(op.InlineArgs) > 0 {
				sigStr, _ := inlineArgsSignature(op.InlineArgs)
				sig = fmt.Sprintf("(ctx context.Context%s, input *%s) (%s, error)", sigStr, goInputName, retTypeExpr)
			} else {
				sig = fmt.Sprintf("(ctx context.Context, input *%s) (%s, error)", goInputName, retTypeExpr)
			}
		} else if len(op.InlineArgs) > 0 {
			sigStr, _ := inlineArgsSignature(op.InlineArgs)
			sig = fmt.Sprintf("(ctx context.Context%s) (%s, error)", sigStr, retTypeExpr)
		} else {
			sig = fmt.Sprintf("(ctx context.Context) (%s, error)", retTypeExpr)
		}
		doc = fmt.Sprintf("// %s retrieves the %s.", op.Name, lcFirst(returnType))
		body = buildSingletonGetBody(op.Name, returnType, resultKey, endpoint, constName, op.ResultPath, op.ResultPathTypes, extraVarValues, rbacMap, op.ReturnIsList, op.InlineArgs, op.InputType, op.InputTypeGoName)

	case "list":
		if len(op.TopLevelArgs) > 0 {
			var argParts []string
			for _, a := range op.TopLevelArgs {
				argParts = append(argParts, ", "+a.Name+" "+a.GoType)
			}
			sig = fmt.Sprintf("(ctx context.Context%s) ([]%s, error)", strings.Join(argParts, ""), returnType)
		} else {
			sig = fmt.Sprintf("(ctx context.Context) ([]%s, error)", returnType)
		}
		doc = fmt.Sprintf("// %s retrieves all %ss.", op.Name, lcFirst(returnType))
		if op.Pagination {
			body, err = buildListPaginatedBody(op.Name, returnType, resultKey, endpoint, constName, op.PaginationVars, rbacMap, op.TopLevelArgs)
		} else {
			body = buildListSimpleBody(op.Name, returnType, resultKey, endpoint, constName)
		}

	case "list_simple":
		sig = fmt.Sprintf("(ctx context.Context) ([]%s, error)", returnType)
		doc = fmt.Sprintf("// %s retrieves all %ss.", op.Name, lcFirst(returnType))
		body = buildListSimpleTopLevelBody(op.Name, returnType, resultKey, endpoint, constName)

	case "list_items":
		if len(op.InlineArgs) > 0 {
			sigStr, _ := inlineArgsSignature(op.InlineArgs)
			sig = fmt.Sprintf("(ctx context.Context%s) ([]%s, error)", sigStr, returnType)
		} else {
			sig = fmt.Sprintf("(ctx context.Context) ([]%s, error)", returnType)
		}
		doc = fmt.Sprintf("// %s retrieves %ss filtered by the given args.", op.Name, lcFirst(returnType))
		body = buildListItemsBody(op, returnType, resultKey, endpoint, constName)

	case "mutation_list":
		goInputName := op.InputType
		if op.InputTypeGoName != "" {
			goInputName = op.InputTypeGoName
		}
		if len(op.InlineArgs) > 0 {
			sigStr, _ := inlineArgsSignature(op.InlineArgs)
			sig = fmt.Sprintf("(ctx context.Context%s) ([]%s, error)", sigStr, returnType)
		} else {
			sig = fmt.Sprintf("(ctx context.Context, input %s) ([]%s, error)", goInputName, returnType)
		}
		doc = fmt.Sprintf("// %s bulk-updates %ss.", op.Name, lcFirst(returnType))
		body = buildMutationListBody(op, returnType, resultKey, endpoint, constName, rbacMap, extraVarValues)

	case "singleton_update":
		if op.GroupInputAs != "" {
			sig = fmt.Sprintf("(ctx context.Context, input %s) (%s, error)", op.GroupInputAs, returnType)
		} else {
			sigStr, _ := inlineArgsSignature(op.InlineArgs)
			sig = fmt.Sprintf("(ctx context.Context%s) (%s, error)", sigStr, returnType)
		}
		doc = fmt.Sprintf("// %s updates the %s.", op.Name, lcFirst(returnType))
		body = buildSingletonUpdateBody(op, returnType, resultKey, endpoint, constName, rbacMap, extraVarValues)

	case "multi_wrapped_update":
		goInputName := op.InputTypeGoName
		if goInputName == "" {
			err = fmt.Errorf("multi_wrapped_update op %q requires inputTypeGoName", op.Name)
			return
		}
		sig = fmt.Sprintf("(ctx context.Context, input %s) (%s, error)", goInputName, returnType)
		doc = fmt.Sprintf("// %s updates the %s.", op.Name, lcFirst(returnType))
		body = buildMultiWrappedUpdateBody(op, returnType, resultKey, endpoint, constName)

	case "update_inline":
		sigStr, _ := inlineArgsSignature(op.InlineArgs)
		sig = fmt.Sprintf("(ctx context.Context%s) (%s, error)", sigStr, returnType)
		doc = fmt.Sprintf("// %s updates a %s.", op.Name, lcFirst(returnType))
		body = buildUpdateInlineBody(op, returnType, resultKey, endpoint, constName, rbacMap, extraVarValues)

	case "date_paginated":
		argName := op.DateRangeArg
		if argName == "" {
			argName = "dateRange"
		}
		dateType := returnType + "DateRange"
		sig = fmt.Sprintf("(ctx context.Context, %s *%s) ([]%s, error)", argName, dateType, returnType)
		doc = fmt.Sprintf("// %s retrieves %ss within a date range.", op.Name, lcFirst(returnType))
		body = buildDatePaginatedBody(op.Name, returnType, resultKey, endpoint, constName, argName, dateType)

	default:
		err = fmt.Errorf("unsupported kind %q for method body", kind)
	}
	return
}

func buildMultiWrappedUpdateBody(op OperationConfig, returnType, resultKey, endpoint, constName string) string {
	tag := bt + `json:"` + resultKey + `"` + bt
	var parts []string
	for _, mw := range op.MultiWrappedInputs {
		parts = append(parts, fmt.Sprintf("%q: input.%s", mw.GQLVar, mw.GoField))
	}
	varsLit := "map[string]any{" + strings.Join(parts, ", ") + "}"
	return fmt.Sprintf(
		"vars := %s\n\tvar result struct {\n\t\t%s %s %s\n\t}\n\tif err := c.transport.DoGraphQL(ctx, %q, %s, vars, &result); err != nil {\n\t\treturn %s, fmt.Errorf(\"%s: %%w\", err)\n\t}\n\treturn result.%s, nil",
		varsLit, toPascalCase(resultKey), returnType, tag, endpoint, constName, zeroVal(returnType), op.Name, toPascalCase(resultKey))
}

// buildMultiWrappedInputTypes generates all input structs for a multi_wrapped_update operation:

func buildSingletonGetBody(methodName, returnType, resultKey, endpoint, constName, resultPath string, resultPathTypes []string, extraVarValues map[string]any, rbacMap string, returnIsList bool, inlineArgs []InlineArg, inputType, inputTypeGoName string) string {
	varsArg := "nil"
	varAssignPrefix := ""
	if len(inlineArgs) > 0 {
		// Build conditional or unconditional vars from inline args.
		var sb strings.Builder
		allOptional := true
		for _, a := range inlineArgs {
			if !a.IsOptional {
				allOptional = false
				break
			}
		}
		if allOptional && len(inlineArgs) == 1 {
			// Single optional arg: var vars map[string]any; if arg != zero { vars = map[string]any{...} }
			a := inlineArgs[0]
			zeroCheck := a.Name + ` != ""`
			if a.GoType == "bool" {
				zeroCheck = a.Name
			} else if strings.HasPrefix(a.GoType, "*") || strings.HasPrefix(a.GoType, "[]") {
				zeroCheck = a.Name + " != nil"
			}
			fmt.Fprintf(&sb, "var vars map[string]any\n\tif %s {\n\t\tvars = map[string]any{%q: %s}\n\t}\n\t", zeroCheck, a.GQLVar, a.Name)
		} else {
			// All required or multiple args: build static map.
			sb.WriteString("vars := map[string]any{")
			for i, a := range inlineArgs {
				if i > 0 {
					sb.WriteString(", ")
				}
				fmt.Fprintf(&sb, "%q: %s", a.GQLVar, a.Name)
			}
			sb.WriteString("}\n\t")
		}
		varAssignPrefix = sb.String()
		varsArg = "vars"
	} else if len(extraVarValues) > 0 || rbacMap != "" {
		var baseLit string
		if len(extraVarValues) > 0 {
			baseLit = buildMapLit(extraVarValues)
		} else {
			baseLit = "map[string]any{}"
		}
		if rbacMap != "" {
			varAssignPrefix = "vars := mergeVars(" + baseLit + ", " + rbacMap + ")\n\t"
		} else {
			varAssignPrefix = "vars := " + baseLit + "\n\t"
		}
		varsArg = "vars"
	}

	// Knob C: optional struct input — conditionally set vars["input"] from *T arg.
	if inputType != "" {
		if varAssignPrefix == "" {
			varAssignPrefix = "vars := map[string]any{}\n\t"
			varsArg = "vars"
		}
		goInputName := inputType
		if inputTypeGoName != "" {
			goInputName = inputTypeGoName
		}
		baseName := strings.TrimSuffix(goInputName, "Input")
		buildFn := "build" + baseName + "Variables"
		varAssignPrefix += "if input != nil {\n\t\tvars[\"input\"] = " + buildFn + "(*input)\n\t}\n\t"
	}

	// Build the inner type expression and the zero-value expression for error returns.
	innerType := returnType
	zeroExpr := primitiveZeroExpr(returnType)
	if returnIsList {
		innerType = "[]" + returnType
		zeroExpr = "nil"
	}

	if resultPath == "" {
		tag := bt + `json:"` + resultKey + `"` + bt
		return fmt.Sprintf(
			"%svar result struct {\n\t\t%s %s %s\n\t}\n\tif err := c.transport.DoGraphQL(ctx, %q, %s, %s, &result); err != nil {\n\t\treturn %s, fmt.Errorf(\"%s: %%w\", err)\n\t}\n\treturn result.%s, nil",
			varAssignPrefix, methodName, innerType, tag, endpoint, constName, varsArg, zeroExpr, methodName, methodName)
	}

	parts := strings.Split(resultPath, ".")
	var b strings.Builder
	b.WriteString(varAssignPrefix)
	b.WriteString("var result struct {\n")
	indent := "\t\t"
	closers := []string{}
	for i, part := range parts {
		fieldGoName := toPascalCase(part)
		if i == len(parts)-1 {
			fmt.Fprintf(&b, "%s%s %s %sjson:\"%s\"%s\n", indent, fieldGoName, innerType, bt, part, bt)
		} else {
			fmt.Fprintf(&b, "%s%s struct {\n", indent, fieldGoName)
			closers = append(closers, indent+"} "+bt+"json:\""+part+"\""+bt)
			indent += "\t"
		}
	}
	for i := len(closers) - 1; i >= 0; i-- {
		b.WriteString(closers[i] + "\n")
	}
	b.WriteString("\t}\n")
	fmt.Fprintf(&b, "\tif err := c.transport.DoGraphQL(ctx, %q, %s, %s, &result); err != nil {\n\t\treturn %s, fmt.Errorf(\"%s: %%w\", err)\n\t}\n", endpoint, constName, varsArg, zeroExpr, methodName)
	var accessor strings.Builder
	accessor.WriteString("result")
	for _, part := range parts {
		accessor.WriteString("." + toPascalCase(part))
	}
	fmt.Fprintf(&b, "\treturn %s, nil", accessor.String())
	return b.String()
}

// buildListItemsBody emits the method body for a list_items op:
// builds vars from inline args (optional ones included only when non-zero), unwraps

func buildListItemsBody(op OperationConfig, returnType, resultKey, endpoint, constName string) string {
	var sb strings.Builder
	hasOptional := false
	hasRequired := false
	for _, a := range op.InlineArgs {
		if a.IsOptional {
			hasOptional = true
		} else {
			hasRequired = true
		}
	}
	if hasOptional && !hasRequired {
		sb.WriteString("vars := map[string]any{}\n\t")
		for _, a := range op.InlineArgs {
			fmt.Fprintf(&sb, "if %s {\n\t\tvars[%q] = %s\n\t}\n\t", inlineArgZeroCheck(a), a.GQLVar, a.Name)
		}
	} else if hasRequired && !hasOptional {
		sb.WriteString("vars := map[string]any{")
		for i, a := range op.InlineArgs {
			if i > 0 {
				sb.WriteString(", ")
			}
			fmt.Fprintf(&sb, "%q: %s", a.GQLVar, a.Name)
		}
		sb.WriteString("}\n\t")
	} else if hasOptional && hasRequired {
		sb.WriteString("vars := map[string]any{")
		first := true
		for _, a := range op.InlineArgs {
			if a.IsOptional {
				continue
			}
			if !first {
				sb.WriteString(", ")
			}
			first = false
			fmt.Fprintf(&sb, "%q: %s", a.GQLVar, a.Name)
		}
		sb.WriteString("}\n\t")
		for _, a := range op.InlineArgs {
			if !a.IsOptional {
				continue
			}
			fmt.Fprintf(&sb, "if %s {\n\t\tvars[%q] = %s\n\t}\n\t", inlineArgZeroCheck(a), a.GQLVar, a.Name)
		}
	} else {
		sb.WriteString("var vars map[string]any\n\t")
	}
	outerTag := bt + `json:"` + resultKey + `"` + bt
	innerTag := bt + `json:"items"` + bt
	fmt.Fprintf(&sb,
		"var result struct {\n\t\t%s struct {\n\t\t\tItems []%s %s\n\t\t} %s\n\t}\n\tif err := c.transport.DoGraphQL(ctx, %q, %s, vars, &result); err != nil {\n\t\treturn nil, fmt.Errorf(\"%s: %%w\", err)\n\t}\n\treturn result.%s.Items, nil",
		toPascalCase(resultKey), returnType, innerTag, outerTag,
		endpoint, constName, op.Name, toPascalCase(resultKey))
	return sb.String()
}

// inlineArgZeroCheck produces a Go expression that's true when the arg is non-zero

func buildListSimpleTopLevelBody(methodName, returnType, resultKey, endpoint, constName string) string {
	// For queries like `listInsights: [Insight]` returning [T] directly (not wrapped in items).
	tag := bt + `json:"` + resultKey + `"` + bt
	return fmt.Sprintf(
		"var result struct {\n\t\t%s []%s %s\n\t}\n\tif err := c.transport.DoGraphQL(ctx, %q, %s, nil, &result); err != nil {\n\t\treturn nil, fmt.Errorf(\"%s: %%w\", err)\n\t}\n\treturn result.%s, nil",
		toPascalCase(resultKey), returnType, tag, endpoint, constName, methodName, toPascalCase(resultKey))
}

func buildMutationListBody(op OperationConfig, returnType, resultKey, endpoint, constName, rbacMap string, extraVarValues map[string]any) string {
	var varAssign string
	if len(op.InlineArgs) > 0 {
		var parts []string
		for _, a := range op.InlineArgs {
			parts = append(parts, fmt.Sprintf("%q: %s", a.GQLVar, a.Name))
		}
		baseLit := "map[string]any{" + strings.Join(parts, ", ") + "}"
		varAssign = mergeVarsExpr(baseLit, buildMapLit(extraVarValues), rbacMap)
	} else {
		goInputName := op.InputType
		if op.InputTypeGoName != "" {
			goInputName = op.InputTypeGoName
		}
		buildFn := "build" + strings.TrimSuffix(goInputName, "Input") + "Variables"
		baseLit := buildFn + "(input)"
		varAssign = mergeVarsExpr(baseLit, buildMapLit(extraVarValues), rbacMap)
	}

	// Default shape: result.<MethodName>.Items where Items = []ReturnType.
	if op.ResultPath == "" {
		outerTag := bt + `json:"` + resultKey + `"` + bt
		innerTag := bt + `json:"items"` + bt
		return fmt.Sprintf(
			"%s\n\tvar result struct {\n\t\t%s struct {\n\t\t\tItems []%s %s\n\t\t} %s\n\t}\n\tif err := c.transport.DoGraphQL(ctx, %q, %s, vars, &result); err != nil {\n\t\treturn nil, fmt.Errorf(\"%s: %%w\", err)\n\t}\n\treturn result.%s.Items, nil",
			varAssign, toPascalCase(resultKey), returnType, innerTag, outerTag, endpoint, constName, op.Name, toPascalCase(resultKey))
	}

	// Custom path: e.g. "updateBetaAcceptanceStatus.betaAcceptanceStatus" → result.UpdateBetaAcceptanceStatus.BetaAcceptanceStatus
	parts := strings.Split(op.ResultPath, ".")
	var b strings.Builder
	b.WriteString(varAssign)
	b.WriteString("\n\tvar result struct {\n")
	indent := "\t\t"
	closers := []string{}
	for i, part := range parts {
		fieldGoName := toPascalCase(part)
		if i == len(parts)-1 {
			fmt.Fprintf(&b, "%s%s []%s %sjson:\"%s\"%s\n", indent, fieldGoName, returnType, bt, part, bt)
		} else {
			fmt.Fprintf(&b, "%s%s struct {\n", indent, fieldGoName)
			closers = append(closers, indent+"} "+bt+"json:\""+part+"\""+bt)
			indent += "\t"
		}
	}
	for i := len(closers) - 1; i >= 0; i-- {
		b.WriteString(closers[i] + "\n")
	}
	b.WriteString("\t}\n")
	fmt.Fprintf(&b, "\tif err := c.transport.DoGraphQL(ctx, %q, %s, vars, &result); err != nil {\n\t\treturn nil, fmt.Errorf(\"%s: %%w\", err)\n\t}\n", endpoint, constName, op.Name)
	var accessor strings.Builder
	accessor.WriteString("result")
	for _, part := range parts {
		accessor.WriteString("." + toPascalCase(part))
	}
	fmt.Fprintf(&b, "\treturn %s, nil", accessor.String())
	return b.String()
}

func buildSingletonUpdateBody(op OperationConfig, returnType, resultKey, endpoint, constName, rbacMap string, extraVarValues map[string]any) string {
	var parts []string
	for _, a := range op.InlineArgs {
		goAccess := a.Name
		if op.GroupInputAs != "" {
			goAccess = "input." + toPascalCase(a.Name)
		}
		parts = append(parts, fmt.Sprintf("%q: %s", a.GQLVar, goAccess))
	}
	baseLit := "map[string]any{" + strings.Join(parts, ", ") + "}"
	varAssign := mergeVarsExpr(baseLit, buildMapLit(extraVarValues), rbacMap)

	if op.ResultPath == "" {
		tag := bt + `json:"` + resultKey + `"` + bt
		return fmt.Sprintf(
			"%s\n\tvar result struct {\n\t\t%s %s %s\n\t}\n\tif err := c.transport.DoGraphQL(ctx, %q, %s, vars, &result); err != nil {\n\t\treturn %s, fmt.Errorf(\"%s: %%w\", err)\n\t}\n\treturn result.%s, nil",
			varAssign, toPascalCase(resultKey), returnType, tag, endpoint, constName, zeroVal(returnType), op.Name, toPascalCase(resultKey))
	}

	// resultPath: build nested result struct (mirrors buildSingletonGetBody).
	pathParts := strings.Split(op.ResultPath, ".")
	var b strings.Builder
	b.WriteString(varAssign)
	b.WriteString("\n\tvar result struct {\n")
	indent := "\t\t"
	var closers []string
	for i, part := range pathParts {
		fieldGoName := toPascalCase(part)
		if i == len(pathParts)-1 {
			fmt.Fprintf(&b, "%s%s %s %sjson:\"%s\"%s\n", indent, fieldGoName, returnType, bt, part, bt)
		} else {
			fmt.Fprintf(&b, "%s%s struct {\n", indent, fieldGoName)
			closers = append(closers, indent+"} "+bt+"json:\""+part+"\""+bt)
			indent += "\t"
		}
	}
	for i := len(closers) - 1; i >= 0; i-- {
		b.WriteString(closers[i] + "\n")
	}
	b.WriteString("\t}\n")
	fmt.Fprintf(&b, "\tif err := c.transport.DoGraphQL(ctx, %q, %s, vars, &result); err != nil {\n\t\treturn %s, fmt.Errorf(\"%s: %%w\", err)\n\t}\n", endpoint, constName, zeroVal(returnType), op.Name)
	var accessor strings.Builder
	accessor.WriteString("result")
	for _, part := range pathParts {
		accessor.WriteString("." + toPascalCase(part))
	}
	fmt.Fprintf(&b, "\treturn %s, nil", accessor.String())
	return b.String()
}

func buildUpdateInlineBody(op OperationConfig, returnType, resultKey, endpoint, constName, rbacMap string, extraVarValues map[string]any) string {
	tag := bt + `json:"` + resultKey + `"` + bt
	var parts []string
	var idArg string
	for _, a := range op.InlineArgs {
		parts = append(parts, fmt.Sprintf("%q: %s", a.GQLVar, a.Name))
		if a.IsID {
			idArg = a.Name
		}
	}
	baseLit := "map[string]any{" + strings.Join(parts, ", ") + "}"
	varAssign := mergeVarsExpr(baseLit, buildMapLit(extraVarValues), rbacMap)
	if idArg == "" {
		idArg = "id"
	}
	return fmt.Sprintf(
		"%s\n\tvar result struct {\n\t\t%s %s %s\n\t}\n\tif err := c.transport.DoGraphQL(ctx, %q, %s, vars, &result); err != nil {\n\t\treturn %s, fmt.Errorf(\"%s(%%s): %%w\", %s, err)\n\t}\n\treturn result.%s, nil",
		varAssign, toPascalCase(resultKey), returnType, tag, endpoint, constName, zeroVal(returnType), op.Name, idArg, toPascalCase(resultKey))
}

func buildDatePaginatedBody(methodName, returnType, resultKey, endpoint, constName, argName, dateType string) string {
	// Generates the per-resource fetch loop and date helper invocation.
	// Uses %sCondition() builder (which the static-emit code must provide).
	localVar := lcFirst(returnType) + "s"
	return fmt.Sprintf(`vars := map[string]any{
		"pageSize":  500,
		"order":     map[string]any{"direction": "DESC"},
		"condition": %sCondition(%s),
	}
	%s, err := c.fetchAll%ss(ctx, %s, vars, %q)
	if err != nil {
		return nil, fmt.Errorf("%s: %%w", err)
	}
	return %s, nil`,
		lcFirst(returnType), argName,
		localVar, returnType, constName, resultKey,
		methodName, localVar)
}

func buildGetBody(methodName, returnType, resultKey, endpoint, constName, idField, rbacMap string, extraVarValues map[string]any) string {
	tag := bt + `json:"` + resultKey + `"` + bt
	baseVarsLit := fmt.Sprintf("map[string]any{%q: %s}", idField, idField)
	varAssign := mergeVarsExpr(baseVarsLit, buildMapLit(extraVarValues), rbacMap)
	return fmt.Sprintf(
		"%s\n\tvar result struct {\n\t\t%s *%s %s\n\t}\n\tif err := c.transport.DoGraphQL(ctx, %q, %s, vars, &result); err != nil {\n\t\treturn nil, fmt.Errorf(\"%s(%%s): %%w\", %s, err)\n\t}\n\treturn result.%s, nil",
		varAssign, methodName, returnType, tag, endpoint, constName, methodName, idField, methodName)
}

func buildCreateBody(methodName, returnType, resultKey, endpoint, constName, buildFn, rbacMap string, wrappedInput bool, extraVarValues map[string]any) string {
	tag := bt + `json:"` + resultKey + `"` + bt
	var baseLit string
	if wrappedInput {
		baseLit = `map[string]any{"input": ` + buildFn + `(input)}`
	} else {
		baseLit = buildFn + "(input)"
	}
	varAssign := mergeVarsExpr(baseLit, buildMapLit(extraVarValues), rbacMap)
	return fmt.Sprintf(
		"%s\n\tvar result struct {\n\t\t%s %s %s\n\t}\n\tif err := c.transport.DoGraphQL(ctx, %q, %s, vars, &result); err != nil {\n\t\treturn %s, fmt.Errorf(\"%s: %%w\", err)\n\t}\n\treturn result.%s, nil",
		varAssign, methodName, returnType, tag, endpoint, constName, zeroVal(returnType), methodName, methodName)
}

func buildUpdateBody(methodName, returnType, resultKey, endpoint, constName, buildFn, idField, rbacMap string, wrappedInput bool, extraVarValues map[string]any) string {
	tag := bt + `json:"` + resultKey + `"` + bt
	var varLines string
	if wrappedInput {
		baseLit := fmt.Sprintf(`map[string]any{%q: %s, "input": `+buildFn+`(input)}`, idField, idField)
		varLines = mergeVarsExpr(baseLit, buildMapLit(extraVarValues), rbacMap)
	} else {
		baseLit := buildFn + "(input)"
		assign := mergeVarsExpr(baseLit, buildMapLit(extraVarValues), rbacMap)
		varLines = assign + "\n\tvars[" + fmt.Sprintf("%q", idField) + "] = " + idField
	}
	return fmt.Sprintf(
		"%s\n\tvar result struct {\n\t\t%s %s %s\n\t}\n\tif err := c.transport.DoGraphQL(ctx, %q, %s, vars, &result); err != nil {\n\t\treturn %s, fmt.Errorf(\"%s(%%s): %%w\", %s, err)\n\t}\n\treturn result.%s, nil",
		varLines, methodName, returnType, tag, endpoint, constName, zeroVal(returnType), methodName, idField, methodName)
}

func buildDeleteBody(methodName, endpoint, constName, idField string) string {
	return fmt.Sprintf(
		"vars := map[string]any{%q: %s}\n\tif err := c.transport.DoGraphQL(ctx, %q, %s, vars, nil); err != nil {\n\t\treturn fmt.Errorf(\"%s(%%s): %%w\", %s, err)\n\t}\n\treturn nil",
		idField, idField, endpoint, constName, methodName, idField)
}

func buildListPaginatedBody(methodName, returnType, resultKey, endpoint, constName string, paginationVars map[string]any, rbacMap string, topLevelArgs []TopLevelArg) (string, error) {
	localVar := lcFirst(returnType) + "s"
	keys := make([]string, 0, len(paginationVars))
	for k := range paginationVars {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var varEntries []string
	for _, k := range keys {
		val := formatGoLiteral(paginationVars[k])
		varEntries = append(varEntries, fmt.Sprintf("\t\t%q: %s,", k, val))
	}
	// Top-level args are added to the vars map by name so they're forwarded to client.ListAll.
	for _, a := range topLevelArgs {
		varEntries = append(varEntries, fmt.Sprintf("\t\t%q: %s,", a.GQLVar, a.Name))
	}
	sort.Strings(varEntries)
	varsStr := strings.Join(varEntries, "\n")
	paginationMapLit := fmt.Sprintf("map[string]any{\n%s\n\t}", varsStr)
	var varsExpr string
	if rbacMap != "" {
		varsExpr = "mergeVars(" + paginationMapLit + ", " + rbacMap + ")"
	} else {
		varsExpr = paginationMapLit
	}
	var errCall string
	if len(topLevelArgs) > 0 {
		errCall = fmt.Sprintf(`fmt.Errorf("%s(%%s): %%w", %s, err)`, methodName, topLevelArgs[0].Name)
	} else {
		errCall = fmt.Sprintf(`fmt.Errorf("%s: %%w", err)`, methodName)
	}
	return fmt.Sprintf(
		"%s, err := client.ListAll[%s](ctx, c.transport, %q, %s, %s, %q)\n\tif err != nil {\n\t\treturn nil, %s\n\t}\n\treturn %s, nil",
		localVar, returnType, endpoint, constName, varsExpr, resultKey, errCall, localVar), nil
}

func buildListSimpleBody(methodName, returnType, resultKey, endpoint, constName string) string {
	localVar := lcFirst(returnType) + "s"
	outerTag := bt + `json:"` + resultKey + `"` + bt
	innerTag := bt + `json:"items"` + bt
	return fmt.Sprintf(
		"var result struct {\n\t\t%s struct {\n\t\t\tItems []%s %s\n\t\t} %s\n\t}\n\tif err := c.transport.DoGraphQL(ctx, %q, %s, nil, &result); err != nil {\n\t\treturn nil, fmt.Errorf(\"%s: %%w\", err)\n\t}\n\t%s := result.%s.Items\n\treturn %s, nil",
		toPascalCase(resultKey), returnType, innerTag, outerTag,
		endpoint, constName, methodName,
		localVar, toPascalCase(resultKey), localVar)
}
