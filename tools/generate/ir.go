// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
)

// bt is a backtick character, used when building Go source strings that need struct tags.
const bt = "`"

// IRResource is the fully-resolved intermediate representation for one resource file.
type IRResource struct {
	TypeName       string
	File           string
	FragConst      string // fragment const name, e.g. "roleFields"
	Fragment       string // GQL fragment string (content of the const)
	GoType         IRStruct
	NestedTypes    []IRStruct
	InputTypes     []IRStruct
	Operations     []IROperation
	BuildVarsFuncs []IRBuildVarsFunc
	NeedClient     bool // true when any operation uses client.ListAll
}

// IRStruct is a Go struct definition.
type IRStruct struct {
	Comment string
	Name    string
	Fields  []IRField
	IsInput bool
}

// IRField is one field in a Go struct.
type IRField struct {
	Name    string
	JSONTag string // empty for input structs
	Type    string // Go type name
}

// IROperation is one Client method plus the associated query/mutation constant.
type IROperation struct {
	DocComment string
	MethodName string
	Signature  string // e.g. "(ctx context.Context, id string) (*Role, error)"
	MethodBody string // pre-built Go method body
	ConstName  string // e.g. "getRoleQuery"
	QueryStr   string // GQL query/mutation string (without fragment appended)
	FragConst  string // fragment const name to append, e.g. "roleFields"
	Pagination bool
}

// IRBuildVarsFunc is the buildXxxVariables helper emitted alongside each input type.
type IRBuildVarsFunc struct {
	Name      string // e.g. "buildRoleVariables"
	InputType string // e.g. "RoleInput"
	Vars      []BuildVar
}

// BuildVar is one key-value entry in a buildXxxVariables return literal.
type BuildVar struct {
	Key      string // GQL variable name, e.g. "readResources"
	GoAccess string // Go field name on the input struct, e.g. "ReadResources"
}

func buildIR(cfg Config, schema *ast.Schema, res ResourceConfig) (IRResource, error) {
	nestedGoNames := make(map[string]string)
	nestedFieldRenames := make(map[string]map[string]string)
	nestedFieldLists := make(map[string][]string) // schemaName → allowed fields (nil = all)
	for _, nt := range res.NestedTypes {
		nestedGoNames[nt.SchemaName] = nt.GoName
		if len(nt.FieldRenames) > 0 {
			nestedFieldRenames[nt.SchemaName] = nt.FieldRenames
		}
		if len(nt.Fields) > 0 {
			nestedFieldLists[nt.SchemaName] = nt.Fields
		}
	}

	fragConst := lcFirst(res.TypeName) + "Fields"

	fragment, err := buildFragment(schema, res, nestedFieldLists)
	if err != nil {
		return IRResource{}, fmt.Errorf("fragment: %w", err)
	}

	mainType, nestedTypes, err := buildResponseTypes(schema, res, nestedGoNames, nestedFieldRenames, nestedFieldLists, cfg.Scalars)
	if err != nil {
		return IRResource{}, fmt.Errorf("response types: %w", err)
	}

	inputTypes, buildVarsFuncs, err := buildInputTypesAndHelpers(schema, res, cfg.Scalars)
	if err != nil {
		return IRResource{}, fmt.Errorf("input types: %w", err)
	}

	ops, err := buildOperations(schema, res, fragConst, cfg.Scalars)
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
		NeedClient:     needClient,
	}, nil
}

func buildFragment(schema *ast.Schema, res ResourceConfig, nestedFieldLists map[string][]string) (string, error) {
	schemaTypeName := res.SchemaTypeName()
	def := schema.Types[schemaTypeName]
	if def == nil {
		return "", fmt.Errorf("type %q not found in schema", schemaTypeName)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\nfragment %sFields on %s {\n", res.TypeName, schemaTypeName)
	for _, fieldName := range res.Fields {
		f := def.Fields.ForName(fieldName)
		if f == nil {
			return "", fmt.Errorf("field %q not on type %s", fieldName, schemaTypeName)
		}
		base := baseTypeName(f.Type)
		fieldDef := schema.Types[base]
		directive := res.DirectiveFields[fieldName]
		if fieldDef != nil && (fieldDef.Kind == ast.Object || fieldDef.Kind == ast.Interface) {
			if directive != "" {
				b.WriteString("\t" + fieldName + " " + directive + " {\n")
			} else {
				b.WriteString("\t" + fieldName + " {\n")
			}
			allowed := nestedFieldLists[base]
			if len(allowed) > 0 {
				for _, sf := range allowed {
					b.WriteString("\t\t" + sf + "\n")
				}
			} else {
				for _, sf := range fieldDef.Fields {
					b.WriteString("\t\t" + sf.Name + "\n")
				}
			}
			b.WriteString("\t}\n")
		} else {
			if directive != "" {
				b.WriteString("\t" + fieldName + " " + directive + "\n")
			} else {
				b.WriteString("\t" + fieldName + "\n")
			}
		}
	}
	b.WriteString("}\n")
	return b.String(), nil
}

func buildResponseTypes(schema *ast.Schema, res ResourceConfig, nestedGoNames map[string]string, nestedFieldRenames map[string]map[string]string, nestedFieldLists map[string][]string, scalars map[string]string) (IRStruct, []IRStruct, error) {
	schemaTypeName := res.SchemaTypeName()
	def := schema.Types[schemaTypeName]
	if def == nil {
		return IRStruct{}, nil, fmt.Errorf("type %q not found in schema", schemaTypeName)
	}

	var mainFields []IRField
	var nestedTypes []IRStruct
	seenNested := make(map[string]bool)

	for _, fieldName := range res.Fields {
		f := def.Fields.ForName(fieldName)
		if f == nil {
			return IRStruct{}, nil, fmt.Errorf("field %q not on type %s", fieldName, schemaTypeName)
		}
		goType := resolveGoType(f.Type, schema, scalars, nestedGoNames)
		mainFields = append(mainFields, IRField{
			Name:    toPascalCase(fieldName),
			JSONTag: fieldName,
			Type:    goType,
		})

		base := baseTypeName(f.Type)
		fieldDef := schema.Types[base]
		if fieldDef != nil && (fieldDef.Kind == ast.Object || fieldDef.Kind == ast.Interface) && !seenNested[base] {
			seenNested[base] = true
			goTypeName := base
			if override, ok := nestedGoNames[base]; ok {
				goTypeName = override
			}
			ns, err := buildNestedStruct(schema, base, goTypeName, nestedFieldRenames[base], nestedFieldLists[base], scalars, nestedGoNames)
			if err != nil {
				return IRStruct{}, nil, err
			}
			nestedTypes = append(nestedTypes, ns)
		}
	}

	mainStruct := IRStruct{
		Comment: fmt.Sprintf("// %s represents a Jamf Protect %s.", res.TypeName, lcFirst(res.TypeName)),
		Name:    res.TypeName,
		Fields:  mainFields,
	}
	return mainStruct, nestedTypes, nil
}

func buildNestedStruct(schema *ast.Schema, schemaTypeName, goTypeName string, fieldRenames map[string]string, allowedFields []string, scalars map[string]string, nestedOverrides map[string]string) (IRStruct, error) {
	def := schema.Types[schemaTypeName]
	if def == nil {
		return IRStruct{}, fmt.Errorf("type %q not found in schema", schemaTypeName)
	}
	allowed := make(map[string]bool, len(allowedFields))
	for _, f := range allowedFields {
		allowed[f] = true
	}
	var fields []IRField
	for _, f := range def.Fields {
		if len(allowed) > 0 && !allowed[f.Name] {
			continue
		}
		goName := toPascalCase(f.Name)
		if renamed, ok := fieldRenames[f.Name]; ok {
			goName = renamed
		}
		fields = append(fields, IRField{
			Name:    goName,
			JSONTag: f.Name,
			Type:    resolveGoType(f.Type, schema, scalars, nestedOverrides),
		})
	}
	return IRStruct{
		Comment: fmt.Sprintf("// %s contains %s data.", goTypeName, schemaTypeName),
		Name:    goTypeName,
		Fields:  fields,
	}, nil
}

func buildInputTypesAndHelpers(schema *ast.Schema, res ResourceConfig, scalars map[string]string) ([]IRStruct, []IRBuildVarsFunc, error) {
	seen := make(map[string]bool)
	var inputTypes []IRStruct
	var buildVarsFuncs []IRBuildVarsFunc

	// Build a set of allowed input fields if the config specifies a subset.
	allowedInputFields := make(map[string]bool)
	for _, f := range res.InputFields {
		allowedInputFields[f] = true
	}

	for _, op := range res.Operations {
		if op.InputType == "" || seen[op.InputType] {
			continue
		}
		seen[op.InputType] = true

		def := schema.Types[op.InputType]
		if def == nil {
			return nil, nil, fmt.Errorf("input type %q not found in schema", op.InputType)
		}

		var fields []IRField
		var buildVars []BuildVar
		for _, f := range def.Fields {
			if len(allowedInputFields) > 0 && !allowedInputFields[f.Name] {
				continue
			}
			goName := toPascalCase(f.Name)
			fields = append(fields, IRField{
				Name: goName,
				Type: resolveInputGoType(f.Type, schema, scalars),
			})
			buildVars = append(buildVars, BuildVar{
				Key:      f.Name,
				GoAccess: goName,
			})
		}

		goInputName := op.InputType
		if op.InputTypeGoName != "" {
			goInputName = op.InputTypeGoName
		}
		baseName := strings.TrimSuffix(goInputName, "Input")
		inputTypes = append(inputTypes, IRStruct{
			Comment: fmt.Sprintf("// %s is the input for %s operations.", goInputName, lcFirst(baseName)),
			Name:    goInputName,
			Fields:  fields,
			IsInput: true,
		})
		buildVarsFuncs = append(buildVarsFuncs, IRBuildVarsFunc{
			Name:      "build" + baseName + "Variables",
			InputType: goInputName,
			Vars:      buildVars,
		})
	}
	return inputTypes, buildVarsFuncs, nil
}

func buildOperations(schema *ast.Schema, res ResourceConfig, fragConst string, scalars map[string]string) ([]IROperation, error) {
	var ops []IROperation
	for _, opCfg := range res.Operations {
		op, err := buildOperation(schema, res, opCfg, fragConst, scalars)
		if err != nil {
			return nil, fmt.Errorf("op %s: %w", opCfg.Name, err)
		}
		ops = append(ops, op)
	}
	return ops, nil
}

func buildOperation(schema *ast.Schema, res ResourceConfig, op OperationConfig, fragConst string, scalars map[string]string) (IROperation, error) {
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

	isMutation := kind == "create" || kind == "update" || kind == "delete"
	suffix := "Query"
	if isMutation {
		suffix = "Mutation"
	}
	constName := lcFirst(op.Name) + suffix

	queryStr, err := buildQueryStr(schema, op, res, gqlName, kind)
	if err != nil {
		return IROperation{}, err
	}

	idField := res.IDField
	if idField == "" {
		idField = "id"
	}
	sig, doc, body, err := buildMethodParts(op, kind, endpoint, returnType, returnNullable, resultKey, constName, idField, res.RBACMap, res.ExtraVarValues)
	if err != nil {
		return IROperation{}, err
	}

	// Delete ops return only the id field and don't use the fragment — omit fragConst
	// so the full fragment body (with directives) isn't included in the delete mutation string.
	opFragConst := fragConst
	if kind == "delete" {
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

// extraVarDeclStr builds a comma-separated GQL variable declaration string from extraVars.
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

func buildQueryStr(schema *ast.Schema, op OperationConfig, res ResourceConfig, gqlName, kind string) (string, error) {
	fragRef := "..." + res.TypeName + "Fields"
	idField := res.IDField
	if idField == "" {
		idField = "id"
	}

	// Extra var declarations are added to all ops that use the fragment (not delete).
	extraDecls := ""
	if kind != "delete" {
		extraDecls = extraVarDeclStr(res.ExtraVars)
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
		return buildCreateStr(schema, op.InputType, gqlName, fragRef, res.InputFields, extraDecls)

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
		return buildUpdateStr(schema, op.InputType, gqlName, fragRef, idField, res.InputFields, extraDecls)

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
		return fmt.Sprintf("\nquery %s {\n\t%s {\n\t\t%s\n\t}\n}\n", gqlName, fieldRef, fragRef), nil

	case "list":
		if op.Pagination {
			return buildPaginatedListStr(schema, gqlName, fragRef, op.PaginationVars, extraDecls)
		}
		return buildSimpleListStr(gqlName, fragRef), nil

	default:
		return "", fmt.Errorf("unsupported kind %q", kind)
	}
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

func buildPaginatedListStr(schema *ast.Schema, gqlName, fragRef string, paginationVars map[string]any, extraDecls string) (string, error) {
	queryDef := schema.Query.Fields.ForName(gqlName)
	if queryDef == nil {
		return "", fmt.Errorf("query %q not found in schema", gqlName)
	}
	inputArg := queryDef.Arguments.ForName("input")
	if inputArg == nil {
		return "", fmt.Errorf("query %q has no 'input' argument", gqlName)
	}
	inputTypeName := inputArg.Type.NamedType
	// Fields whose paginationVars value is a map are passed as opaque object variables.
	opaqueFields := make(map[string]bool)
	for k, v := range paginationVars {
		if _, ok := v.(map[string]interface{}); ok {
			opaqueFields[k] = true
		}
	}
	nodes, err := buildInputTree(schema, inputTypeName, opaqueFields)
	if err != nil {
		return "", err
	}
	leaves := leafVars(nodes)
	varDecls := make([]string, 0, len(leaves))
	for _, leaf := range leaves {
		varDecls = append(varDecls, "$"+leaf.VarName+": "+leaf.TypeStr)
	}
	allDecls := strings.Join(varDecls, ", ")
	if extraDecls != "" {
		allDecls += ", " + extraDecls
	}
	constructor := buildConstructorStr(nodes)
	return fmt.Sprintf(
		"\nquery %s(%s) {\n\t%s(\n\t\tinput: %s\n\t) {\n\t\titems {\n\t\t\t%s\n\t\t}\n\t\tpageInfo {\n\t\t\tnext\n\t\t\ttotal\n\t\t}\n\t}\n}\n",
		gqlName, allDecls, gqlName, constructor, fragRef,
	), nil
}

func buildSimpleListStr(gqlName, fragRef string) string {
	return fmt.Sprintf("\nquery %s {\n\t%s {\n\t\titems {\n\t\t\t%s\n\t\t}\n\t}\n}\n", gqlName, gqlName, fragRef)
}

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
		sig = fmt.Sprintf("(ctx context.Context) (%s, error)", returnType)
		doc = fmt.Sprintf("// %s retrieves the %s.", op.Name, lcFirst(returnType))
		body = buildSingletonGetBody(op.Name, returnType, resultKey, endpoint, constName)

	case "list":
		sig = fmt.Sprintf("(ctx context.Context) ([]%s, error)", returnType)
		doc = fmt.Sprintf("// %s retrieves all %ss.", op.Name, lcFirst(returnType))
		if op.Pagination {
			body, err = buildListPaginatedBody(op.Name, returnType, resultKey, endpoint, constName, op.PaginationVars, rbacMap)
		} else {
			body = buildListSimpleBody(op.Name, returnType, resultKey, endpoint, constName)
		}

	default:
		err = fmt.Errorf("unsupported kind %q for method body", kind)
	}
	return
}

// buildMapLit emits a Go map[string]any{...} literal from a map, or "" when the map is empty.
func buildMapLit(m map[string]any) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%q: %s", k, formatGoLiteral(m[k])))
	}
	return "map[string]any{" + strings.Join(parts, ", ") + "}"
}

// mergeVarsExpr builds a Go expression that produces a vars map from base literal, optional
// extra var values, and optional rbacMap identifier.
func mergeVarsExpr(baseLit, extraVarLit, rbacMap string) string {
	args := []string{baseLit}
	if extraVarLit != "" {
		args = append(args, extraVarLit)
	}
	if rbacMap != "" {
		args = append(args, rbacMap)
	}
	if len(args) == 1 {
		return "vars := " + args[0]
	}
	return "vars := mergeVars(" + strings.Join(args, ", ") + ")"
}

func buildSingletonGetBody(methodName, returnType, resultKey, endpoint, constName string) string {
	tag := bt + `json:"` + resultKey + `"` + bt
	return fmt.Sprintf(
		"var result struct {\n\t\t%s %s %s\n\t}\n\tif err := c.transport.DoGraphQL(ctx, %q, %s, nil, &result); err != nil {\n\t\treturn %s{}, fmt.Errorf(\"%s: %%w\", err)\n\t}\n\treturn result.%s, nil",
		methodName, returnType, tag, endpoint, constName, returnType, methodName, methodName)
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
		"%s\n\tvar result struct {\n\t\t%s %s %s\n\t}\n\tif err := c.transport.DoGraphQL(ctx, %q, %s, vars, &result); err != nil {\n\t\treturn %s{}, fmt.Errorf(\"%s: %%w\", err)\n\t}\n\treturn result.%s, nil",
		varAssign, methodName, returnType, tag, endpoint, constName, returnType, methodName, methodName)
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
		"%s\n\tvar result struct {\n\t\t%s %s %s\n\t}\n\tif err := c.transport.DoGraphQL(ctx, %q, %s, vars, &result); err != nil {\n\t\treturn %s{}, fmt.Errorf(\"%s(%%s): %%w\", %s, err)\n\t}\n\treturn result.%s, nil",
		varLines, methodName, returnType, tag, endpoint, constName, returnType, methodName, idField, methodName)
}

func buildDeleteBody(methodName, endpoint, constName, idField string) string {
	return fmt.Sprintf(
		"vars := map[string]any{%q: %s}\n\tif err := c.transport.DoGraphQL(ctx, %q, %s, vars, nil); err != nil {\n\t\treturn fmt.Errorf(\"%s(%%s): %%w\", %s, err)\n\t}\n\treturn nil",
		idField, idField, endpoint, constName, methodName, idField)
}

func buildListPaginatedBody(methodName, returnType, resultKey, endpoint, constName string, paginationVars map[string]any, rbacMap string) (string, error) {
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
	varsStr := strings.Join(varEntries, "\n")
	paginationMapLit := fmt.Sprintf("map[string]any{\n%s\n\t}", varsStr)
	var varsExpr string
	if rbacMap != "" {
		varsExpr = "mergeVars(" + paginationMapLit + ", " + rbacMap + ")"
	} else {
		varsExpr = paginationMapLit
	}
	return fmt.Sprintf(
		"%s, err := client.ListAll[%s](ctx, c.transport, %q, %s, %s, %q)\n\tif err != nil {\n\t\treturn nil, fmt.Errorf(\"%s: %%w\", err)\n\t}\n\treturn %s, nil",
		localVar, returnType, endpoint, constName, varsExpr, resultKey, methodName, localVar), nil
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

func formatGoLiteral(v any) string {
	switch val := v.(type) {
	case float64:
		if val == float64(int64(val)) {
			return fmt.Sprintf("%d", int64(val))
		}
		return fmt.Sprintf("%g", val)
	case string:
		return fmt.Sprintf("%q", val)
	case bool:
		return fmt.Sprintf("%t", val)
	case map[string]interface{}:
		if len(val) == 0 {
			return "map[string]any{}"
		}
		return fmt.Sprintf("%v", val)
	default:
		return fmt.Sprintf("%v", val)
	}
}
