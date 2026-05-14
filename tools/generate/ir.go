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
	Body      string // pre-built function body; replaces Vars in the template
}

// BuildVar is one key-value entry in a buildXxxVariables return literal.
type BuildVar struct {
	Key      string // GQL variable name, e.g. "readResources"
	GoAccess string // Go field name on the input struct, e.g. "ReadResources"
	Optional bool   // if true, only include when non-zero
	IsPtr    bool   // if true, dereference with *input.X (only meaningful when Optional)
}

func buildIR(cfg Config, schema *ast.Schema, res ResourceConfig) (IRResource, error) {
	// Schema-name-keyed maps (the default; first NestedTypeConfig wins per schema name).
	nestedGoNames := make(map[string]string)
	nestedFieldRenames := make(map[string]map[string]string)
	nestedFieldLists := make(map[string][]string) // schemaName → allowed fields (nil = all)
	nestedDirectives := make(map[string]map[string]string)
	nestedNullableFields := make(map[string]map[string]bool)
	// Path-keyed maps for context-specific overrides (e.g. "computer.plan" → AlertComputerPlan).
	pathOverrides := make(map[string]NestedTypeConfig)

	for _, nt := range res.NestedTypes {
		if nt.Path != "" {
			pathOverrides[nt.Path] = nt
			continue
		}
		if _, exists := nestedGoNames[nt.SchemaName]; !exists {
			nestedGoNames[nt.SchemaName] = nt.GoName
		}
		if len(nt.FieldRenames) > 0 {
			nestedFieldRenames[nt.SchemaName] = nt.FieldRenames
		}
		if len(nt.Fields) > 0 {
			nestedFieldLists[nt.SchemaName] = nt.Fields
		}
		if len(nt.DirectiveFields) > 0 {
			nestedDirectives[nt.SchemaName] = nt.DirectiveFields
		}
		if len(nt.NullableFields) > 0 {
			m := make(map[string]bool)
			for _, f := range nt.NullableFields {
				m[f] = true
			}
			nestedNullableFields[nt.SchemaName] = m
		}
	}

	nullableResponseFields := make(map[string]bool)
	for _, f := range res.NullableResponseFields {
		nullableResponseFields[f] = true
	}

	fragConst := lcFirst(res.TypeName) + "Fields"

	fragment, err := buildFragment(schema, res, nestedFieldLists, nestedDirectives, pathOverrides)
	if err != nil {
		return IRResource{}, fmt.Errorf("fragment: %w", err)
	}

	mainType, nestedTypes, err := buildResponseTypes(schema, res, nestedGoNames, nestedFieldRenames, nestedFieldLists, nestedNullableFields, nullableResponseFields, pathOverrides, cfg.Scalars)
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

func buildFragment(schema *ast.Schema, res ResourceConfig, nestedFieldLists map[string][]string, nestedDirectives map[string]map[string]string, pathOverrides map[string]NestedTypeConfig) (string, error) {
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
			// Resolve sub-fields for this nested type: check path override first, then schema-name fallback.
			subFields := nestedFieldLists[base]
			subDirectives := nestedDirectives[base]
			if override, ok := pathOverrides[fieldName]; ok {
				if len(override.Fields) > 0 {
					subFields = override.Fields
				}
				if len(override.DirectiveFields) > 0 {
					subDirectives = override.DirectiveFields
				}
			}
			writeFragmentSubFields(schema, base, subFields, subDirectives, nestedFieldLists, nestedDirectives, pathOverrides, fieldName, 2, &b)
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

// writeFragmentSubFields recursively writes field selections for a schema type at the
// given indentation depth. Object sub-fields are expanded using nestedFieldLists.
// currentPath tracks the dot-path from the main type root, enabling path-based overrides.
func writeFragmentSubFields(schema *ast.Schema, typeName string, allowedFields []string, directives map[string]string, nestedFieldLists map[string][]string, nestedDirectives map[string]map[string]string, pathOverrides map[string]NestedTypeConfig, currentPath string, depth int, b *strings.Builder) {
	def := schema.Types[typeName]
	if def == nil {
		return
	}
	indent := strings.Repeat("\t", depth)

	var fieldNames []string
	if len(allowedFields) > 0 {
		fieldNames = allowedFields
	} else {
		for _, f := range def.Fields {
			fieldNames = append(fieldNames, f.Name)
		}
	}

	for _, fieldName := range fieldNames {
		f := def.Fields.ForName(fieldName)
		if f == nil {
			continue
		}
		base := baseTypeName(f.Type)
		fieldDef := schema.Types[base]
		directive := directives[fieldName]
		childPath := currentPath + "." + fieldName
		if fieldDef != nil && (fieldDef.Kind == ast.Object || fieldDef.Kind == ast.Interface) {
			if directive != "" {
				fmt.Fprintf(b, "%s%s %s {\n", indent, fieldName, directive)
			} else {
				fmt.Fprintf(b, "%s%s {\n", indent, fieldName)
			}
			subFields := nestedFieldLists[base]
			subDirectives := nestedDirectives[base]
			if override, ok := pathOverrides[childPath]; ok {
				if len(override.Fields) > 0 {
					subFields = override.Fields
				}
				if len(override.DirectiveFields) > 0 {
					subDirectives = override.DirectiveFields
				}
			}
			writeFragmentSubFields(schema, base, subFields, subDirectives, nestedFieldLists, nestedDirectives, pathOverrides, childPath, depth+1, b)
			fmt.Fprintf(b, "%s}\n", indent)
		} else {
			if directive != "" {
				fmt.Fprintf(b, "%s%s %s\n", indent, fieldName, directive)
			} else {
				fmt.Fprintf(b, "%s%s\n", indent, fieldName)
			}
		}
	}
}

func buildResponseTypes(schema *ast.Schema, res ResourceConfig, nestedGoNames map[string]string, nestedFieldRenames map[string]map[string]string, nestedFieldLists map[string][]string, nestedNullableFields map[string]map[string]bool, nullableResponseFields map[string]bool, pathOverrides map[string]NestedTypeConfig, scalars map[string]string) (IRStruct, []IRStruct, error) {
	schemaTypeName := res.SchemaTypeName()
	def := schema.Types[schemaTypeName]
	if def == nil {
		return IRStruct{}, nil, fmt.Errorf("type %q not found in schema", schemaTypeName)
	}

	seenNested := make(map[string]bool)
	seenNested[schemaTypeName] = true // prevent the main type from being generated as nested

	seenPaths := make(map[string]bool)

	// Seed the BFS queue with Object fields of the main type.
	// pathPrefix is the dot-path from the root used to look up path-overrides; it's
	// always carried forward even when there's no override.
	type queueItem struct {
		schemaName, goName string
		pathPrefix         string
		usingPathOverride  bool // true when this queue item was enqueued because of a path override
	}
	var queue []queueItem
	var mainFields []IRField

	for _, fieldName := range res.Fields {
		f := def.Fields.ForName(fieldName)
		if f == nil {
			return IRStruct{}, nil, fmt.Errorf("field %q not on type %s", fieldName, schemaTypeName)
		}
		base := baseTypeName(f.Type)
		// Check for path-based override first.
		var goType string
		if override, ok := pathOverrides[fieldName]; ok {
			goType = wrapTypeForPathOverride(f.Type, override.GoName)
		} else {
			goType = resolveGoType(f.Type, schema, scalars, nestedGoNames)
		}
		if nullableResponseFields[fieldName] {
			goType = ensurePointer(goType)
		}
		mainFields = append(mainFields, IRField{
			Name:    toPascalCase(fieldName),
			JSONTag: fieldName,
			Type:    goType,
		})

		fieldDef := schema.Types[base]
		if fieldDef != nil && (fieldDef.Kind == ast.Object || fieldDef.Kind == ast.Interface) {
			if override, ok := pathOverrides[fieldName]; ok {
				if !seenPaths[fieldName] {
					seenPaths[fieldName] = true
					queue = append(queue, queueItem{base, override.GoName, fieldName, true})
				}
			} else if !seenNested[base] {
				seenNested[base] = true
				goTypeName := base
				if o, ok := nestedGoNames[base]; ok {
					goTypeName = o
				}
				queue = append(queue, queueItem{base, goTypeName, fieldName, false})
			}
		}
	}

	// BFS: generate each nested struct and enqueue its own Object sub-fields.
	var nestedTypes []IRStruct
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		var fieldsList []string
		var renames map[string]string
		var nullable map[string]bool
		if item.usingPathOverride {
			if override, ok := pathOverrides[item.pathPrefix]; ok {
				fieldsList = override.Fields
				renames = override.FieldRenames
				if len(override.NullableFields) > 0 {
					nullable = make(map[string]bool)
					for _, nf := range override.NullableFields {
						nullable[nf] = true
					}
				}
			}
		} else {
			fieldsList = nestedFieldLists[item.schemaName]
			renames = nestedFieldRenames[item.schemaName]
			nullable = nestedNullableFields[item.schemaName]
		}
		ns, err := buildNestedStruct(schema, item.schemaName, item.goName, renames, fieldsList, nullable, scalars, nestedGoNames, pathOverrides, item.pathPrefix)
		if err != nil {
			return IRStruct{}, nil, err
		}
		nestedTypes = append(nestedTypes, ns)

		// Enqueue Object fields of this nested type (respecting its allowed field list).
		itemDef := schema.Types[item.schemaName]
		allowedSet := make(map[string]bool)
		for _, af := range fieldsList {
			allowedSet[af] = true
		}
		fieldOrder := fieldsList
		if len(fieldOrder) == 0 {
			for _, f := range itemDef.Fields {
				fieldOrder = append(fieldOrder, f.Name)
			}
		}
		for _, fName := range fieldOrder {
			subf := itemDef.Fields.ForName(fName)
			if subf == nil {
				continue
			}
			if len(allowedSet) > 0 && !allowedSet[subf.Name] {
				continue
			}
			base := baseTypeName(subf.Type)
			childDef := schema.Types[base]
			if childDef == nil || (childDef.Kind != ast.Object && childDef.Kind != ast.Interface) {
				continue
			}
			childPath := item.pathPrefix + "." + subf.Name
			if override, ok := pathOverrides[childPath]; ok {
				if !seenPaths[childPath] {
					seenPaths[childPath] = true
					queue = append(queue, queueItem{base, override.GoName, childPath, true})
				}
				continue
			}
			if seenNested[base] {
				continue
			}
			seenNested[base] = true
			goTypeName := base
			if override, ok := nestedGoNames[base]; ok {
				goTypeName = override
			}
			queue = append(queue, queueItem{base, goTypeName, childPath, false})
		}
	}

	mainStruct := IRStruct{
		Comment: fmt.Sprintf("// %s represents a Jamf Protect %s.", res.TypeName, lcFirst(res.TypeName)),
		Name:    res.TypeName,
		Fields:  mainFields,
	}

	// Generate any extra response types defined in config (e.g. minimal list-item types).
	// These use GoName as the dedup key since the SchemaName may already be the main type.
	seenExtraGoNames := make(map[string]bool)
	for _, ert := range res.ExtraResponseTypes {
		if seenExtraGoNames[ert.GoName] {
			continue
		}
		seenExtraGoNames[ert.GoName] = true
		ns, err := buildNestedStruct(schema, ert.SchemaName, ert.GoName, nil, ert.Fields, nil, scalars, nestedGoNames, pathOverrides, "")
		if err != nil {
			return IRStruct{}, nil, fmt.Errorf("extra response type %q: %w", ert.GoName, err)
		}
		nestedTypes = append(nestedTypes, ns)
	}

	return mainStruct, nestedTypes, nil
}

// ensurePointer wraps a Go type in a pointer, unless it already is one or is a slice.
// Slices become *[]T (pointer to slice).
func ensurePointer(goType string) string {
	if strings.HasPrefix(goType, "*") {
		return goType
	}
	return "*" + goType
}

// wrapTypeForPathOverride takes a schema field type and an override Go type name and produces
// the Go type expression preserving list/nullability wrapping from the schema field.
func wrapTypeForPathOverride(t *ast.Type, overrideGoName string) string {
	if t.Elem != nil {
		return "[]" + overrideGoName
	}
	if !t.NonNull {
		return "*" + overrideGoName
	}
	return overrideGoName
}

func buildNestedStruct(schema *ast.Schema, schemaTypeName, goTypeName string, fieldRenames map[string]string, allowedFields []string, nullableFields map[string]bool, scalars map[string]string, nestedOverrides map[string]string, pathOverrides map[string]NestedTypeConfig, parentPath string) (IRStruct, error) {
	def := schema.Types[schemaTypeName]
	if def == nil {
		return IRStruct{}, fmt.Errorf("type %q not found in schema", schemaTypeName)
	}
	allowed := make(map[string]bool, len(allowedFields))
	for _, f := range allowedFields {
		allowed[f] = true
	}
	// Iterate in allowedFields order when provided, otherwise schema order.
	var iterNames []string
	if len(allowedFields) > 0 {
		iterNames = allowedFields
	} else {
		for _, f := range def.Fields {
			iterNames = append(iterNames, f.Name)
		}
	}
	var fields []IRField
	for _, fName := range iterNames {
		f := def.Fields.ForName(fName)
		if f == nil {
			continue
		}
		goName := toPascalCase(f.Name)
		if renamed, ok := fieldRenames[f.Name]; ok {
			goName = renamed
		}
		var fGoType string
		childPath := ""
		if parentPath != "" {
			childPath = parentPath + "." + f.Name
		}
		if childPath != "" {
			if override, ok := pathOverrides[childPath]; ok {
				fGoType = wrapTypeForPathOverride(f.Type, override.GoName)
			}
		}
		if fGoType == "" {
			fGoType = resolveGoType(f.Type, schema, scalars, nestedOverrides)
		}
		if nullableFields[f.Name] {
			fGoType = ensurePointer(fGoType)
		}
		fields = append(fields, IRField{
			Name:    goName,
			JSONTag: f.Name,
			Type:    fGoType,
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
	seenNested := make(map[string]bool) // tracks nested InputObject types generated across all ops
	var inputTypes []IRStruct
	var buildVarsFuncs []IRBuildVarsFunc

	// Build a set of allowed input fields if the config specifies a subset.
	allowedInputFields := make(map[string]bool)
	for _, f := range res.InputFields {
		allowedInputFields[f] = true
	}

	// Build a set of nullable input fields that should use pointer types.
	nullableFields := make(map[string]bool)
	for _, f := range res.NullableInputFields {
		nullableFields[f] = true
	}

	// Build a set of optional input fields for conditional inclusion in buildVarsFunc.
	optionalFields := make(map[string]bool)
	for _, f := range res.OptionalInputFields {
		optionalFields[f] = true
	}

	for _, op := range res.Operations {
		if op.InputType == "" || seen[op.InputType] {
			continue
		}
		seen[op.InputType] = true
		seenNested[op.InputType] = true // exclude top-level from nested generation

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
			goType := resolveInputGoType(f.Type, schema, scalars)
			if nullableFields[f.Name] && !strings.HasPrefix(goType, "[]") && !strings.HasPrefix(goType, "*") {
				goType = "*" + goType
			}
			// Apply input type renames to the Go type (strip any list/pointer prefix to check the base name).
			goType = applyInputTypeRenames(goType, res.InputTypeRenames)
			fields = append(fields, IRField{
				Name: goName,
				Type: goType,
			})
			isOptional := optionalFields[f.Name]
			buildVars = append(buildVars, BuildVar{
				Key:      f.Name,
				GoAccess: goName,
				Optional: isOptional,
				IsPtr:    isOptional && strings.HasPrefix(goType, "*"),
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
			Body:      buildVarsFuncBody(buildVars),
		})

		// Recursively generate nested InputObject types (with json tags, in dependency order).
		nested, err := buildNestedInputTypes(schema, op.InputType, seenNested, scalars, res.InputTypeRenames)
		if err != nil {
			return nil, nil, fmt.Errorf("nested input types for %s: %w", op.InputType, err)
		}
		inputTypes = append(inputTypes, nested...)
	}
	return inputTypes, buildVarsFuncs, nil
}

// applyInputTypeRenames rewrites a Go type string (possibly "[]Foo" or "*Foo") by applying
// the inputTypeRenames map to the base type name.
func applyInputTypeRenames(goType string, renames map[string]string) string {
	if len(renames) == 0 {
		return goType
	}
	prefix := ""
	base := goType
	for _, p := range []string{"[]", "*"} {
		if strings.HasPrefix(base, p) {
			prefix += p
			base = base[len(p):]
		}
	}
	if renamed, ok := renames[base]; ok {
		return prefix + renamed
	}
	return goType
}

// buildNestedInputTypes recursively generates Go structs for nested InputObject types
// referenced by the fields of the given schema input type. The generated structs include
// json tags (required for direct serialisation into vars maps).
func buildNestedInputTypes(schema *ast.Schema, typeName string, seen map[string]bool, scalars map[string]string, renames map[string]string) ([]IRStruct, error) {
	def := schema.Types[typeName]
	if def == nil {
		return nil, fmt.Errorf("type %q not found in schema", typeName)
	}
	var result []IRStruct
	for _, f := range def.Fields {
		base := baseTypeName(f.Type)
		childDef := schema.Types[base]
		if childDef == nil || childDef.Kind != ast.InputObject {
			continue
		}
		if seen[base] {
			continue
		}
		seen[base] = true

		// Recurse to get dependencies first.
		nested, err := buildNestedInputTypes(schema, base, seen, scalars, renames)
		if err != nil {
			return nil, err
		}
		result = append(result, nested...)

		goTypeName := toPascalCase(base)
		if renamed, ok := renames[base]; ok {
			goTypeName = renamed
		}

		var fields []IRField
		for _, nf := range childDef.Fields {
			nfGoType := resolveInputGoType(nf.Type, schema, scalars)
			nfGoType = applyInputTypeRenames(nfGoType, renames)
			fields = append(fields, IRField{
				Name:    toPascalCase(nf.Name),
				JSONTag: nf.Name,
				Type:    nfGoType,
			})
		}
		result = append(result, IRStruct{
			Comment: fmt.Sprintf("// %s is a nested input type.", goTypeName),
			Name:    goTypeName,
			Fields:  fields,
			IsInput: true,
		})
	}
	return result, nil
}

// buildVarsFuncBody produces the Go body of a buildXxxVariables function. Required vars go into
// the map literal unconditionally; optional vars are guarded by nil/zero-value checks.
func buildVarsFuncBody(vars []BuildVar) string {
	var required, optional []BuildVar
	for _, v := range vars {
		if v.Optional {
			optional = append(optional, v)
		} else {
			required = append(required, v)
		}
	}

	var b strings.Builder
	if len(optional) == 0 {
		b.WriteString("\treturn map[string]any{\n")
		for _, v := range required {
			fmt.Fprintf(&b, "\t\t%q: input.%s,\n", v.Key, v.GoAccess)
		}
		b.WriteString("\t}\n")
		return b.String()
	}

	b.WriteString("\tvars := map[string]any{\n")
	for _, v := range required {
		fmt.Fprintf(&b, "\t\t%q: input.%s,\n", v.Key, v.GoAccess)
	}
	b.WriteString("\t}\n")
	for _, v := range optional {
		if v.IsPtr {
			fmt.Fprintf(&b, "\tif input.%s != nil {\n\t\tvars[%q] = *input.%s\n\t}\n", v.GoAccess, v.Key, v.GoAccess)
		} else {
			fmt.Fprintf(&b, "\tif input.%s != \"\" {\n\t\tvars[%q] = input.%s\n\t}\n", v.GoAccess, v.Key, v.GoAccess)
		}
	}
	b.WriteString("\treturn vars\n")
	return b.String()
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

	isMutation := kind == "create" || kind == "update" || kind == "delete" ||
		kind == "mutation_list" || kind == "singleton_update" || kind == "update_inline"
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
	// Per-op extra var values override / extend resource-level extra var values.
	combinedExtraVars := make(map[string]any)
	for k, v := range res.ExtraVarValues {
		combinedExtraVars[k] = v
	}
	for k, v := range op.ExtraVarValues {
		combinedExtraVars[k] = v
	}
	sig, doc, body, err := buildMethodParts(op, kind, endpoint, returnType, returnNullable, resultKey, constName, idField, res.RBACMap, combinedExtraVars)
	if err != nil {
		return IROperation{}, err
	}

	// Delete ops, list ops with inline item fields, ops with inline fields, and ops with noFragment
	// don't use the fragment — omit fragConst so AppSync doesn't reject the unused fragment definition.
	opFragConst := fragConst
	if kind == "delete" || (kind == "list" && len(op.ListItemFields) > 0) || len(op.InlineFields) > 0 || op.NoFragment {
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
		varDecls := ""
		if extraDecls != "" {
			varDecls = "(" + extraDecls + ")"
		}
		// Wrap nested-result paths around the bodySelection.
		body := wrapResultPath(op.ResultPath, gqlName, bodySelection)
		// If ResultPath wasn't given, default to single-level wrap with fieldRef.
		if op.ResultPath == "" {
			body = fmt.Sprintf("%s {\n\t\t%s\n\t}", fieldRef, bodySelection)
		}
		return fmt.Sprintf("\nquery %s%s {\n\t%s\n}\n", gqlName, varDecls, body), nil

	case "list":
		if op.Pagination {
			return buildPaginatedListStr(schema, gqlName, fragRef, op.PaginationVars, extraDecls, op.ListItemFields)
		}
		return buildSimpleListStr(gqlName, fragRef), nil

	case "list_simple":
		// Top-level list returning [T] directly (no items/pageInfo wrapper, no pagination).
		// e.g. listInsights returns [Insight] directly.
		return fmt.Sprintf("\nquery %s {\n\t%s {\n\t\t%s\n\t}\n}\n", gqlName, gqlName, bodySelection), nil

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
		return buildMutationListStr(schema, op.InputType, gqlName, bodySelection, opInputFields, extraDecls)

	case "singleton_update":
		// Mutation taking primitive args, wrapped in input: {field: $field}.
		if len(op.InlineArgs) == 0 {
			return "", fmt.Errorf("singleton_update op %q requires inlineArgs", op.Name)
		}
		return buildInlineArgsMutationStr(op, gqlName, bodySelection, false, extraDecls, idField)

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
// The innermost level wraps bodySelection. If path is empty, returns body wrapping with gqlName.
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

// buildMutationListStr builds a mutation that returns {items: [T]}.
func buildMutationListStr(schema *ast.Schema, inputTypeName, gqlName, bodySelection string, allowedFields []string, extraDecls string) (string, error) {
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
	return fmt.Sprintf("\nmutation %s(%s) {\n\t%s(input: %s) {\n\t\titems {\n\t\t\t%s\n\t\t}\n\t}\n}\n", gqlName, vars, gqlName, input, bodySelection), nil
}

// buildInlineArgsMutationStr builds a mutation from primitive inline args.
// If wrapInItems is true, wraps the response in {items: [T]}.
func buildInlineArgsMutationStr(op OperationConfig, gqlName, bodySelection string, wrapInItems bool, extraDecls, idField string) (string, error) {
	var varDecls []string
	var idArgPart string
	var inputParts []string
	for _, a := range op.InlineArgs {
		varDecls = append(varDecls, "$"+a.GQLVar+": "+a.GQLType)
		if a.IsID {
			idArgPart = a.GQLVar + ": $" + a.GQLVar
		} else {
			inputParts = append(inputParts, a.GQLVar+": $"+a.GQLVar)
		}
	}
	vars := strings.Join(varDecls, ", ")
	if extraDecls != "" {
		vars += ", " + extraDecls
	}
	var argPart string
	if idArgPart != "" {
		if len(inputParts) > 0 {
			argPart = idArgPart + ", input: {" + strings.Join(inputParts, ", ") + "}"
		} else {
			argPart = idArgPart
		}
	} else {
		argPart = "input: {" + strings.Join(inputParts, ", ") + "}"
	}
	if wrapInItems {
		return fmt.Sprintf("\nmutation %s(%s) {\n\t%s(%s) {\n\t\titems {\n\t\t\t%s\n\t\t}\n\t}\n}\n", gqlName, vars, gqlName, argPart, bodySelection), nil
	}
	return fmt.Sprintf("\nmutation %s(%s) {\n\t%s(%s) {\n\t\t%s\n\t}\n}\n", gqlName, vars, gqlName, argPart, bodySelection), nil
}

// buildDatePaginatedStr builds the query for a date-range paginated op.
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

func buildPaginatedListStr(schema *ast.Schema, gqlName, fragRef string, paginationVars map[string]any, extraDecls string, listItemFields []string) (string, error) {
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
	itemsContent := fragRef
	if len(listItemFields) > 0 {
		itemsContent = strings.Join(listItemFields, "\n\t\t\t")
	}
	return fmt.Sprintf(
		"\nquery %s(%s) {\n\t%s(\n\t\tinput: %s\n\t) {\n\t\titems {\n\t\t\t%s\n\t\t}\n\t\tpageInfo {\n\t\t\tnext\n\t\t\ttotal\n\t\t}\n\t}\n}\n",
		gqlName, allDecls, gqlName, constructor, itemsContent,
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
		body = buildSingletonGetBody(op.Name, returnType, resultKey, endpoint, constName, op.ResultPath, op.ResultPathTypes, extraVarValues, rbacMap)

	case "list":
		sig = fmt.Sprintf("(ctx context.Context) ([]%s, error)", returnType)
		doc = fmt.Sprintf("// %s retrieves all %ss.", op.Name, lcFirst(returnType))
		if op.Pagination {
			body, err = buildListPaginatedBody(op.Name, returnType, resultKey, endpoint, constName, op.PaginationVars, rbacMap)
		} else {
			body = buildListSimpleBody(op.Name, returnType, resultKey, endpoint, constName)
		}

	case "list_simple":
		sig = fmt.Sprintf("(ctx context.Context) ([]%s, error)", returnType)
		doc = fmt.Sprintf("// %s retrieves all %ss.", op.Name, lcFirst(returnType))
		body = buildListSimpleTopLevelBody(op.Name, returnType, resultKey, endpoint, constName)

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
		sigStr, _ := inlineArgsSignature(op.InlineArgs)
		sig = fmt.Sprintf("(ctx context.Context%s) (%s, error)", sigStr, returnType)
		doc = fmt.Sprintf("// %s updates the %s.", op.Name, lcFirst(returnType))
		body = buildSingletonUpdateBody(op, returnType, resultKey, endpoint, constName, rbacMap, extraVarValues)

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

// inlineArgsSignature builds the Go signature args portion for inline args (e.g. ", configFreeze bool").
func inlineArgsSignature(args []InlineArg) (string, []string) {
	var parts []string
	var names []string
	for _, a := range args {
		parts = append(parts, ", "+a.Name+" "+a.GoType)
		names = append(names, a.Name)
	}
	return strings.Join(parts, ""), names
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

func buildSingletonGetBody(methodName, returnType, resultKey, endpoint, constName, resultPath string, resultPathTypes []string, extraVarValues map[string]any, rbacMap string) string {
	// Build vars expression. For singleton_get with extraVars/rbacMap, vars are needed.
	varsArg := "nil"
	varAssignPrefix := ""
	if len(extraVarValues) > 0 || rbacMap != "" {
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

	if resultPath == "" {
		tag := bt + `json:"` + resultKey + `"` + bt
		return fmt.Sprintf(
			"%svar result struct {\n\t\t%s %s %s\n\t}\n\tif err := c.transport.DoGraphQL(ctx, %q, %s, %s, &result); err != nil {\n\t\treturn %s{}, fmt.Errorf(\"%s: %%w\", err)\n\t}\n\treturn result.%s, nil",
			varAssignPrefix, methodName, returnType, tag, endpoint, constName, varsArg, returnType, methodName, methodName)
	}

	// Nested-result extraction: result.Level1.Level2.<value>
	parts := strings.Split(resultPath, ".")
	// Build nested struct + accessor path.
	// Outer struct's field is parts[0]; type wraps inner struct; final type is returnType.
	var b strings.Builder
	b.WriteString(varAssignPrefix)
	b.WriteString("var result struct {\n")
	// Build nested: each level a struct field with json tag.
	indent := "\t\t"
	closers := []string{}
	for i, part := range parts {
		fieldGoName := toPascalCase(part)
		if i == len(parts)-1 {
			fmt.Fprintf(&b, "%s%s %s %sjson:\"%s\"%s\n", indent, fieldGoName, returnType, bt, part, bt)
		} else {
			// Allow optional intermediate type override; default is anonymous struct.
			fmt.Fprintf(&b, "%s%s struct {\n", indent, fieldGoName)
			closers = append(closers, indent+"} "+bt+"json:\""+part+"\""+bt)
			indent += "\t"
		}
	}
	for i := len(closers) - 1; i >= 0; i-- {
		b.WriteString(closers[i] + "\n")
	}
	b.WriteString("\t}\n")
	fmt.Fprintf(&b, "\tif err := c.transport.DoGraphQL(ctx, %q, %s, %s, &result); err != nil {\n\t\treturn %s{}, fmt.Errorf(\"%s: %%w\", err)\n\t}\n", endpoint, constName, varsArg, returnType, methodName)
	// Build accessor: result.Part1.Part2...
	accessor := "result"
	for _, part := range parts {
		accessor += "." + toPascalCase(part)
	}
	fmt.Fprintf(&b, "\treturn %s, nil", accessor)
	return b.String()
}

func buildListSimpleTopLevelBody(methodName, returnType, resultKey, endpoint, constName string) string {
	// For queries like `listInsights: [Insight]` returning [T] directly (not wrapped in items).
	tag := bt + `json:"` + resultKey + `"` + bt
	return fmt.Sprintf(
		"var result struct {\n\t\t%s []%s %s\n\t}\n\tif err := c.transport.DoGraphQL(ctx, %q, %s, nil, &result); err != nil {\n\t\treturn nil, fmt.Errorf(\"%s: %%w\", err)\n\t}\n\treturn result.%s, nil",
		toPascalCase(resultKey), returnType, tag, endpoint, constName, methodName, toPascalCase(resultKey))
}

func buildMutationListBody(op OperationConfig, returnType, resultKey, endpoint, constName, rbacMap string, extraVarValues map[string]any) string {
	outerTag := bt + `json:"` + resultKey + `"` + bt
	innerTag := bt + `json:"items"` + bt

	var varAssign string
	if len(op.InlineArgs) > 0 {
		// Build vars from inline args.
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

	return fmt.Sprintf(
		"%s\n\tvar result struct {\n\t\t%s struct {\n\t\t\tItems []%s %s\n\t\t} %s\n\t}\n\tif err := c.transport.DoGraphQL(ctx, %q, %s, vars, &result); err != nil {\n\t\treturn nil, fmt.Errorf(\"%s: %%w\", err)\n\t}\n\treturn result.%s.Items, nil",
		varAssign, toPascalCase(resultKey), returnType, innerTag, outerTag, endpoint, constName, op.Name, toPascalCase(resultKey))
}

func buildSingletonUpdateBody(op OperationConfig, returnType, resultKey, endpoint, constName, rbacMap string, extraVarValues map[string]any) string {
	tag := bt + `json:"` + resultKey + `"` + bt
	var parts []string
	for _, a := range op.InlineArgs {
		parts = append(parts, fmt.Sprintf("%q: %s", a.GQLVar, a.Name))
	}
	baseLit := "map[string]any{" + strings.Join(parts, ", ") + "}"
	varAssign := mergeVarsExpr(baseLit, buildMapLit(extraVarValues), rbacMap)
	return fmt.Sprintf(
		"%s\n\tvar result struct {\n\t\t%s %s %s\n\t}\n\tif err := c.transport.DoGraphQL(ctx, %q, %s, vars, &result); err != nil {\n\t\treturn %s{}, fmt.Errorf(\"%s: %%w\", err)\n\t}\n\treturn result.%s, nil",
		varAssign, toPascalCase(resultKey), returnType, tag, endpoint, constName, returnType, op.Name, toPascalCase(resultKey))
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
		"%s\n\tvar result struct {\n\t\t%s %s %s\n\t}\n\tif err := c.transport.DoGraphQL(ctx, %q, %s, vars, &result); err != nil {\n\t\treturn %s{}, fmt.Errorf(\"%s(%%s): %%w\", %s, err)\n\t}\n\treturn result.%s, nil",
		varAssign, toPascalCase(resultKey), returnType, tag, endpoint, constName, returnType, op.Name, idArg, toPascalCase(resultKey))
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
