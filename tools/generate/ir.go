// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"maps"
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
	TypedEnums     []IRTypedEnum
	NeedClient     bool   // true when any operation uses client.ListAll
	ExtraTopLevel  string // raw Go code emitted after main type, before client methods
	NoMainFragment bool   // true when no operation references the main type's fragment (suppresses the unused fragment const)
}

// IRTypedEnum is a typed string alias with named constants.
type IRTypedEnum struct {
	GoName    string
	Doc       string
	Constants []IRTypedEnumConst
}

// IRTypedEnumConst is one named constant of a typed enum.
type IRTypedEnumConst struct {
	Name  string
	Value string
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
	Key          string // GQL variable name, e.g. "readResources"
	GoAccess     string // Go field name on the input struct, e.g. "ReadResources"
	Optional     bool   // if true, only include when non-zero
	IsPtr        bool   // if true, dereference with *input.X (only meaningful when Optional)
	IsSlice      bool   // if true, use != nil check instead of != "" (only meaningful when Optional)
	ExplicitNull bool   // if true, emit tri-state: FooNull sentinel → nil, Foo != nil → set, else → omit
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

	ops, err := buildOperations(schema, res, fragConst, cfg.Scalars, nestedFieldLists, nestedDirectives, pathOverrides)
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
	noMainFragment := true
	for _, op := range ops {
		if op.FragConst != "" {
			noMainFragment = false
			break
		}
	}

	var typedEnums []IRTypedEnum
	for _, te := range res.TypedEnums {
		doc := te.Doc
		if doc == "" {
			doc = fmt.Sprintf("// %s identifies a %s value.", te.GoName, te.GoName)
		}
		var consts []IRTypedEnumConst
		// Sort by Go const name for stable output.
		var keys []string
		for k := range te.Constants {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, schemaVal := range keys {
			consts = append(consts, IRTypedEnumConst{Name: te.Constants[schemaVal], Value: schemaVal})
		}
		typedEnums = append(typedEnums, IRTypedEnum{GoName: te.GoName, Doc: doc, Constants: consts})
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
		TypedEnums:     typedEnums,
		NeedClient:     needClient,
		ExtraTopLevel:  res.ExtraTopLevel,
		NoMainFragment: noMainFragment,
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

		// Interface and union fields with explicit union config emit inline fragments.
		if fieldDef != nil && (fieldDef.Kind == ast.Interface || fieldDef.Kind == ast.Union) {
			if uf, ok := res.UnionFields[fieldName]; ok {
				b.WriteString("\t" + fieldName + " {\n")
				for _, cf := range uf.Common {
					b.WriteString("\t\t" + cf + "\n")
				}
				for _, typeName := range sortedStringKeys(uf.Variants) {
					b.WriteString("\t\t... on " + typeName + " {\n")
					writeFragmentSubFields(schema, typeName, uf.Variants[typeName], nil, nestedFieldLists, nestedDirectives, pathOverrides, fieldName, 3, &b, res.UnionFields)
					b.WriteString("\t\t}\n")
				}
				b.WriteString("\t}\n")
				continue
			}
		}

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
			writeFragmentSubFields(schema, base, subFields, subDirectives, nestedFieldLists, nestedDirectives, pathOverrides, fieldName, 2, &b, res.UnionFields)
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
// Union/interface fields with a matching entry in unionFields emit inline fragments.
// currentPath tracks the dot-path from the main type root, enabling path-based overrides.
func writeFragmentSubFields(schema *ast.Schema, typeName string, allowedFields []string, directives map[string]string, nestedFieldLists map[string][]string, nestedDirectives map[string]map[string]string, pathOverrides map[string]NestedTypeConfig, currentPath string, depth int, b *strings.Builder, unionFields map[string]UnionFieldConfig) {
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

		// Interface and union fields with union config emit inline fragments.
		if fieldDef != nil && (fieldDef.Kind == ast.Interface || fieldDef.Kind == ast.Union) {
			if uf, ok := unionFields[fieldName]; ok {
				fmt.Fprintf(b, "%s%s {\n", indent, fieldName)
				for _, cf := range uf.Common {
					fmt.Fprintf(b, "%s\t%s\n", indent, cf)
				}
				for _, variantName := range sortedStringKeys(uf.Variants) {
					fmt.Fprintf(b, "%s\t... on %s {\n", indent, variantName)
					writeFragmentSubFields(schema, variantName, uf.Variants[variantName], nil, nestedFieldLists, nestedDirectives, pathOverrides, childPath, depth+2, b, unionFields)
					fmt.Fprintf(b, "%s\t}\n", indent)
				}
				fmt.Fprintf(b, "%s}\n", indent)
				continue
			}
		}

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
			writeFragmentSubFields(schema, base, subFields, subDirectives, nestedFieldLists, nestedDirectives, pathOverrides, childPath, depth+1, b, unionFields)
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
	var nestedTypes []IRStruct

	for _, fieldName := range res.Fields {
		f := def.Fields.ForName(fieldName)
		if f == nil {
			return IRStruct{}, nil, fmt.Errorf("field %q not on type %s", fieldName, schemaTypeName)
		}
		base := baseTypeName(f.Type)
		fieldDef := schema.Types[base]

		// Interface and union fields with explicit union config build a merged flat struct.
		if fieldDef != nil && (fieldDef.Kind == ast.Interface || fieldDef.Kind == ast.Union) {
			if uf, ok := res.UnionFields[fieldName]; ok {
				var unionGoType string
				if f.Type.Elem != nil {
					unionGoType = "[]" + uf.GoStruct
				} else {
					unionGoType = uf.GoStruct
				}
				if nullableResponseFields[fieldName] {
					unionGoType = ensurePointer(unionGoType)
				}
				mainFields = append(mainFields, IRField{
					Name:    toPascalCase(fieldName),
					JSONTag: fieldName,
					Type:    unionGoType,
				})
				if !seenNested[base] {
					seenNested[base] = true
					mergedStruct, subObjectBases, mergeErr := buildUnionMergedStruct(schema, fieldDef, uf, scalars, nestedGoNames)
					if mergeErr != nil {
						return IRStruct{}, nil, fmt.Errorf("union field %q: %w", fieldName, mergeErr)
					}
					nestedTypes = append(nestedTypes, mergedStruct)
					for _, subBase := range subObjectBases {
						if seenNested[subBase] {
							continue
						}
						seenNested[subBase] = true
						subGoName := subBase
						if o, ok := nestedGoNames[subBase]; ok {
							subGoName = o
						}
						queue = append(queue, queueItem{subBase, subGoName, fieldName + "." + subBase, false})
					}
				}
				continue
			}
		}

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

	seenGoNames := make(map[string]bool)

	// BFS: generate each nested struct and enqueue its own Object sub-fields.
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		// Skip duplicate generation when multiple schema types share a Go name.
		if seenGoNames[item.goName] {
			continue
		}
		seenGoNames[item.goName] = true

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
			// Union fields with a union config generate a merged flat struct in-place.
			if childDef != nil && childDef.Kind == ast.Union {
				if uf, ok := res.UnionFields[fName]; ok && !seenNested[base] {
					seenNested[base] = true
					mergedStruct, subObjectBases, mergeErr := buildUnionMergedStruct(schema, childDef, uf, scalars, nestedGoNames)
					if mergeErr != nil {
						return IRStruct{}, nil, fmt.Errorf("union field %q in %s: %w", fName, item.schemaName, mergeErr)
					}
					nestedTypes = append(nestedTypes, mergedStruct)
					for _, subBase := range subObjectBases {
						if !seenNested[subBase] {
							seenNested[subBase] = true
							subGoName := subBase
							if o, ok := nestedGoNames[subBase]; ok {
								subGoName = o
							}
							queue = append(queue, queueItem{subBase, subGoName, item.pathPrefix + "." + subBase, false})
						}
					}
				}
				continue
			}
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

	// Build a set of explicit-null input fields (three-state: null / omit / set).
	explicitNullFields := make(map[string]bool)
	for _, f := range res.ExplicitNullInputFields {
		explicitNullFields[f] = true
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

			// Knob D: mapInputFields overrides the Go type and skips nested recursion.
			var goType string
			if overrideType, ok := res.MapInputFields[f.Name]; ok {
				goType = overrideType
				base := baseTypeName(f.Type)
				if childDef := schema.Types[base]; childDef != nil && childDef.Kind == ast.InputObject {
					seenNested[base] = true
				}
			} else {
				goType = resolveInputGoType(f.Type, schema, scalars)
				if nullableFields[f.Name] && !strings.HasPrefix(goType, "[]") && !strings.HasPrefix(goType, "*") {
					goType = "*" + goType
				}
				goType = applyInputTypeRenames(goType, res.InputTypeRenames)
			}

			// Knob A: explicitNullInputFields emits a value field + a FooNull bool sentinel.
			if explicitNullFields[f.Name] {
				fields = append(fields, IRField{Name: goName, Type: goType})
				fields = append(fields, IRField{Name: goName + "Null", Type: "bool"})
				buildVars = append(buildVars, BuildVar{
					Key:          f.Name,
					GoAccess:     goName,
					Optional:     true,
					IsPtr:        true,
					ExplicitNull: true,
				})
			} else {
				fields = append(fields, IRField{Name: goName, Type: goType})
				isOptional := optionalFields[f.Name]
				buildVars = append(buildVars, BuildVar{
					Key:      f.Name,
					GoAccess: goName,
					Optional: isOptional,
					IsPtr:    isOptional && strings.HasPrefix(goType, "*"),
					IsSlice:  isOptional && strings.HasPrefix(goType, "[]"),
				})
			}
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
		nested, err := buildNestedInputTypes(schema, op.InputType, seenNested, scalars, res.InputTypeRenames, res.NullableNestedInputFields, res.InputFieldGoRenames)
		if err != nil {
			return nil, nil, fmt.Errorf("nested input types for %s: %w", op.InputType, err)
		}
		inputTypes = append(inputTypes, nested...)
	}

	// groupInputAs: generate a plain Go struct from inlineArgs (no json tags, no buildVarsFunc).
	seenGroupInputs := make(map[string]bool)
	for _, op := range res.Operations {
		if op.GroupInputAs == "" || seenGroupInputs[op.GroupInputAs] {
			continue
		}
		seenGroupInputs[op.GroupInputAs] = true
		var fields []IRField
		for _, a := range op.InlineArgs {
			fields = append(fields, IRField{
				Name: toPascalCase(a.Name),
				Type: a.GoType,
			})
		}
		baseName := strings.TrimSuffix(op.GroupInputAs, "Input")
		inputTypes = append(inputTypes, IRStruct{
			Comment: fmt.Sprintf("// %s is the input for %s operations.", op.GroupInputAs, lcFirst(baseName)),
			Name:    op.GroupInputAs,
			Fields:  fields,
			IsInput: true,
		})
	}

	// multi_wrapped_update: generate composite input struct + component nested types.
	for _, op := range res.Operations {
		if op.Kind != "multi_wrapped_update" || len(op.MultiWrappedInputs) == 0 {
			continue
		}
		mwTypes, err := buildMultiWrappedInputTypes(schema, op, res, seenNested, scalars)
		if err != nil {
			return nil, nil, fmt.Errorf("multi_wrapped_update input types for %s: %w", op.Name, err)
		}
		inputTypes = append(inputTypes, mwTypes...)
	}

	return inputTypes, buildVarsFuncs, nil
}

// applyInputTypeRenames rewrites a Go type string (possibly "[]Foo" or "*Foo") by applying
// the inputTypeRenames map to the base type name.
func applyInputTypeRenames(goType string, renames map[string]string) string {
	if len(renames) == 0 {
		return goType
	}
	var prefix strings.Builder
	base := goType
	for _, p := range []string{"[]", "*"} {
		if strings.HasPrefix(base, p) {
			prefix.WriteString(p)
			base = base[len(p):]
		}
	}
	if renamed, ok := renames[base]; ok {
		return prefix.String() + renamed
	}
	return goType
}

// buildNestedInputTypes recursively generates Go structs for nested InputObject types
// referenced by the fields of the given schema input type. The generated structs include
// json tags (required for direct serialisation into vars maps).
// nullableNestedFields maps schema type name → field names that should use *T + omitempty json tag.
// inputFieldGoRenames maps schema type name → (schema field name → Go field name override).
func buildNestedInputTypes(schema *ast.Schema, typeName string, seen map[string]bool, scalars map[string]string, renames map[string]string, nullableNestedFields map[string][]string, inputFieldGoRenames map[string]map[string]string) ([]IRStruct, error) {
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
		nested, err := buildNestedInputTypes(schema, base, seen, scalars, renames, nullableNestedFields, inputFieldGoRenames)
		if err != nil {
			return nil, err
		}
		result = append(result, nested...)

		goTypeName := toPascalCase(base)
		if renamed, ok := renames[base]; ok {
			goTypeName = renamed
		}

		nullableSet := make(map[string]bool)
		for _, fn := range nullableNestedFields[base] {
			nullableSet[fn] = true
		}

		// Knob B: per-field Go name overrides for this schema type.
		fieldGoRenames := inputFieldGoRenames[base]

		var fields []IRField
		for _, nf := range childDef.Fields {
			nfGoType := resolveInputGoType(nf.Type, schema, scalars)
			nfGoType = applyInputTypeRenames(nfGoType, renames)
			jsonTag := nf.Name
			if nullableSet[nf.Name] && !strings.HasPrefix(nfGoType, "[]") && !strings.HasPrefix(nfGoType, "*") {
				nfGoType = "*" + nfGoType
				jsonTag += ",omitempty"
			}
			goFieldName := toPascalCase(nf.Name)
			if override, ok := fieldGoRenames[nf.Name]; ok {
				goFieldName = override
			}
			fields = append(fields, IRField{
				Name:    goFieldName,
				JSONTag: jsonTag,
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
		if v.ExplicitNull {
			// Tri-state: NullSentinel → pass nil, ptr non-nil → pass value, else → omit.
			fmt.Fprintf(&b, "\tif input.%sNull {\n\t\tvars[%q] = nil\n\t} else if input.%s != nil {\n\t\tvars[%q] = *input.%s\n\t}\n",
				v.GoAccess, v.Key, v.GoAccess, v.Key, v.GoAccess)
		} else if v.IsPtr {
			fmt.Fprintf(&b, "\tif input.%s != nil {\n\t\tvars[%q] = *input.%s\n\t}\n", v.GoAccess, v.Key, v.GoAccess)
		} else if v.IsSlice {
			fmt.Fprintf(&b, "\tif input.%s != nil {\n\t\tvars[%q] = input.%s\n\t}\n", v.GoAccess, v.Key, v.GoAccess)
		} else {
			fmt.Fprintf(&b, "\tif input.%s != \"\" {\n\t\tvars[%q] = input.%s\n\t}\n", v.GoAccess, v.Key, v.GoAccess)
		}
	}
	b.WriteString("\treturn vars\n")
	return b.String()
}

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

// buildMutationListStr builds a mutation that returns {items: [T]} (or custom-path equivalent).
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
// E.g. resultPath="updateOrganizationRetention.retention", gqlName="updateOrganizationRetention" → "retention".
func resultPathSuffix(resultPath, gqlName string) string {
	prefix := gqlName + "."
	if strings.HasPrefix(resultPath, prefix) {
		return resultPath[len(prefix):]
	}
	return ""
}

// wrapBodyInMutationSuffix wraps bodySelection in nested blocks for the given dot-path suffix.
// The wrapping starts at tab depth 2 (inside "mutation { gqlName { ... } }").
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

// inputTreeNode is an ordered tree node for building nested GQL input literals from InputPath.
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
// schema InputObject type (e.g. $s3: OrganizationS3ForwardInput!), all passed as input: {s3: $s3, ...}.
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

// buildMultiWrappedUpdateBody builds the method body for a multi_wrapped_update operation.
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
// component input types (with json tags) + the composite input struct (no json tags).
func buildMultiWrappedInputTypes(schema *ast.Schema, op OperationConfig, res ResourceConfig, seen map[string]bool, scalars map[string]string) ([]IRStruct, error) {
	var result []IRStruct
	for _, mw := range op.MultiWrappedInputs {
		schemaTypeName := strings.TrimSuffix(mw.SchemaType, "!")
		if seen[schemaTypeName] {
			continue
		}
		seen[schemaTypeName] = true

		def := schema.Types[schemaTypeName]
		if def == nil {
			return nil, fmt.Errorf("input type %q not found in schema", schemaTypeName)
		}

		// Generate nested types (dependencies) first.
		nested, err := buildNestedInputTypes(schema, schemaTypeName, seen, scalars, res.InputTypeRenames, res.NullableNestedInputFields, res.InputFieldGoRenames)
		if err != nil {
			return nil, err
		}
		result = append(result, nested...)

		// Generate the component type itself.
		goTypeName := toPascalCase(schemaTypeName)
		if renamed, ok := res.InputTypeRenames[schemaTypeName]; ok {
			goTypeName = renamed
		}
		nullableSet := make(map[string]bool)
		for _, fn := range res.NullableNestedInputFields[schemaTypeName] {
			nullableSet[fn] = true
		}
		var fields []IRField
		for _, f := range def.Fields {
			fGoType := resolveInputGoType(f.Type, schema, scalars)
			fGoType = applyInputTypeRenames(fGoType, res.InputTypeRenames)
			jsonTag := f.Name
			if nullableSet[f.Name] && !strings.HasPrefix(fGoType, "[]") && !strings.HasPrefix(fGoType, "*") {
				fGoType = "*" + fGoType
				jsonTag += ",omitempty"
			}
			fields = append(fields, IRField{
				Name:    toPascalCase(f.Name),
				JSONTag: jsonTag,
				Type:    fGoType,
			})
		}
		result = append(result, IRStruct{
			Comment: fmt.Sprintf("// %s is a nested input type.", goTypeName),
			Name:    goTypeName,
			Fields:  fields,
			IsInput: true,
		})
	}

	// Composite input struct: no json tags (Go-only struct, not directly serialized).
	goCompositeType := op.InputTypeGoName
	var compositeFields []IRField
	for _, mw := range op.MultiWrappedInputs {
		compositeFields = append(compositeFields, IRField{
			Name: mw.GoField,
			Type: mw.GoInputType,
		})
	}
	baseName := strings.TrimSuffix(goCompositeType, "Input")
	result = append(result, IRStruct{
		Comment: fmt.Sprintf("// %s is the input for %s operations.", goCompositeType, lcFirst(baseName)),
		Name:    goCompositeType,
		Fields:  compositeFields,
		IsInput: true,
	})

	return result, nil
}

// buildInlineArgsMutationStr builds a mutation from primitive inline args.
// If wrapInItems is true, wraps the response in {<wrapField>: [T]} where wrapField defaults to "items"
// or is derived from op.ResultPath when set.
// If any arg has InputPath set, uses buildNestedInputLiteralStr to build the input literal.
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
// Var decls and inline input args are emitted in alphabetical order by GQL var name.
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
// {items: []T} from the response, returns the slice.
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
// for the purpose of conditional vars inclusion. Distinguishes scalar Go types.
func inlineArgZeroCheck(a InlineArg) string {
	switch a.GoType {
	case "bool":
		return a.Name
	case "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32", "uint64", "float32", "float64":
		return a.Name + " > 0"
	}
	if strings.HasPrefix(a.GoType, "*") || strings.HasPrefix(a.GoType, "[]") {
		return a.Name + " != nil"
	}
	return a.Name + ` != ""`
}

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

// primitiveZeroExpr returns the Go zero-value literal for t, falling back to t+"{}".
func primitiveZeroExpr(t string) string {
	switch t {
	case "int64", "int32", "int", "int16", "int8", "uint64", "uint32", "uint":
		return "0"
	case "float64", "float32":
		return "0"
	case "bool":
		return "false"
	case "string":
		return `""`
	default:
		return t + "{}"
	}
}

func formatGoLiteral(v any) string {
	if v == nil {
		return "nil"
	}
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
	case map[string]any:
		if len(val) == 0 {
			return "map[string]any{}"
		}
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%q: %s", k, formatGoLiteral(val[k])))
		}
		return "map[string]any{" + strings.Join(parts, ", ") + "}"
	case []any:
		parts := make([]string, len(val))
		for i, elem := range val {
			parts[i] = formatGoLiteral(elem)
		}
		return "[]any{" + strings.Join(parts, ", ") + "}"
	default:
		return fmt.Sprintf("%v", val)
	}
}

// buildUnionMergedStruct builds a merged flat IRStruct from a GraphQL interface type's common
// fields plus all variant-specific fields listed in uf. Returns the struct and a slice of
// sub-object base type names that should be enqueued for BFS expansion.
func buildUnionMergedStruct(schema *ast.Schema, interfaceDef *ast.Definition, uf UnionFieldConfig, scalars map[string]string, nestedOverrides map[string]string) (IRStruct, []string, error) {
	seen := make(map[string]bool)
	var fields []IRField
	var subObjectBases []string

	addField := func(fDef *ast.Definition, fName string) error {
		f := fDef.Fields.ForName(fName)
		if f == nil {
			return fmt.Errorf("field %q not on type %s", fName, fDef.Name)
		}
		goType := resolveGoType(f.Type, schema, scalars, nestedOverrides)
		fields = append(fields, IRField{Name: toPascalCase(fName), JSONTag: fName, Type: goType})
		base := baseTypeName(f.Type)
		if childDef := schema.Types[base]; childDef != nil && (childDef.Kind == ast.Object || childDef.Kind == ast.Interface) {
			subObjectBases = append(subObjectBases, base)
		}
		return nil
	}

	for _, fName := range uf.Common {
		if seen[fName] {
			continue
		}
		seen[fName] = true
		if err := addField(interfaceDef, fName); err != nil {
			return IRStruct{}, nil, fmt.Errorf("common %w", err)
		}
	}

	for _, typeName := range sortedStringKeys(uf.Variants) {
		variantDef := schema.Types[typeName]
		if variantDef == nil {
			return IRStruct{}, nil, fmt.Errorf("variant type %q not found in schema", typeName)
		}
		for _, fName := range uf.Variants[typeName] {
			if seen[fName] {
				continue
			}
			seen[fName] = true
			if err := addField(variantDef, fName); err != nil {
				return IRStruct{}, nil, fmt.Errorf("variant %s: %w", typeName, err)
			}
		}
	}

	return IRStruct{
		Comment: fmt.Sprintf("// %s contains %s data.", uf.GoStruct, interfaceDef.Name),
		Name:    uf.GoStruct,
		Fields:  fields,
	}, subObjectBases, nil
}

// sortedStringKeys returns the keys of a map[string][]string in sorted order.
func sortedStringKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// zeroVal returns the correct Go zero-value expression for a return type.
func zeroVal(t string) string {
	if strings.HasPrefix(t, "*") || strings.HasPrefix(t, "[]") {
		return "nil"
	}
	return t + "{}"
}
