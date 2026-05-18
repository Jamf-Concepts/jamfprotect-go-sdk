// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
)

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
			if nullableSet[nf.Name] {
				if !strings.HasPrefix(nfGoType, "[]") && !strings.HasPrefix(nfGoType, "*") {
					nfGoType = "*" + nfGoType
				}
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
			if nullableSet[f.Name] {
				if !strings.HasPrefix(fGoType, "[]") && !strings.HasPrefix(fGoType, "*") {
					fGoType = "*" + fGoType
				}
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
