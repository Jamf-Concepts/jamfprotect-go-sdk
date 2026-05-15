// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package main

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
