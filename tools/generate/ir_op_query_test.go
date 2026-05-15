// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package main

import (
	"strings"
	"testing"
)

// callBuildQueryStr is a tiny helper so tests stay readable; the underlying
// function takes seven args, most of which are nil in unit-test fixtures.
func callBuildQueryStr(t *testing.T, sdl string, op OperationConfig, res ResourceConfig) string {
	t.Helper()
	schema := loadTestSchema(t, sdl)
	got, err := buildQueryStr(schema, op, res, opGQLName(op), op.Kind, nil, nil, nil)
	if err != nil {
		t.Fatalf("buildQueryStr: %v", err)
	}
	return got
}

func opGQLName(op OperationConfig) string {
	if op.GQLName != "" {
		return op.GQLName
	}
	return lcFirst(op.Name)
}

// assertEqualGQL compares two GQL strings after collapsing runs of whitespace.
// GQL whitespace is non-semantic; this keeps tests resilient to indentation
// tweaks in the builders without losing string-shape coverage.
func assertEqualGQL(t *testing.T, got, want string) {
	t.Helper()
	normalize := func(s string) string {
		return strings.Join(strings.Fields(s), " ")
	}
	if normalize(got) != normalize(want) {
		t.Errorf("query mismatch:\n got  %q\n want %q", got, want)
	}
}

func TestBuildQueryStr_Get(t *testing.T) {
	got := callBuildQueryStr(t,
		`type Query { getRole(id: ID!): Role } type Role { id: ID! name: String }`,
		OperationConfig{Name: "GetRole", GQLName: "getRole", Kind: "get"},
		ResourceConfig{TypeName: "Role", Fields: []string{"id", "name"}},
	)
	assertEqualGQL(t, got, `query getRole($id: ID!) { getRole(id: $id) { ...RoleFields } }`)
}

func TestBuildQueryStr_Delete(t *testing.T) {
	got := callBuildQueryStr(t,
		`type Query { _: String } type Mutation { deleteRole(id: ID!): Role } type Role { id: ID! }`,
		OperationConfig{Name: "DeleteRole", GQLName: "deleteRole", Kind: "delete"},
		ResourceConfig{TypeName: "Role", Fields: []string{"id"}},
	)
	assertEqualGQL(t, got, `mutation deleteRole($id: ID!) { deleteRole(id: $id) { id } }`)
}

func TestBuildQueryStr_Create_WrappedInput(t *testing.T) {
	got := callBuildQueryStr(t,
		`type Query{_:String} type Mutation { createRole(input: RoleInput!): Role } input RoleInput { name: String! } type Role { id: ID! name: String }`,
		OperationConfig{
			Name: "CreateRole", GQLName: "createRole", Kind: "create",
			InputType: "RoleInput", WrappedInput: true,
		},
		ResourceConfig{TypeName: "Role", Fields: []string{"id", "name"}},
	)
	assertEqualGQL(t, got, `mutation createRole($input: RoleInput!) { createRole(input: $input) { ...RoleFields } }`)
}

func TestBuildQueryStr_Create_ExpandedFields(t *testing.T) {
	got := callBuildQueryStr(t,
		`type Query{_:String} type Mutation { createRole(input: RoleInput!): Role } input RoleInput { name: String!, description: String } type Role { id: ID! }`,
		OperationConfig{
			Name: "CreateRole", GQLName: "createRole", Kind: "create",
			InputType: "RoleInput",
		},
		ResourceConfig{TypeName: "Role", Fields: []string{"id"}, InputFields: []string{"name", "description"}},
	)
	assertEqualGQL(t, got, `mutation createRole($name: String!, $description: String) { createRole( input: {name: $name, description: $description} ) { ...RoleFields } }`)
}

func TestBuildQueryStr_Update_WrappedInput(t *testing.T) {
	got := callBuildQueryStr(t,
		`type Query{_:String} type Mutation { updateRole(id: ID!, input: RoleInput!): Role } input RoleInput { name: String! } type Role { id: ID! }`,
		OperationConfig{
			Name: "UpdateRole", GQLName: "updateRole", Kind: "update",
			InputType: "RoleInput", WrappedInput: true,
		},
		ResourceConfig{TypeName: "Role", Fields: []string{"id"}},
	)
	assertEqualGQL(t, got, `mutation updateRole($id: ID!, $input: RoleInput!) { updateRole(id: $id, input: $input) { ...RoleFields } }`)
}

func TestBuildQueryStr_List_Simple(t *testing.T) {
	got := callBuildQueryStr(t,
		`type Query { listRoles: RoleList } type RoleList { items: [Role] } type Role { id: ID! }`,
		OperationConfig{Name: "ListRoles", GQLName: "listRoles", Kind: "list"},
		ResourceConfig{TypeName: "Role", Fields: []string{"id"}},
	)
	assertEqualGQL(t, got, `query listRoles { listRoles { items { ...RoleFields } } }`)
}

func TestBuildQueryStr_ListSimple_TopLevelArray(t *testing.T) {
	got := callBuildQueryStr(t,
		`type Query { listInsights: [Insight] } type Insight { id: ID! }`,
		OperationConfig{Name: "ListInsights", GQLName: "listInsights", Kind: "list_simple"},
		ResourceConfig{TypeName: "Insight", Fields: []string{"id"}},
	)
	assertEqualGQL(t, got, `query listInsights { listInsights { ...InsightFields } }`)
}

func TestBuildQueryStr_ListItems_OptionalInlineArgs(t *testing.T) {
	got := callBuildQueryStr(t,
		`type Query { listRiskiestComputers(input: RiskyComputersInput): RiskyComputerConnection } input RiskyComputersInput { limit: Int, createdInterval: String } type RiskyComputerConnection { items: [RiskyComputer] } type RiskyComputer { id: ID! }`,
		OperationConfig{
			Name: "ListRiskiestComputers", GQLName: "listRiskiestComputers", Kind: "list_items",
			ReturnType: "RiskyComputer", NoFragment: true,
			InlineArgs: []InlineArg{
				{Name: "limit", GoType: "int", GQLVar: "limit", GQLType: "Int", IsOptional: true},
				{Name: "createdInterval", GoType: "string", GQLVar: "createdInterval", GQLType: "String", IsOptional: true},
			},
		},
		ResourceConfig{TypeName: "Dashboard", Fields: []string{"id"}},
	)
	assertEqualGQL(t, got, `query listRiskiestComputers($createdInterval: String, $limit: Int) { listRiskiestComputers(input: {createdInterval: $createdInterval, limit: $limit}) { items { ...DashboardFields } } }`)
}

func TestBuildQueryStr_SingletonGet_NoArgs(t *testing.T) {
	got := callBuildQueryStr(t,
		`type Query { getOrganization: Organization } type Organization { id: ID! }`,
		OperationConfig{Name: "GetOrganization", GQLName: "getOrganization", Kind: "singleton_get"},
		ResourceConfig{TypeName: "Organization", Fields: []string{"id"}},
	)
	assertEqualGQL(t, got, `query getOrganization { getOrganization { ...OrganizationFields } }`)
}

func TestBuildQueryStr_SingletonGet_ResultPath(t *testing.T) {
	got := callBuildQueryStr(t,
		`type Query { getOrg: Org } type Org { sub: Sub } type Sub { id: ID! name: String }`,
		OperationConfig{
			Name: "GetOrgSub", GQLName: "getOrg", Kind: "singleton_get",
			ResultPath: "getOrg.sub", GQLReturnType: "Sub",
		},
		ResourceConfig{TypeName: "Sub", Fields: []string{"id", "name"}},
	)
	assertEqualGQL(t, got, `query getOrg { getOrg { sub { ...SubFields } } }`)
}

func TestBuildQueryStr_SingletonGet_ResultPathLeaf(t *testing.T) {
	// resultPathLeaf: the last segment is a scalar field, no further wrap.
	got := callBuildQueryStr(t,
		`type Query { getComputerCount: ComputerCountResponse } type ComputerCountResponse { computers: Int }`,
		OperationConfig{
			Name: "GetComputerCount", GQLName: "getComputerCount", Kind: "singleton_get",
			ResultPath: "getComputerCount.computers", ResultPathLeaf: true, NoFragment: true,
		},
		ResourceConfig{TypeName: "ComputerCountResponse", Fields: []string{"computers"}},
	)
	assertEqualGQL(t, got, `query getComputerCount { getComputerCount { computers } }`)
}

func TestBuildQueryStr_SingletonGet_NoSelection(t *testing.T) {
	got := callBuildQueryStr(t,
		`type Query { getOrgConfigFreezeReason: String }`,
		OperationConfig{
			Name: "GetConfigFreezeReason", GQLName: "getOrgConfigFreezeReason", Kind: "singleton_get",
			ReturnType: "string", NoSelection: true, NoFragment: true,
		},
		ResourceConfig{TypeName: "Organization", Fields: []string{}},
	)
	assertEqualGQL(t, got, `query getOrgConfigFreezeReason { getOrgConfigFreezeReason }`)
}

func TestBuildQueryStr_SingletonGet_GQLVarsAndFieldArgs(t *testing.T) {
	// GetCount-style: hidden GQL var declaration whose value comes from extraVarValues.
	got := callBuildQueryStr(t,
		`type Query { getCount(input: CountQueryInput): CountResponse } input CountQueryInput { computers: String } type CountResponse { computers: Int }`,
		OperationConfig{
			Name: "GetCount", GQLName: "getCount", Kind: "singleton_get",
			NoFragment:   true,
			InlineFields: []string{"computers"},
			GQLVars:      map[string]string{"input": "CountQueryInput"},
			FieldArgs:    "input: $input",
		},
		ResourceConfig{TypeName: "CountResponse", Fields: []string{"computers"}},
	)
	assertEqualGQL(t, got, `query getCount($input: CountQueryInput) { getCount(input: $input) { computers } }`)
}

func TestBuildQueryStr_SingletonUpdate(t *testing.T) {
	got := callBuildQueryStr(t,
		`type Query{_:String} type Mutation { updateOrgFreeze(input: FreezeInput!): Organization } input FreezeInput { configFreeze: Boolean! } type Organization { configFreeze: Boolean }`,
		OperationConfig{
			Name: "UpdateConfigFreeze", GQLName: "updateOrgFreeze", Kind: "singleton_update",
			InlineArgs: []InlineArg{
				{Name: "configFreeze", GoType: "bool", GQLVar: "configFreeze", GQLType: "Boolean!"},
			},
		},
		ResourceConfig{TypeName: "Organization", Fields: []string{"configFreeze"}},
	)
	assertEqualGQL(t, got, `mutation updateOrgFreeze($configFreeze: Boolean!) { updateOrgFreeze(input: {configFreeze: $configFreeze}) { ...OrganizationFields } }`)
}

func TestBuildQueryStr_SingletonUpdate_NestedInputPath(t *testing.T) {
	// InputPath collapses scalar args into a nested input literal — used by DataRetention.
	got := callBuildQueryStr(t,
		`type Query{_:String} type Mutation { updateRetention(input: RetentionInput!): Organization } input RetentionInput { days: Int } type Organization { id: ID! }`,
		OperationConfig{
			Name: "UpdateDataRetention", GQLName: "updateRetention", Kind: "singleton_update",
			InlineArgs: []InlineArg{
				{Name: "databaseLogDays", GoType: "int64", GQLVar: "databaseLogDays", GQLType: "Int!", InputPath: "retention.database.log.numberOfDays"},
				{Name: "coldAlertDays", GoType: "int64", GQLVar: "coldAlertDays", GQLType: "Int!", InputPath: "retention.cold.alert.numberOfDays"},
			},
		},
		ResourceConfig{TypeName: "Organization", Fields: []string{"id"}},
	)
	assertEqualGQL(t, got, `mutation updateRetention($databaseLogDays: Int!, $coldAlertDays: Int!) { updateRetention(input: {retention: {database: {log: {numberOfDays: $databaseLogDays}}, cold: {alert: {numberOfDays: $coldAlertDays}}}}) { ...OrganizationFields } }`)
}

func TestBuildQueryStr_UpdateInline(t *testing.T) {
	got := callBuildQueryStr(t,
		`type Query{_:String} type Mutation { setComputerPlan(input: SetPlanInput!): Computer } input SetPlanInput { uuid: ID!, planId: ID } type Computer { uuid: ID! }`,
		OperationConfig{
			Name: "SetComputerPlan", GQLName: "setComputerPlan", Kind: "update_inline",
			InlineArgs: []InlineArg{
				{Name: "uuid", GoType: "string", GQLVar: "uuid", GQLType: "ID!", IsID: true},
				{Name: "planId", GoType: "string", GQLVar: "planId", GQLType: "ID"},
			},
		},
		ResourceConfig{TypeName: "Computer", Fields: []string{"uuid"}, IDField: "uuid"},
	)
	assertEqualGQL(t, got, `mutation setComputerPlan($uuid: ID!, $planId: ID) { setComputerPlan(uuid: $uuid, input: {planId: $planId}) { ...ComputerFields } }`)
}

func TestBuildQueryStr_MutationList(t *testing.T) {
	got := callBuildQueryStr(t,
		`type Query{_:String} type Mutation { updateAlerts(input: AlertBulkInput!): AlertList } input AlertBulkInput { uuids: [ID!]!, status: String! } type AlertList { items: [Alert] } type Alert { uuid: ID! }`,
		OperationConfig{
			Name: "UpdateAlerts", GQLName: "updateAlerts", Kind: "mutation_list",
			InputType: "AlertBulkInput",
		},
		ResourceConfig{TypeName: "Alert", Fields: []string{"uuid"}, InputFields: []string{"uuids", "status"}},
	)
	assertEqualGQL(t, got, `mutation updateAlerts($uuids: [ID!]!, $status: String!) { updateAlerts(input: {uuids: $uuids, status: $status}) { items { ...AlertFields } } }`)
}

func TestBuildQueryStr_MultiWrappedUpdate(t *testing.T) {
	got := callBuildQueryStr(t,
		`type Query{_:String} type Mutation { updateOrgForward(input: ForwardInput!): Organization } input ForwardInput { s3: S3Input, sentinel: SentinelInput } input S3Input { bucket: String } input SentinelInput { dcr: String } type Organization { id: ID! }`,
		OperationConfig{
			Name: "UpdateDataForwarding", GQLName: "updateOrgForward", Kind: "multi_wrapped_update",
			InputTypeGoName: "DataForwardingInput",
			MultiWrappedInputs: []MultiWrappedInput{
				{GoField: "S3", GQLVar: "s3", SchemaType: "S3Input!", GoInputType: "ForwardS3Input"},
				{GoField: "Sentinel", GQLVar: "sentinel", SchemaType: "SentinelInput!", GoInputType: "ForwardSentinelInput"},
			},
		},
		ResourceConfig{TypeName: "Organization", Fields: []string{"id"}},
	)
	assertEqualGQL(t, got, `mutation updateOrgForward($s3: S3Input!, $sentinel: SentinelInput!) { updateOrgForward(input: {s3: $s3, sentinel: $sentinel}) { ...OrganizationFields } }`)
}

func TestBuildQueryStr_DatePaginated(t *testing.T) {
	got := callBuildQueryStr(t,
		`type Query { listAuditLogs(input: AuditLogsInput): AuditLogConnection } input AuditLogsInput { next: String, pageSize: Int, order: AuditLogsOrderInput, condition: AuditLogsDateConditionInput } input AuditLogsOrderInput { direction: String } input AuditLogsDateConditionInput { start: String } type AuditLogConnection { items: [AuditLog] pageInfo: PageInfo } type AuditLog { id: ID! } type PageInfo { next: String total: Int }`,
		OperationConfig{
			Name: "ListAuditLogsByDate", GQLName: "listAuditLogs", Kind: "date_paginated",
		},
		ResourceConfig{TypeName: "AuditLog", Fields: []string{"id"}},
	)
	assertEqualGQL(t, got, `query listAuditLogs( $next: String, $pageSize: Int, $order: AuditLogsOrderInput, $condition: AuditLogsDateConditionInput ) { listAuditLogs( input: {next: $next, pageSize: $pageSize, order: $order, condition: $condition} ) { items { ...AuditLogFields } pageInfo { next total } } }`)
}

// TestBuildQueryStr_UnsupportedKind locks the error path so adding a kind that
// forgets to register a builder fails loudly instead of producing empty output.
func TestBuildQueryStr_UnsupportedKind(t *testing.T) {
	schema := loadTestSchema(t, `type Query { _: String } type Role { id: ID! }`)
	_, err := buildQueryStr(schema, OperationConfig{Name: "Whatever", GQLName: "whatever", Kind: "totally_bogus"}, ResourceConfig{TypeName: "Role", Fields: []string{"id"}}, "whatever", "totally_bogus", nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for unsupported kind, got nil")
	}
	if !strings.Contains(err.Error(), "totally_bogus") {
		t.Fatalf("error should mention unsupported kind: %v", err)
	}
}
