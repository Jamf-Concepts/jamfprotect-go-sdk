// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package main

import "testing"

func TestWalkTransitiveClosure(t *testing.T) {
	schema := loadTestSchema(t, `
		type Query { getRole(id: ID!): Role }
		type Role {
			id: ID!
			name: String
			perms: [Permission!]!
		}
		type Permission {
			scope: Scope
		}
		type Scope { value: String }
		type Orphan { id: ID! }
	`)
	cfg := Config{
		Resources: []ResourceConfig{{
			TypeName: "Role",
			Fields:   []string{"id", "name", "perms"},
			Operations: []OperationConfig{
				{Name: "GetRole", GQLName: "getRole"},
			},
		}},
	}
	sf := newSchemaFilter(schema)
	for _, r := range cfg.Resources {
		sf.walkResource(r)
	}
	sf.walkTransitive()

	for _, want := range []string{"Role", "Permission", "Scope"} {
		if _, ok := sf.types[want]; !ok {
			t.Errorf("expected type %q in filtered set, missing", want)
		}
	}
	if _, ok := sf.types["Orphan"]; ok {
		t.Errorf("Orphan should not be in filtered set; was pulled in")
	}
}

func TestWalkTransitiveRespectsFieldAllow(t *testing.T) {
	schema := loadTestSchema(t, `
		type Query { getThing(id: ID!): Thing }
		type Thing {
			id: ID!
			used: Sub
			unused: HiddenSub
		}
		type Sub { x: String }
		type HiddenSub { y: String }
	`)
	cfg := Config{
		Resources: []ResourceConfig{{
			TypeName: "Thing",
			Fields:   []string{"id", "used"},
			Operations: []OperationConfig{
				{Name: "GetThing", GQLName: "getThing"},
			},
		}},
	}
	sf := newSchemaFilter(schema)
	for _, r := range cfg.Resources {
		sf.walkResource(r)
	}
	sf.walkTransitive()

	if _, ok := sf.types["Sub"]; !ok {
		t.Errorf("Sub should be pulled in via allowed field")
	}
	if _, ok := sf.types["HiddenSub"]; ok {
		t.Errorf("HiddenSub should not be pulled in; field is excluded")
	}
}
