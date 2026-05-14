// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"context"
	"strings"
	"testing"
)

func TestAcc_User_CRUD(t *testing.T) {
	client := accClient(t)
	ctx := context.Background()
	email := accName("user") + "@example.invalid"

	// Create
	connectionID := "1"
	input := UserInput{
		Email:                 email,
		ConnectionID:          &connectionID,
		RoleIDs:               []string{},
		GroupIDs:              []string{},
		ReceiveEmailAlert:     false,
		EmailAlertMinSeverity: "Low",
	}
	created, err := client.CreateUser(ctx, input)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if created.ID == "" {
		t.Fatal("CreateUser: expected non-empty ID")
	}
	if !strings.EqualFold(created.Email, email) {
		t.Fatalf("CreateUser: expected email %q, got %q", email, created.Email)
	}
	defer func() {
		if err := client.DeleteUser(ctx, created.ID); err != nil {
			t.Logf("cleanup DeleteUser(%s): %v", created.ID, err)
		}
	}()

	// Get
	got, err := client.GetUser(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got == nil {
		t.Fatal("GetUser: expected non-nil user")
	}
	if got.ID != created.ID {
		t.Fatalf("GetUser: expected ID %q, got %q", created.ID, got.ID)
	}

	// List
	users, err := client.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	found := false
	for _, u := range users {
		if u.ID == created.ID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ListUsers: created user %q not found in list", created.ID)
	}

	// Update — change receiveEmailAlert and severity
	updateInput := UserInput{
		Email:                 email,
		RoleIDs:               []string{},
		GroupIDs:              []string{},
		ReceiveEmailAlert:     true,
		EmailAlertMinSeverity: "High",
	}
	updated, err := client.UpdateUser(ctx, created.ID, updateInput)
	if err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if !updated.ReceiveEmailAlert {
		t.Fatalf("UpdateUser: expected receiveEmailAlert=true")
	}
	if updated.EmailAlertMinSeverity != "High" {
		t.Fatalf("UpdateUser: expected severity High, got %q", updated.EmailAlertMinSeverity)
	}

	// Delete (the deferred cleanup also covers this, but explicit delete validates the API)
	if err := client.DeleteUser(ctx, created.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
}
