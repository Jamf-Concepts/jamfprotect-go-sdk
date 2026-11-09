// Copyright Jamf Software LLC 2026
// SPDX-License-Identifier: MIT

package jamfprotect

import (
	"encoding/json/v2"
	"testing"
)

// TestNullableInputOmitsOnlyNil checks that nullable input fields omit nil but keep empty values.
func TestNullableInputOmitsOnlyNil(t *testing.T) {
	t.Parallel()

	empty := ""
	tests := []struct {
		name string
		in   ExceptionInput
		want string
	}{
		{"nil omitted", ExceptionInput{Type: "t", IgnoreActivity: "a"}, `{"type":"t","ignoreActivity":"a"}`},
		{"empty string kept", ExceptionInput{Type: "t", IgnoreActivity: "a", Value: &empty}, `{"type":"t","value":"","ignoreActivity":"a"}`},
		{"empty slice kept", ExceptionInput{Type: "t", IgnoreActivity: "a", AnalyticTypes: []string{}}, `{"type":"t","ignoreActivity":"a","analyticTypes":[]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := json.Marshal(tt.in)
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("Marshal() = %s, want %s", got, tt.want)
			}
		})
	}
}
