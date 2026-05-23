// Copyright 2024 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securitytest

import (
	"os"
	"testing"
)

func TestIsTestDisabled(t *testing.T) {
	tests := []struct {
		name      string
		testName  string
		envValue  string
		want      bool
		setEnv    bool
	}{
		{
			name:     "disabled with 'true'",
			testName: "gitauthors",
			envValue: "true",
			setEnv:   true,
			want:     true,
		},
		{
			name:     "disabled with 'TRUE'",
			testName: "gitauthors",
			envValue: "TRUE",
			setEnv:   true,
			want:     true,
		},
		{
			name:     "disabled with '1'",
			testName: "gitleaks",
			envValue: "1",
			setEnv:   true,
			want:     true,
		},
		{
			name:     "enabled with 'false'",
			testName: "gitauthors",
			envValue: "false",
			setEnv:   true,
			want:     false,
		},
		{
			name:     "enabled with empty string",
			testName: "gitauthors",
			envValue: "",
			setEnv:   true,
			want:     false,
		},
		{
			name:     "enabled when env not set",
			testName: "gitauthors",
			setEnv:   false,
			want:     false,
		},
		{
			name:     "disabled with random value treated as false",
			testName: "gitauthors",
			envValue: "random",
			setEnv:   true,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envVarName := "HUSKYCI_DISABLE_" + upper(tt.testName)
			if tt.setEnv {
				os.Setenv(envVarName, tt.envValue)
				defer os.Unsetenv(envVarName)
			}

			got := isTestDisabled(tt.testName)
			if got != tt.want {
				t.Errorf("isTestDisabled(%q) = %v, want %v", tt.testName, got, tt.want)
			}
		})
	}
}

func upper(s string) string {
	// Simple uppercase helper - matches strings.ToUpper behavior
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			result[i] = c - 32
		} else {
			result[i] = c
		}
	}
	return string(result)
}
