// Copyright 2024 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securitytest

import (
	"fmt"
	"os"
	"testing"


	"github.com/githubanotaai/huskyci-api/api/types"
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
				if err := os.Setenv(envVarName, tt.envValue); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := os.Unsetenv(envVarName); err != nil {
						t.Fatal(err)
					}
				}()
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

func TestStart_FirstErrorCancelsRemaining(t *testing.T) {
	mockGenericTests := []types.SecurityTest{
		{Name: "gitleaks"},
		{Name: "gitauthors"},
	}

	runner := &mockRunner{
		genericTests: mockGenericTests,
		newScanFunc: func(RID, URL, branch, name string, le map[string]bool, dh string) (*SecTestScanInfo, error) {
			return &SecTestScanInfo{
				RID:              RID,
				SecurityTestName: name,
				Container:        types.Container{CID: "cid-" + name, CResult: "passed"},
			}, nil
		},
		startScanFunc: func(scan *SecTestScanInfo) error {
			if scan.SecurityTestName == "gitleaks" {
				return fmt.Errorf("gitleaks scan failed")
			}
			return nil
		},
	}

	results := &RunAllInfo{runner: runner}
	enryScan := SecTestScanInfo{
		RID: "test-rid", URL: "https://example.com/repo", Branch: "main",
	}

	err := results.Start(enryScan)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != "gitleaks scan failed" {
		t.Errorf("expected 'gitleaks scan failed', got %q", err.Error())
	}
}

func TestStart_ConcurrentErrorsNoPanic(t *testing.T) {
	mockGenericTests := []types.SecurityTest{
		{Name: "gitleaks"}, {Name: "gitauthors"},
	}

	runner := &mockRunner{
		genericTests: mockGenericTests,
		newScanFunc: func(RID, URL, branch, name string, le map[string]bool, dh string) (*SecTestScanInfo, error) {
			return &SecTestScanInfo{
				RID: RID, SecurityTestName: name,
				Container: types.Container{CID: "cid-" + name},
			}, nil
		},
		startScanFunc: func(scan *SecTestScanInfo) error {
			return fmt.Errorf("scan %s failed", scan.SecurityTestName)
		},
	}

	results := &RunAllInfo{runner: runner}
	enryScan := SecTestScanInfo{
		RID: "test-rid-stress", URL: "https://example.com/repo", Branch: "main",
	}

	err := results.Start(enryScan)
	if err == nil {
		t.Fatal("expected error with all scans failing")
	}
	// Key: no panic occurred
}

func TestStart_AllScansPass(t *testing.T) {
	mockGenericTests := []types.SecurityTest{
		{Name: "gitleaks"}, {Name: "gitauthors"},
	}

	runner := &mockRunner{
		genericTests: mockGenericTests,
		newScanFunc: func(RID, URL, branch, name string, le map[string]bool, dh string) (*SecTestScanInfo, error) {
			return &SecTestScanInfo{
				RID: RID, SecurityTestName: name,
				Container: types.Container{CID: "cid-" + name, CResult: "passed", CStatus: "finished"},
			}, nil
		},
		startScanFunc: func(scan *SecTestScanInfo) error { return nil },
	}

	results := &RunAllInfo{runner: runner}
	enryScan := SecTestScanInfo{
		RID: "test-rid-pass", URL: "https://example.com/repo", Branch: "main",
	}

	err := results.Start(enryScan)
	if err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestStart_ConcurrentWritesDataRace(t *testing.T) {
	mockGenericTests := []types.SecurityTest{
		{Name: "gitleaks"},
		{Name: "gitauthors"},
	}

	runner := &mockRunner{
		genericTests: mockGenericTests,
		newScanFunc: func(RID, URL, branch, name string, le map[string]bool, dh string) (*SecTestScanInfo, error) {
			scan := &SecTestScanInfo{
				RID:              RID,
				SecurityTestName: name,
				Container: types.Container{
					CID:     "cid-" + name,
					CResult: "passed",
					CStatus: "finished",
				},
				CommitAuthors: GitAuthorsOutput{
					Authors: []string{"author-" + name},
				},
			}
			// Add vulns for gitleaks so setVulns has data to append
			if name == "gitleaks" {
				scan.Vulnerabilities = types.HuskyCISecurityTestOutput{
					HighVulns: []types.HuskyCIVulnerability{{Details: name + "-high-vuln"}},
				}
			}
			return scan, nil
		},
		startScanFunc: func(scan *SecTestScanInfo) error { return nil },
	}

	results := &RunAllInfo{runner: runner}
	enryScan := SecTestScanInfo{
		RID: "race-test-rid", URL: "https://example.com/repo", Branch: "main",
	}

	// This triggers concurrent Container append + CommitAuthors + setVulns writes
	err := results.Start(enryScan)
	if err != nil {
		t.Errorf("expected nil, got %v", err)
	}

	// Verify we got results from both scans (basic correctness)
	if len(results.Containers) < 2 {
		t.Errorf("expected at least 2 containers, got %d", len(results.Containers))
	}
}
