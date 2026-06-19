// Copyright 2026 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securitytest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/githubanotaai/huskyci-api/api/types"
)

// Tier-4 parser regression tests for safety.
// See api/securitytest/gosec_test.go for the canonical template.

func loadSafetyFixture(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join("testdata", "safety", name)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read fixture %s: %v", path, err)
	}
	return string(b)
}

// TestParseSafety_HighVulnerabilityFound asserts that realistic safety JSON
// output with issues is parsed and all issues land in HighVulns (hardcoded severity).
func TestParseSafety_HighVulnerabilityFound(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("analyzeSafety panicked on valid input: %v", r)
		}
	}()

	scan := &SecTestScanInfo{
		SecurityTestName: "safety",
		Container: types.Container{
			COutput: loadSafetyFixture(t, "high_vuln.json"),
		},
	}

	if err := analyzeSafety(scan); err != nil {
		t.Fatalf("analyzeSafety returned unexpected error: %v", err)
	}

	if len(scan.Vulnerabilities.HighVulns) < 1 {
		t.Fatalf("expected at least 1 HighVuln, got %d", len(scan.Vulnerabilities.HighVulns))
	}

	for i, v := range scan.Vulnerabilities.HighVulns {
		if v.Severity == "" {
			t.Errorf("HighVulns[%d].Severity is empty", i)
		}
		if v.Details == "" {
			t.Errorf("HighVulns[%d].Details is empty", i)
		}
		if v.File == "" {
			t.Errorf("HighVulns[%d].File is empty", i)
		}
	}
}

// TestParseSafety_CleanOutputProducesEmptyResults asserts that a clean safety
// run (no issues) yields no vulnerabilities and no error.
func TestParseSafety_CleanOutputProducesEmptyResults(t *testing.T) {
	t.Parallel()

	scan := &SecTestScanInfo{
		SecurityTestName: "safety",
		Container: types.Container{
			COutput: loadSafetyFixture(t, "no_vuln.json"),
		},
	}

	if err := analyzeSafety(scan); err != nil {
		t.Fatalf("analyzeSafety returned unexpected error on clean output: %v", err)
	}
	if len(scan.Vulnerabilities.HighVulns) != 0 {
		t.Errorf("expected 0 HighVulns, got %d", len(scan.Vulnerabilities.HighVulns))
	}
	if len(scan.Vulnerabilities.MediumVulns) != 0 {
		t.Errorf("expected 0 MediumVulns, got %d", len(scan.Vulnerabilities.MediumVulns))
	}
	if len(scan.Vulnerabilities.LowVulns) != 0 {
		t.Errorf("expected 0 LowVulns, got %d", len(scan.Vulnerabilities.LowVulns))
	}
}

// TestParseSafety_MalformedOutputDoesNotPanic catches gap #7 at the parser
// level. Renaming "issues" → "findings" causes SafetyIssues to remain nil,
// producing zero vulns without panicking.
func TestParseSafety_MalformedOutputDoesNotPanic(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("safety parser panicked on malformed input: %v\n"+
				"This is gap #7 — the parser must not panic; it must return an error or empty result", r)
		}
	}()

	scan := &SecTestScanInfo{
		SecurityTestName: "safety",
		Container: types.Container{
			COutput: loadSafetyFixture(t, "malformed.json"),
		},
	}

	err := analyzeSafety(scan)
	total := len(scan.Vulnerabilities.HighVulns) +
		len(scan.Vulnerabilities.MediumVulns) +
		len(scan.Vulnerabilities.LowVulns)
	if err == nil && total != 0 {
		t.Errorf("expected zero vulnerabilities OR a non-nil error from malformed input; got %d vulns and nil error", total)
	}
}
