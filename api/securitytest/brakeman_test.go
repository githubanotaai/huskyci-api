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

// Tier-4 parser regression test. Mirrors gosec_test.go.

func loadBrakemanFixture(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join("testdata", "brakeman", name)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read fixture %s: %v", path, err)
	}
	return string(b)
}

// TestParseBrakeman_HighVulnerabilityFound asserts that a realistic brakeman JSON
// output with High and Medium confidence findings is parsed and bucketed correctly
// into scan.Vulnerabilities by confidence level.
func TestParseBrakeman_HighVulnerabilityFound(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("analyzeBrakeman panicked on valid input: %v", r)
		}
	}()

	scan := &SecTestScanInfo{
		SecurityTestName: "brakeman",
		Container: types.Container{
			COutput: loadBrakemanFixture(t, "high_vuln.json"),
		},
	}

	if err := analyzeBrakeman(scan); err != nil {
		t.Fatalf("analyzeBrakeman returned unexpected error: %v", err)
	}

	if len(scan.Vulnerabilities.HighVulns) < 1 {
		t.Fatalf("expected at least 1 HighVuln, got %d", len(scan.Vulnerabilities.HighVulns))
	}
	if len(scan.Vulnerabilities.MediumVulns) < 1 {
		t.Errorf("expected at least 1 MediumVuln, got %d", len(scan.Vulnerabilities.MediumVulns))
	}

	for i, v := range scan.Vulnerabilities.HighVulns {
		if v.Confidence == "" {
			t.Errorf("HighVulns[%d].Confidence is empty", i)
		}
		if v.Details == "" {
			t.Errorf("HighVulns[%d].Details is empty", i)
		}
		if v.File == "" {
			t.Errorf("HighVulns[%d].File is empty", i)
		}
	}
}

// TestParseBrakeman_CleanOutputProducesEmptyResults asserts that a clean brakeman
// run (no findings) yields no vulnerabilities and no error.
func TestParseBrakeman_CleanOutputProducesEmptyResults(t *testing.T) {
	t.Parallel()

	scan := &SecTestScanInfo{
		SecurityTestName: "brakeman",
		Container: types.Container{
			COutput: loadBrakemanFixture(t, "no_vuln.json"),
		},
	}

	if err := analyzeBrakeman(scan); err != nil {
		t.Fatalf("analyzeBrakeman returned unexpected error on clean output: %v", err)
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

// TestParseBrakeman_MalformedOutputDoesNotPanic catches gap #7 at the parser
// level. If the parser panics on schema-misnamed input, the goroutine in
// run.go brings down the API process. The parser must either return an empty
// result or return a non-nil error — but it must not panic.
func TestParseBrakeman_MalformedOutputDoesNotPanic(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("brakeman parser panicked on malformed input: %v\n"+
				"This is gap #7 — the parser must not panic; it must return an error or empty result", r)
		}
	}()

	scan := &SecTestScanInfo{
		SecurityTestName: "brakeman",
		Container: types.Container{
			COutput: loadBrakemanFixture(t, "malformed.json"),
		},
	}

	err := analyzeBrakeman(scan)
	// Either outcome is acceptable: parser returns an error, OR parser succeeds
	// with zero vulnerabilities because the misnamed "alerts" field is ignored
	// by encoding/json. What matters is that no panic escaped this goroutine.
	total := len(scan.Vulnerabilities.HighVulns) +
		len(scan.Vulnerabilities.MediumVulns) +
		len(scan.Vulnerabilities.LowVulns)
	if err == nil && total != 0 {
		t.Errorf("expected zero vulnerabilities OR a non-nil error from malformed input; got %d vulns and nil error", total)
	}
}
