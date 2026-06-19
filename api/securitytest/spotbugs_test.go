// Copyright 2026 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securitytest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/githubanotaai/huskyci-api/api/log"
	"github.com/githubanotaai/huskyci-api/api/types"
)

// noopGelfLogger satisfies the log.logger interface so that log.Warning
// (and similar calls inside parser code) do not nil-pointer-dereference
// when the log package has not been initialised (as is the case during
// unit tests).
type noopGelfLogger struct{}

func (n noopGelfLogger) SendLog(extra map[string]interface{}, loglevel string, messages ...interface{}) error {
	return nil
}

// Tier-4 parser regression template. Pattern to copy when adding tests for
// the remaining per-tool analyzers (bandit, brakeman, npmaudit, spotbugs, ...).

// init ensures the log package has a functioning logger so that log.Warning
// calls inside the spotbugs parser (e.g. on non-numeric rank) do not
// nil-pointer-dereference during unit tests.
func init() {
	if log.Logger == nil {
		log.Logger = noopGelfLogger{}
	}
}

func loadSpotbugsFixture(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join("testdata", "spotbugs", name)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read fixture %s: %v", path, err)
	}
	return string(b)
}

// TestParseSpotbugs_HighVulnerabilityFound asserts that a realistic SpotBugs XML
// output with a HIGH rank finding is parsed and bucketed correctly into
// scan.Vulnerabilities by severity.
func TestParseSpotbugs_HighVulnerabilityFound(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("analyzeSpotBugs panicked on valid input: %v", r)
		}
	}()

	scan := &SecTestScanInfo{
		SecurityTestName: "spotbugs",
		Container: types.Container{
			COutput: loadSpotbugsFixture(t, "high_vuln.xml"),
		},
	}

	if err := analyzeSpotBugs(scan); err != nil {
		t.Fatalf("analyzeSpotBugs returned unexpected error: %v", err)
	}

	if len(scan.Vulnerabilities.HighVulns) < 1 {
		t.Fatalf("expected at least 1 HighVuln, got %d", len(scan.Vulnerabilities.HighVulns))
	}
	if len(scan.Vulnerabilities.MediumVulns) < 1 {
		t.Errorf("expected at least 1 MediumVuln, got %d", len(scan.Vulnerabilities.MediumVulns))
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

// TestParseSpotbugs_CleanOutputProducesEmptyResults asserts that a clean SpotBugs
// run (no findings) yields no vulnerabilities and no error.
func TestParseSpotbugs_CleanOutputProducesEmptyResults(t *testing.T) {
	t.Parallel()

	scan := &SecTestScanInfo{
		SecurityTestName: "spotbugs",
		Container: types.Container{
			COutput: loadSpotbugsFixture(t, "no_vuln.xml"),
		},
	}

	if err := analyzeSpotBugs(scan); err != nil {
		t.Fatalf("analyzeSpotBugs returned unexpected error on clean output: %v", err)
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

// TestParseSpotbugs_MalformedOutputDoesNotPanic catches gap #7 at the parser
// level. If the parser panics on schema-misnamed input, the goroutine in
// run.go (no defer recover() today) brings down the API process. The parser
// must either return an empty result or return a non-nil error — but it must
// not panic.
func TestParseSpotbugs_MalformedOutputDoesNotPanic(t *testing.T) {
	t.Parallel()

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("spotbugs parser panicked on malformed input: %v\n"+
				"This is gap #7 — the parser must not panic; it must return an error or empty result", r)
		}
	}()

	scan := &SecTestScanInfo{
		SecurityTestName: "spotbugs",
		Container: types.Container{
			COutput: loadSpotbugsFixture(t, "malformed.xml"),
		},
	}

	err := analyzeSpotBugs(scan)
	// Either outcome is acceptable: parser returns an error, OR parser succeeds
	// with zero vulnerabilities because the non-numeric rank triggers a
	// continue in prepareSpotBugsVulns, producing zero vulns.
	total := len(scan.Vulnerabilities.HighVulns) +
		len(scan.Vulnerabilities.MediumVulns) +
		len(scan.Vulnerabilities.LowVulns)
	if err == nil && total != 0 {
		t.Errorf("expected zero vulnerabilities OR a non-nil error from malformed input; got %d vulns and nil error", total)
	}
}
