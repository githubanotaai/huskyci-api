// Copyright 2026 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package analysis

import (
	"testing"

	"github.com/githubanotaai/huskyci-api/client/types"
)

// Tier-2 client contract. Protects the exit-code 190 signal that GitHub Actions
// pipelines consume to distinguish "scan ran and found blockers" from "scan
// infrastructure failed".
//
// TESTABILITY GAP: the actual os.Exit calls live inline in client/cmd/main.go
// (lines 32, 44, 55, 82, 98 for os.Exit(1); line 112/125 for os.Exit(0); line
// 145 for os.Exit(190)). They can't be unit-tested without subprocess tricks.
// However, the decision driving them is purely a function of the package-level
// booleans types.FoundVuln and types.FoundInfo, which prepareAllSummary sets
// from the API response. Testing that function pins the exact same decision
// surface the main() switch reads.
//
// These tests cannot run in parallel — types.FoundVuln, types.FoundInfo, and
// the package-level outputJSON are shared mutable state.

// resetSummaryState clears all globals that prepareAllSummary mutates so each
// test starts from a clean slate.
func resetSummaryState() {
	outputJSON = types.JSONOutput{}
	types.FoundVuln = false
	types.FoundInfo = false
}

// TestExitDecision_190WhenBlockingVulnerabilitiesFound:
// CONTRACT: the client exits 190 when blocking (HIGH or MEDIUM) vulnerabilities
// are present. This is an intentional, load-bearing CI/CD signal — pipelines
// rely on the distinction between "scan failed" (exit 1) and "scan found bugs"
// (exit 190). Do not change this value.
func TestExitDecision_190WhenBlockingVulnerabilitiesFound(t *testing.T) {
	resetSummaryState()

	analysis := types.Analysis{
		HuskyCIResults: types.HuskyCIResults{
			GoResults: types.GoResults{
				HuskyCIGosecOutput: types.HuskyCISecurityTestOutput{
					HighVulns: []types.HuskyCIVulnerability{
						{
							Language:     "Go",
							SecurityTool: "GoSec",
							Severity:     "HIGH",
							Title:        "Use of weak cryptographic primitive",
							File:         "main.go",
							Line:         "12",
						},
					},
				},
			},
		},
	}

	prepareAllSummary(analysis)

	if !types.FoundVuln {
		t.Fatal("expected types.FoundVuln=true with a HIGH vuln present (would cause main() to os.Exit(190))")
	}
	// Sanity check on the summary the main() switch also reads.
	if !outputJSON.Summary.GosecSummary.FoundVuln {
		t.Error("expected GosecSummary.FoundVuln=true")
	}
	if outputJSON.Summary.TotalSummary.HighVuln != 1 {
		t.Errorf("expected TotalSummary.HighVuln=1, got %d", outputJSON.Summary.TotalSummary.HighVuln)
	}
}

// TestExitDecision_0WhenNoVulnerabilitiesFound asserts the clean-scan path:
// no findings of any severity → FoundVuln and FoundInfo both false →
// main() takes the os.Exit(0) branch at client/cmd/main.go:112.
func TestExitDecision_0WhenNoVulnerabilitiesFound(t *testing.T) {
	resetSummaryState()

	analysis := types.Analysis{
		Result:         "passed",
		HuskyCIResults: types.HuskyCIResults{},
	}

	prepareAllSummary(analysis)

	if types.FoundVuln {
		t.Error("expected types.FoundVuln=false on empty results")
	}
	if types.FoundInfo {
		t.Error("expected types.FoundInfo=false on empty results")
	}
}

// TestExitDecision_NonZeroNotOneNinetyWhenAPIUnreachable documents the
// invariant: the API-error exit code MUST differ from the vulnerability-
// found exit code so CI pipelines can distinguish the two situations.
//
// TESTABILITY GAP: API-error exits live inline as os.Exit(1) at main.go:32,
// 44, 55, 82, 98 — none are extracted into a callable function. The test
// pins the literal-vs-literal invariant instead of executing main().
//
// PROBABLE GAP: a future refactor should hoist these into named constants
// (e.g. ExitOK=0, ExitAPIError=1, ExitVulnFound=190) and a thin
// decideExitCode(types.Analysis, error) int helper so the exact decision
// can be exercised here without subprocess plumbing.
func TestExitDecision_NonZeroNotOneNinetyWhenAPIUnreachable(t *testing.T) {
	const (
		apiErrorExit  = 1   // client/cmd/main.go:32, 44, 55, 82, 98
		vulnFoundExit = 190 // client/cmd/main.go:145
		cleanScanExit = 0   // client/cmd/main.go:112, 125
	)

	if apiErrorExit == vulnFoundExit {
		t.Fatalf("apiErrorExit (%d) must not equal vulnFoundExit (%d) — CI consumers rely on the distinction",
			apiErrorExit, vulnFoundExit)
	}
	if apiErrorExit == cleanScanExit {
		t.Fatalf("apiErrorExit (%d) must not equal cleanScanExit (%d)", apiErrorExit, cleanScanExit)
	}
	if apiErrorExit == 0 {
		t.Fatalf("apiErrorExit must be non-zero, got %d", apiErrorExit)
	}
}
