// Copyright 2026 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securitytest

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/githubanotaai/huskyci-api/api/log"
	"github.com/githubanotaai/huskyci-api/api/types"
)

// Tier-1 orchestration safety net. These tests pin down the contract of
// RunAllInfo.Start() so future fixes to run.go (bug #8 finalization order,
// gap #7 panic recovery, gap #3 concurrency limit) cannot silently regress.
//
// Tests use the existing mockRunner from runner.go so no real DB or container
// runtime is involved.

// TestStartAnalysis_HappyPath_MultiScanner verifies that when 3+ generic
// scanners all report CResult="passed" and CStatus="finished", Start() returns
// nil, FinalResult is "passed", and Status is "finished". This pins the
// happy-path contract including the Status field which existing baseline tests
// do not check.
func TestStartAnalysis_HappyPath_MultiScanner(t *testing.T) {
	t.Parallel()

	tests := []types.SecurityTest{
		{Name: "gitleaks"},
		{Name: "gitauthors"},
		{Name: "wizcli_secrets"},
	}

	runner := &mockRunner{
		genericTests: tests,
		newScanFunc: func(RID, URL, branch, name string, le map[string]bool, cf, dh string) (*SecTestScanInfo, error) {
			return &SecTestScanInfo{
				RID:              RID,
				SecurityTestName: name,
				Container: types.Container{
					CID:     "cid-" + name,
					CResult: "passed",
					CStatus: "finished",
				},
			}, nil
		},
		startScanFunc: func(scan *SecTestScanInfo) error { return nil },
	}

	results := &RunAllInfo{runner: runner}
	enryScan := SecTestScanInfo{
		RID: "happy-multi-rid", URL: "https://example.com/repo", Branch: "main",
	}

	if err := results.Start(enryScan); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if results.FinalResult != "passed" {
		t.Errorf("expected FinalResult=%q, got %q", "passed", results.FinalResult)
	}
	if results.Status != "finished" {
		t.Errorf("expected Status=%q, got %q", "finished", results.Status)
	}
}

// TestStartAnalysis_MixedResults verifies that when scanners return a mix of
// results (one failed, one warning, one passed), FinalResult resolves to
// "failed" because failed takes unconditional precedence over both warning
// and passed. Start() must return nil (all scanners completed without error),
// Status must be "finished". Per scope decision: test directly without #25
// skip — current main's setToAnalysis already handles this.
func TestStartAnalysis_MixedResults(t *testing.T) {
	t.Parallel()

	tests := []types.SecurityTest{
		{Name: "gitleaks"},
		{Name: "gitauthors"},
		{Name: "wizcli_secrets"},
	}

	results := map[string]string{
		"gitleaks":       "failed",
		"gitauthors":     "warning",
		"wizcli_secrets": "passed",
	}

	runner := &mockRunner{
		genericTests: tests,
		newScanFunc: func(RID, URL, branch, name string, le map[string]bool, cf, dh string) (*SecTestScanInfo, error) {
			return &SecTestScanInfo{
				RID:              RID,
				SecurityTestName: name,
				Container: types.Container{
					CID:     "cid-" + name,
					CResult: results[name],
					CStatus: "finished",
				},
			}, nil
		},
		startScanFunc: func(scan *SecTestScanInfo) error { return nil },
	}

	run := &RunAllInfo{runner: runner}
	enryScan := SecTestScanInfo{
		RID: "mixed-rid", URL: "https://example.com/repo", Branch: "main",
	}

	if err := run.Start(enryScan); err != nil {
		t.Fatalf("Start returned unexpected error: %v", err)
	}
	if run.FinalResult != "failed" {
		t.Errorf("expected FinalResult=%q with mix of failed/warning/passed, got %q", "failed", run.FinalResult)
	}
	if run.Status != "finished" {
		t.Errorf("expected Status=%q, got %q", "finished", run.Status)
	}
}

// TestStartAnalysis_LanguageFanout verifies that when enry detects Go and
// Python, the runLanguageScans path dispatches gosec for Go and bandit for
// Python. It pins the language-to-scanner mapping contract and exercises the
// runLanguageScans path which currently has zero coverage.
func TestStartAnalysis_LanguageFanout(t *testing.T) {
	t.Parallel()

	languageTests := map[string][]types.SecurityTest{
		"Go":     {{Name: "gosec"}},
		"Python": {{Name: "bandit"}},
	}

	runner := &mockRunner{
		genericTests: nil, // isolate language scan path
		listLanguageTestsFunc: func(language string) ([]types.SecurityTest, error) {
			return languageTests[language], nil
		},
		newScanFunc: func(RID, URL, branch, name string, le map[string]bool, cf, dh string) (*SecTestScanInfo, error) {
			return &SecTestScanInfo{
				RID:              RID,
				SecurityTestName: name,
				Container: types.Container{
					CID:     "cid-" + name,
					CResult: "passed",
					CStatus: "finished",
				},
			}, nil
		},
		startScanFunc: func(scan *SecTestScanInfo) error { return nil },
	}

	results := &RunAllInfo{runner: runner}
	enryScan := SecTestScanInfo{
		RID: "lang-fanout-rid", URL: "https://example.com/repo", Branch: "main",
		Codes: []types.Code{
			{Language: "Go"},
			{Language: "Python"},
		},
	}

	if err := results.Start(enryScan); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	// Exactly 2 containers: one for gosec, one for bandit
	if len(results.Containers) != 2 {
		t.Fatalf("expected 2 containers, got %d", len(results.Containers))
	}

	found := make(map[string]bool)
	for _, c := range results.Containers {
		found[c.CID] = true
	}
	if !found["cid-gosec"] {
		t.Errorf("gosec container not dispatched")
	}
	if !found["cid-bandit"] {
		t.Errorf("bandit container not dispatched")
	}

	if results.FinalResult != "passed" {
		t.Errorf("expected FinalResult=%q, got %q", "passed", results.FinalResult)
	}
	if results.Status != "finished" {
		t.Errorf("expected Status=%q, got %q", "finished", results.Status)
	}
}

// TestStartAnalysis_DisabledScanner verifies that setting
// HUSKYCI_DISABLE_GITLEAKS=true prevents gitleaks from being dispatched
// while other scanners continue to run. This pins the runtime-disabling
// contract for the isTestDisabled integration within RunAllInfo.Start.
func TestStartAnalysis_DisabledScanner(t *testing.T) {
	log.InitLog(true, "", "", "test", "test")
	t.Setenv("HUSKYCI_DISABLE_GITLEAKS", "true")

	tests := []types.SecurityTest{
		{Name: "gitleaks"},
		{Name: "gitauthors"},
	}

	runner := &mockRunner{
		genericTests: tests,
		newScanFunc: func(RID, URL, branch, name string, le map[string]bool, cf, dh string) (*SecTestScanInfo, error) {
			return &SecTestScanInfo{
				RID:              RID,
				SecurityTestName: name,
				Container: types.Container{
					CID:     "cid-" + name,
					CResult: "passed",
					CStatus: "finished",
				},
			}, nil
		},
		startScanFunc: func(scan *SecTestScanInfo) error { return nil },
	}

	results := &RunAllInfo{runner: runner}
	enryScan := SecTestScanInfo{
		RID: "disabled-rid", URL: "https://example.com/repo", Branch: "main",
	}

	if err := results.Start(enryScan); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	// Gitauthors must be present (only disabled scanner is skipped)
	found := make(map[string]bool)
	for _, c := range results.Containers {
		found[c.CID] = true
	}
	if !found["cid-gitauthors"] {
		t.Errorf("gitauthors container not dispatched — expected it to run even though gitleaks was disabled")
	}

	// Gitleaks must NOT be present (disabled via env var)
	if found["cid-gitleaks"] {
		t.Errorf("gitleaks container was dispatched but it should have been disabled by HUSKYCI_DISABLE_GITLEAKS=true")
	}

	// Exactly 1 container
	if len(results.Containers) != 1 {
		t.Fatalf("expected 1 container (gitauthors only), got %d", len(results.Containers))
	}

	if results.FinalResult != "passed" {
		t.Errorf("expected FinalResult=%q, got %q", "passed", results.FinalResult)
	}
	if results.Status != "finished" {
		t.Errorf("expected Status=%q, got %q", "finished", results.Status)
	}
}

// TestStart_PassedWhenAllScannersPass is the baseline. Multiple scanners all
// report CResult="passed" — Start() must return nil and FinalResult must be
// "passed". This test must remain green on the current code; if it ever fails
// the orchestration core has regressed.
func TestStart_PassedWhenAllScannersPass(t *testing.T) {
	tests := []types.SecurityTest{
		{Name: "gitleaks"},
		{Name: "gitauthors"},
		{Name: "wizcli_secrets"},
	}

	runner := &mockRunner{
		genericTests: tests,
		newScanFunc: func(RID, URL, branch, name string, le map[string]bool, cf, dh string) (*SecTestScanInfo, error) {
			return &SecTestScanInfo{
				RID:              RID,
				SecurityTestName: name,
				Container: types.Container{
					CID:     "cid-" + name,
					CResult: "passed",
					CStatus: "finished",
				},
			}, nil
		},
		startScanFunc: func(scan *SecTestScanInfo) error { return nil },
	}

	results := &RunAllInfo{runner: runner}
	enryScan := SecTestScanInfo{
		RID: "baseline-rid", URL: "https://example.com/repo", Branch: "main",
	}

	if err := results.Start(enryScan); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if results.FinalResult != "passed" {
		t.Errorf("expected FinalResult=%q, got %q", "passed", results.FinalResult)
	}
}

// TestStart_FailedWhenAnyScannerFails asserts the desired post-fix behavior
// for bug #8 (run.go:63-83 defer/return ordering): when any single scanner
// returns CResult="failed", the final result must be "failed".
//
// Remove the Skip after the setToAnalysis ordering bug is resolved in
// run.go:65-81. When unskipped the test should pass green; if it fails, the
// failure-propagation contract is broken and you should debug setToAnalysis
// (run.go:279) before merging.
func TestStart_FailedWhenAnyScannerFails(t *testing.T) {
	tests := []types.SecurityTest{
		{Name: "gitleaks"},
		{Name: "gitauthors"},
		{Name: "wizcli_secrets"},
	}

	results := map[string]string{
		"gitleaks":       "failed",
		"gitauthors":     "passed",
		"wizcli_secrets": "passed",
	}

	runner := &mockRunner{
		genericTests: tests,
		newScanFunc: func(RID, URL, branch, name string, le map[string]bool, cf, dh string) (*SecTestScanInfo, error) {
			return &SecTestScanInfo{
				RID:              RID,
				SecurityTestName: name,
				Container: types.Container{
					CID:     "cid-" + name,
					CResult: results[name],
					CStatus: "finished",
				},
			}, nil
		},
		startScanFunc: func(scan *SecTestScanInfo) error { return nil },
	}

	run := &RunAllInfo{runner: runner}
	enryScan := SecTestScanInfo{
		RID: "failed-rid", URL: "https://example.com/repo", Branch: "main",
	}

	if err := run.Start(enryScan); err != nil {
		t.Fatalf("Start returned unexpected error: %v", err)
	}
	if run.FinalResult != "failed" {
		t.Errorf("expected FinalResult=%q with one failed scanner, got %q", "failed", run.FinalResult)
	}
}

// TestStart_WarningWhenAllScannersWarn asserts the desired post-fix behavior
// for the warning-propagation half of bug #8: when all scanners report
// "warning" and none fail, the final result must be "warning", not "passed".
//
// Remove the Skip after the run.go:65-81 ordering issue is fixed.
func TestStart_WarningWhenAllScannersWarn(t *testing.T) {
	tests := []types.SecurityTest{
		{Name: "gitleaks"},
		{Name: "gitauthors"},
		{Name: "wizcli_secrets"},
	}

	runner := &mockRunner{
		genericTests: tests,
		newScanFunc: func(RID, URL, branch, name string, le map[string]bool, cf, dh string) (*SecTestScanInfo, error) {
			return &SecTestScanInfo{
				RID:              RID,
				SecurityTestName: name,
				Container: types.Container{
					CID:          "cid-" + name,
					CResult:      "warning",
					CStatus:      "finished",
					SecurityTest: types.SecurityTest{Name: name, Language: "Generic"},
				},
			}, nil
		},
		startScanFunc: func(scan *SecTestScanInfo) error { return nil },
	}

	run := &RunAllInfo{runner: runner}
	enryScan := SecTestScanInfo{
		RID: "warning-rid", URL: "https://example.com/repo", Branch: "main",
	}

	if err := run.Start(enryScan); err != nil {
		t.Fatalf("Start returned unexpected error: %v", err)
	}
	if run.FinalResult != "warning" {
		t.Errorf("expected FinalResult=%q with all warning scanners, got %q", "warning", run.FinalResult)
	}
}

// TestStart_PanicInScannerDoesNotCrashAPI documents gap #7. The goroutines
// spawned inside runGenericScans (run.go:100) and runLanguageScans (run.go:149)
// have no defer recover(), so a panic inside any scanner brings down the API.
// The desired post-fix behavior: panics are recovered and surfaced as errors.
//
// Remove the Skip after defer recover() is added to the g.Go bodies in
// run.go:100-124 and run.go:149-181. Until then, executing this test body
// would crash the test binary itself — hence the Skip guards the harness.
func TestStart_PanicInScannerDoesNotCrashAPI(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("panic escaped Start(): %v — expected error return, not panic", r)
		}
	}()

	tests := []types.SecurityTest{
		{Name: "gitleaks"},
		{Name: "gitauthors"},
	}

	runner := &mockRunner{
		genericTests: tests,
		newScanFunc: func(RID, URL, branch, name string, le map[string]bool, cf, dh string) (*SecTestScanInfo, error) {
			return &SecTestScanInfo{
				RID:              RID,
				SecurityTestName: name,
				Container:        types.Container{CID: "cid-" + name, CResult: "passed"},
			}, nil
		},
		startScanFunc: func(scan *SecTestScanInfo) error {
			if scan.SecurityTestName == "gitleaks" {
				panic("simulated malformed output from gitleaks parser")
			}
			return nil
		},
	}

	run := &RunAllInfo{runner: runner}
	enryScan := SecTestScanInfo{
		RID: "panic-rid", URL: "https://example.com/repo", Branch: "main",
	}

	err := run.Start(enryScan)
	if err == nil {
		t.Error("expected non-nil error after scanner panic was recovered, got nil")
	}
}

// TestStart_ConcurrencyIsLimited documents gap #3. Today errgroup.Group is
// used without SetLimit, so K languages × N scanners all run concurrently
// with no bound. The desired post-fix behavior: peak in-flight scanners
// never exceeds a small configured limit.
//
// Remove the Skip after errgroup.SetLimit (or equivalent semaphore) is added
// in run.go. Test asserts a max of 5 concurrent scanners; tune the limit to
// match whatever value the fix configures.
func TestStart_ConcurrencyIsLimited(t *testing.T) {
	const totalScanners = 20
	const maxAllowed = int32(5)

	tests := make([]types.SecurityTest, 0, totalScanners)
	for i := 0; i < totalScanners; i++ {
		tests = append(tests, types.SecurityTest{Name: "scanner_" + itoa(i)})
	}

	var inFlight atomic.Int32
	var peak atomic.Int32
	var mu sync.Mutex

	runner := &mockRunner{
		genericTests: tests,
		newScanFunc: func(RID, URL, branch, name string, le map[string]bool, cf, dh string) (*SecTestScanInfo, error) {
			return &SecTestScanInfo{
				RID:              RID,
				SecurityTestName: name,
				Container:        types.Container{CID: "cid-" + name, CResult: "passed"},
			}, nil
		},
		startScanFunc: func(scan *SecTestScanInfo) error {
			current := inFlight.Add(1)
			mu.Lock()
			if current > peak.Load() {
				peak.Store(current)
			}
			mu.Unlock()
			time.Sleep(50 * time.Millisecond)
			inFlight.Add(-1)
			return nil
		},
	}

	run := &RunAllInfo{runner: runner}
	enryScan := SecTestScanInfo{
		RID: "concurrency-rid", URL: "https://example.com/repo", Branch: "main",
	}

	if err := run.Start(enryScan); err != nil {
		t.Fatalf("Start returned unexpected error: %v", err)
	}
	if got := peak.Load(); got > maxAllowed {
		t.Errorf("peak concurrent scanners = %d, want <= %d (concurrency limit not enforced)", got, maxAllowed)
	}
	if len(run.Containers) != totalScanners {
		t.Errorf("expected %d containers to complete, got %d", totalScanners, len(run.Containers))
	}
}

// itoa avoids importing strconv just to label test scanners.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
