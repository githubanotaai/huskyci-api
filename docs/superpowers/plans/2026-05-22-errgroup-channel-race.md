# Fix 1: errgroup Channel Race — Implementation Plan (TDD)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Eliminate `panic: send on closed channel` by replacing manual errChan/syncChan/waitChan/wg with errgroup.

**Architecture:** Introduce `scanRunner` interface to mock DB + K8s calls. Refactor Start, runGenericScans, runLanguageScans to use errgroup.WithContext. This plan does NOT add mutex — that's Fix 2.

**Tech Stack:** Go 1.20, golang.org/x/sync v0.8.0

---

### Task 1: Create worktree + promote dependency

- [ ] **Step 1: Create worktree**

```bash
cd ~/Gits/huskyci-api
git worktree add ../huskyci-api-errgroup fix/errgroup-channel-race 2>/dev/null || {
  git branch fix/errgroup-channel-race
  git worktree add ../huskyci-api-errgroup fix/errgroup-channel-race
}
```

- [ ] **Step 2: Promote dependency**

```bash
cd ~/Gits/huskyci-api-errgroup/api
go get golang.org/x/sync@v0.8.0
go mod tidy
```

- [ ] **Step 3: Commit**

```bash
cd ~/Gits/huskyci-api-errgroup
git add api/go.mod api/go.sum
git commit -m "chore: promote golang.org/x/sync to direct dependency for errgroup refactor"
```

---

### Task 2: RED — Write failing tests for errgroup behavior

- [ ] **Step 1: Create scanRunner interface**

Create `api/securitytest/runner.go`:

```go
package securitytest

import "github.com/githubanotaai/huskyci-api/api/types"

// scanRunner abstracts scan lifecycle so tests can mock
// DB queries and scan execution without MongoDB or K8s.
type scanRunner interface {
	listGenericTests() ([]types.SecurityTest, error)
	listLanguageTests(language string) ([]types.SecurityTest, error)
	newScan(RID, URL, branch, securityTestName string, languageExclusions map[string]bool, dockerHost string) (*SecTestScanInfo, error)
	startScan(scan *SecTestScanInfo) error
}

// realRunner delegates to actual SecTestScanInfo + DB methods.
type realRunner struct{}

func (realRunner) listGenericTests() ([]types.SecurityTest, error) {
	return getAllDefaultSecurityTests("Generic", "")
}

func (realRunner) listLanguageTests(language string) ([]types.SecurityTest, error) {
	return getAllDefaultSecurityTests("Language", language)
}

func (realRunner) newScan(RID, URL, branch, securityTestName string, languageExclusions map[string]bool, dockerHost string) (*SecTestScanInfo, error) {
	scan := &SecTestScanInfo{}
	return scan, scan.New(RID, URL, branch, securityTestName, languageExclusions, dockerHost)
}

func (realRunner) startScan(scan *SecTestScanInfo) error {
	return scan.Start()
}

// mockRunner returns preconfigured results for testing.
type mockRunner struct {
	genericTests   []types.SecurityTest
	languageTests   []types.SecurityTest
	newScanFunc    func(RID, URL, branch, securityTestName string, languageExclusions map[string]bool, dockerHost string) (*SecTestScanInfo, error)
	startScanFunc  func(scan *SecTestScanInfo) error
}

func (m *mockRunner) listGenericTests() ([]types.SecurityTest, error) {
	return m.genericTests, nil
}

func (m *mockRunner) listLanguageTests(language string) ([]types.SecurityTest, error) {
	return m.languageTests, nil
}

func (m *mockRunner) newScan(RID, URL, branch, securityTestName string, languageExclusions map[string]bool, dockerHost string) (*SecTestScanInfo, error) {
	if m.newScanFunc != nil {
		return m.newScanFunc(RID, URL, branch, securityTestName, languageExclusions, dockerHost)
	}
	return &SecTestScanInfo{}, nil
}

func (m *mockRunner) startScan(scan *SecTestScanInfo) error {
	if m.startScanFunc != nil {
		return m.startScanFunc(scan)
	}
	return nil
}
```

- [ ] **Step 2: Add runner field to RunAllInfo (so tests can inject mocks)**

In `api/securitytest/run.go`, add to imports: `"context"` and remove `"sync"`. Add to `RunAllInfo`:

```go
type RunAllInfo struct {
	runner         scanRunner `json:"-" bson:"-"`
	RID            string
	// ... rest unchanged ...
}
```

Add helper method:

```go
func (results *RunAllInfo) getRunner() scanRunner {
	if results.runner != nil {
		return results.runner
	}
	return realRunner{}
}
```

- [ ] **Step 3: Write the failing tests**

Add to `api/securitytest/run_test.go` — add `"fmt"`, `"sync/atomic"` to imports:

```go
func TestStart_FirstErrorCancelsRemaining(t *testing.T) {
	// Bug 1: under old errChan/syncChan pattern, concurrent error sends
	// cause panic. Under errgroup, first error returns cleanly.
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
	// Stress test: all scans error simultaneously — no panic allowed.
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

	// The key assertion: no panic
	err := results.Start(enryScan)
	if err == nil {
		t.Fatal("expected error with all scans failing")
	}
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
```

- [ ] **Step 4: Run tests — verify they FAIL**

```bash
cd ~/Gits/huskyci-api-errgroup/api
go test -v -run "TestStart_First|TestStart_Concurrent|TestStart_All" ./securitytest/ 2>&1 | tail -20
```

Expected: FAIL — Start() still uses old channel pattern, not errgroup.

- [ ] **Step 5: Commit failing tests**

```bash
cd ~/Gits/huskyci-api-errgroup
git add api/securitytest/runner.go api/securitytest/run.go api/securitytest/run_test.go
git commit -m "test(securitytest): add TDD tests for errgroup error propagation

Tests verify: first error cancels remaining, concurrent errors
don't panic, all-pass returns nil. These currently FAIL."
```

---

### Task 3: GREEN — Refactor to errgroup + scanRunner

- [ ] **Step 1: Replace imports in run.go**

```go
import (
	"context"
	"os"
	"strings"

	apiContext "github.com/githubanotaai/huskyci-api/api/context"
	"github.com/githubanotaai/huskyci-api/api/log"
	"github.com/githubanotaai/huskyci-api/api/types"
	"golang.org/x/sync/errgroup"
)
```

- [ ] **Step 2: Replace Start()**

```go
func (results *RunAllInfo) Start(enryScan SecTestScanInfo) error {
	results.Codes = enryScan.Codes
	defer results.setToAnalysis()

	g, ctx := errgroup.WithContext(context.Background())

	g.Go(func() error {
		return results.runGenericScans(ctx, enryScan)
	})
	g.Go(func() error {
		return results.runLanguageScans(ctx, enryScan)
	})

	if err := g.Wait(); err != nil {
		results.ErrorFound = err
		return err
	}

	results.setFinalResult()
	return nil
}
```

- [ ] **Step 3: Replace runGenericScans()**

```go
func (results *RunAllInfo) runGenericScans(ctx context.Context, enryScan SecTestScanInfo) error {
	g, ctx := errgroup.WithContext(ctx)
	runner := results.getRunner()

	genericTests, err := runner.listGenericTests()
	if err != nil {
		return err
	}

	for i := range genericTests {
		if isTestDisabled(genericTests[i].Name) {
			log.Info("runGenericScans", "SECURITYTEST", 0, "Skipping disabled test: "+genericTests[i].Name)
			continue
		}
		g.Go(func() error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			scan, err := runner.newScan(enryScan.RID, enryScan.URL, enryScan.Branch, genericTests[i].Name, nil, enryScan.DockerHost)
			if err != nil {
				return err
			}
			if err := runner.startScan(scan); err != nil {
				return err
			}
			results.Containers = append(results.Containers, scan.Container)
			switch genericTests[i].Name {
			case "gitauthors":
				results.CommitAuthors = scan.CommitAuthors.Authors
			case "gitleaks", "wizcli":
				results.setVulns(*scan)
			}
			return nil
		})
	}

	return g.Wait()
}
```

- [ ] **Step 4: Replace runLanguageScans()**

```go
func (results *RunAllInfo) runLanguageScans(ctx context.Context, enryScan SecTestScanInfo) error {
	g, ctx := errgroup.WithContext(ctx)
	runner := results.getRunner()

	languageTests := []types.SecurityTest{}
	for _, code := range enryScan.Codes {
		codeTests, err := runner.listLanguageTests(code.Language)
		if err != nil {
			return err
		}
		languageTests = append(languageTests, codeTests...)
	}

	for i := range languageTests {
		if isTestDisabled(languageTests[i].Name) {
			log.Info("runLanguageScans", "SECURITYTEST", 0, "Skipping disabled test: "+languageTests[i].Name)
			continue
		}
		g.Go(func() error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			scan, err := runner.newScan(enryScan.RID, enryScan.URL, enryScan.Branch, languageTests[i].Name, nil, enryScan.DockerHost)
			if err != nil {
				return err
			}
			if err := runner.startScan(scan); err != nil {
				results.Containers = append(results.Containers, scan.Container)
				return err
			}
			results.Containers = append(results.Containers, scan.Container)
			results.setVulns(*scan)
			return nil
		})
	}

	return g.Wait()
}
```

- [ ] **Step 5: Run TDD tests — verify they PASS**

```bash
cd ~/Gits/huskyci-api-errgroup/api
go test -v -run "TestStart_First|TestStart_Concurrent|TestStart_All" ./securitytest/
```

Expected: ALL PASS.

- [ ] **Step 6: Run existing tests — no regression**

```bash
cd ~/Gits/huskyci-api-errgroup/api
go test -v ./securitytest/
```

Expected: ALL PASS.

- [ ] **Step 7: Commit**

```bash
cd ~/Gits/huskyci-api-errgroup
git add api/securitytest/run.go api/securitytest/runner.go
git commit -m "refactor(securitytest): replace channel pattern with errgroup + scanRunner

Start(), runGenericScans(), runLanguageScans() use errgroup.WithContext.
scanRunner interface enables mock injection for tests.
Fixes enryScan.LanguageExclusions shared mutation.
Eliminates send-on-closed-channel panic."
```

---

### Task 4: Final verification and push

- [ ] **Step 1: Run full suite with race detector**

```bash
cd ~/Gits/huskyci-api-errgroup/api
go test -race ./...
```

Expected: PASS (note: data race on Container append still exists — that's Bug 2, fixed in Plan 2).

- [ ] **Step 2: Verify no old channel patterns**

```bash
cd ~/Gits/huskyci-api-errgroup
grep -n "syncChan\|errChan\|waitChan\|sync\.WaitGroup" api/securitytest/run.go
```

Expected: No matches.

- [ ] **Step 3: go vet**

```bash
cd ~/Gits/huskyci-api-errgroup/api
go vet ./...
```

- [ ] **Step 4: Push**

```bash
cd ~/Gits/huskyci-api-errgroup
git push -u origin fix/errgroup-channel-race
```

---

## Self-Review

**TDD cycle:**
- Task 2: RED (tests fail — old channel pattern, no scanRunner)
- Task 3: GREEN (errgroup + scanRunner makes all 3 tests pass)
- Task 4: commit + verify

**Scope:** Only Bug 1 (send-on-closed-channel). Bug 2 (data race) intentionally left for Plan 2.

**Placeholder scan:** No TBD/TODO. All code inline.

**Type consistency:**
- `scanRunner.listGenericTests()` → `[]types.SecurityTest, error` matches `getAllDefaultSecurityTests`
- `runner.newScan()` returns `*SecTestScanInfo` — callers use `*scan` / `*scan` in setVulns
- `context.Context` threaded through runGenericScans, runLanguageScans