# Fix 2: Mutex Data Race — Implementation Plan (TDD)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Eliminate data races on shared `RunAllInfo` fields by adding `sync.Mutex`.

**Architecture:** Add `sync.Mutex` to `RunAllInfo`, wrap concurrent mutations (Container append, CommitAuthors, setVulns). Lock scope is minimal — I/O stays outside. This branch is based on Fix 1 (errgroup already applied).

**Tech Stack:** Go 1.20, sync.Mutex (stdlib)

**Depends on:** Fix 1 branch `fix/errgroup-channel-race` must be complete first.

---

### Task 1: Create worktree from errgroup branch

- [ ] **Step 1: Create branch and worktree**

```bash
cd ~/Gits/huskyci-api
git branch fix/mutex-data-race fix/errgroup-channel-race
git worktree add ../huskyci-api-mutex fix/mutex-data-race
```

- [ ] **Step 2: Verify base compiles**

```bash
cd ~/Gits/huskyci-api-mutex/api
go build ./...
```

Expected: SUCCESS.

- [ ] **Step 3: Verify existing TDD tests pass**

```bash
cd ~/Gits/huskyci-api-mutex/api
go test -v -run "TestStart_First|TestStart_Concurrent|TestStart_All" ./securitytest/
```

Expected: ALL PASS (errgroup tests from Fix 1).

---

### Task 2: RED — Write failing data race tests

- [ ] **Step 1: Write concurrent append test**

Add to `api/securitytest/run_test.go` — ensure imports include `"fmt"`, `"sync"`:

```go
func TestRunAllInfoConcurrentAppend(t *testing.T) {
	// Bug 2: concurrent append to results.Containers is a data race.
	// Under -race flag this should report DATA RACE until mutex is added.
	results := &RunAllInfo{}

	const concurrency = 50
	var wg sync.WaitGroup
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer wg.Done()
			results.Containers = append(results.Containers, types.Container{
				CID:     fmt.Sprintf("container-%d", idx),
				CResult: "passed",
			})
		}(i)
	}

	wg.Wait()

	if len(results.Containers) != concurrency {
		t.Errorf("expected %d containers, got %d", concurrency, len(results.Containers))
	}
}
```

- [ ] **Step 2: Write concurrent setVulns test**

```go
func TestRunAllInfoConcurrentSetVulns(t *testing.T) {
	// Bug 2: concurrent setVulns calls race on HuskyCIResults fields.
	results := &RunAllInfo{}

	const concurrency = 20
	var wg sync.WaitGroup
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer wg.Done()
			scanInfo := SecTestScanInfo{
				SecurityTestName: bandit,
				Vulnerabilities: types.HuskyCISecurityTestOutput{
					HighVulns: []types.HuskyCIVulnerability{
						{Code: fmt.Sprintf("vuln-%d", idx)},
					},
				},
			}
			results.setVulns(scanInfo)
		}(i)
	}

	wg.Wait()

	highCount := len(results.HuskyCIResults.PythonResults.HuskyCIBanditOutput.HighVulns)
	if highCount != concurrency {
		t.Errorf("expected %d high vulns, got %d", concurrency, highCount)
	}
}
```

- [ ] **Step 3: Run with race detector — verify DATA RACE detected**

```bash
cd ~/Gits/huskyci-api-mutex/api
go test -race -v -run "TestRunAllInfoConcurrent" ./securitytest/ 2>&1 | head -30
```

Expected: `DATA RACE` reported by race detector, or wrong container count (append race loses entries).

- [ ] **Step 4: Commit failing race tests**

```bash
cd ~/Gits/huskyci-api-mutex
git add api/securitytest/run_test.go
git commit -m "test(securitytest): add failing data race tests for RunAllInfo

TestRunAllInfoConcurrentAppend and TestRunAllInfoConcurrentSetVulns
expose Bug 2 under -race flag. Currently FAIL."
```

---

### Task 3: GREEN — Add sync.Mutex and wrap mutations

- [ ] **Step 1: Add sync import and mutex field**

In `api/securitytest/run.go`, update imports — add `"sync"`:

```go
import (
	"context"
	"os"
	"strings"
	"sync"

	apiContext "github.com/githubanotaai/huskyci-api/api/context"
	"github.com/githubanotaai/huskyci-api/api/log"
	"github.com/githubanotaai/huskyci-api/api/types"
	"golang.org/x/sync/errgroup"
)
```

Update `RunAllInfo` struct — add mutex field:

```go
type RunAllInfo struct {
	mu             sync.Mutex `json:"-" bson:"-"`
	runner         scanRunner `json:"-" bson:"-"`
	RID            string
	Status         string
	Containers     []types.Container
	CommitAuthors  []string
	Codes          []types.Code
	FinalResult    string
	ErrorFound     error
	HuskyCIResults types.HuskyCIResults
}
```

- [ ] **Step 2: Wrap mutations in runGenericScans goroutine**

In `runGenericScans`, replace the result mutation block with:

```go
			results.mu.Lock()
			results.Containers = append(results.Containers, scan.Container)
			switch genericTests[i].Name {
			case "gitauthors":
				results.CommitAuthors = scan.CommitAuthors.Authors
			case "gitleaks", "wizcli":
				results.setVulns(*scan)
			}
			results.mu.Unlock()
			return nil
```

- [ ] **Step 3: Wrap mutations in runLanguageScans goroutine**

Error path:

```go
			if err := runner.startScan(scan); err != nil {
				results.mu.Lock()
				results.Containers = append(results.Containers, scan.Container)
				results.mu.Unlock()
				return err
			}
```

Success path:

```go
			results.mu.Lock()
			results.Containers = append(results.Containers, scan.Container)
			results.setVulns(*scan)
			results.mu.Unlock()
			return nil
```

- [ ] **Step 4: Run race tests — verify they PASS**

```bash
cd ~/Gits/huskyci-api-mutex/api
go test -race -v -run "TestRunAllInfoConcurrent" ./securitytest/
```

Expected: ALL PASS — no DATA RACE warnings, correct container/vuln counts.

- [ ] **Step 5: Run ALL tests — no regression**

```bash
cd ~/Gits/huskyci-api-mutex/api
go test -race -v ./securitytest/
```

Expected: ALL PASS — errgroup tests + race tests + old isTestDisabled.

- [ ] **Step 6: Commit**

```bash
cd ~/Gits/huskyci-api-mutex
git add api/securitytest/run.go
git commit -m "fix(securitytest): add sync.Mutex to RunAllInfo for data race protection

Mutex wraps Container append, CommitAuthors assignment, and setVulns.
Lock scope minimal — I/O stays outside. json/bson tags prevent serialization."
```

---

### Task 4: Final verification and push

- [ ] **Step 1: Run full suite with race detector**

```bash
cd ~/Gits/huskyci-api-mutex/api
go test -race ./...
```

- [ ] **Step 2: Verify all mutation sites guarded**

```bash
cd ~/Gits/huskyci-api-mutex
grep -n "results.Containers = append\|results.CommitAuthors\|results.setVulns" api/securitytest/run.go | grep -v "mu.Lock\|mu.Unlock"
```

Expected: No output — all sites have locks.

- [ ] **Step 3: go vet**

```bash
cd ~/Gits/huskyci-api-mutex/api
go vet ./...
```

- [ ] **Step 4: Push**

```bash
cd ~/Gits/huskyci-api-mutex
git push -u origin fix/mutex-data-race
```

---

## Self-Review

**TDD cycle:**
- Task 2: RED (race tests fail under `-race`)
- Task 3: GREEN (mutex makes all tests pass)
- Task 4: commit + verify

**Scope:** Only Bug 2 (data race). Bug 1 already fixed by Fix 1 base branch.

**Placeholder scan:** No TBD/TODO. All code inline.

**Type consistency:**
- `sync.Mutex` with `json:"-" bson:"-"` — `registerFinishedAnalysis` uses explicit `bson.M`
- Lock/unlock pairs symmetric — each Lock has exactly one Unlock on same code path
- `setVulns(*scan)` called inside lock — scan is already fully populated before lock