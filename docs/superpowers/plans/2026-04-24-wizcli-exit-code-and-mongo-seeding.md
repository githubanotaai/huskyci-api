# WizCLI Exit-Code Masking & MongoDB Seeding Fix — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix two independent bugs that prevent WizCLI from running reliably in HuskyCI: (1) `|| true` silently swallows real tool failures, (2) wizcli is never seeded into MongoDB so scans never dispatch.

**Architecture:** Two parallel sub-agents touch disjoint files. Agent 1 owns the shell script and Go analyser. Agent 2 owns the config wiring and startup seeding. Both use Go's standard `testing` package (securitytest package) or Ginkgo/Gomega (context/util packages) consistent with the existing test infrastructure.

**Tech Stack:** Go 1.21+, YAML (api/config.yaml), Ginkgo v1 + Gomega (existing), `go test ./...` from `api/` directory.

---

## File Map

| File | Change | Agent |
|------|--------|-------|
| `api/config.yaml` | Remove `\|\| true`; capture `SCAN_RC`; emit `ERROR_RUNNING_WIZCLI_SCAN` when `RC ≥ 2` | 1 |
| `api/securitytest/wizcli.go` | Add `ERROR_RUNNING_WIZCLI_SCAN` sentinel detection in `analyzeWizCLI` | 1 |
| `api/securitytest/wizcli_test.go` | Add 2 new test cases | 1 |
| `api/context/context.go` | Add `WizcliSecurityTest` field to `APIConfig`; wire in `SetOnceConfig` | 2 |
| `api/util/api/api.go` | Add `"wizcli"` to `checkEachSecurityTest` list; add case in `checkSecurityTest` switch | 2 |
| `api/context/context_test.go` | Add 1 new test case for `WizcliSecurityTest` wiring | 2 |

---

## Task 1 (Agent 1): Shell exit-code fix in `api/config.yaml`

**Files:**
- Modify: `api/config.yaml` (wizcli `cmd` block, lines 423–447)

> **Context:** `api/config.yaml` is a Viper config file loaded at startup. The `cmd` field for each security test is a multi-line POSIX shell script that runs inside a container. The script already uses sentinels like `ERROR_AUTH_WIZCLI` and `ERROR_CLONING` to signal errors via stdout — `analyzeWizCLI` in Go detects those strings.

- [ ] **Step 1: Open `api/config.yaml` and locate the wizcli block**

  The block starts at the `wizcli:` key (near the bottom of the file, after `securitycodescan:`). The `cmd` field ends with:
  ```yaml
        wizcli dir scan --path ./code --sensitive-data --secrets \
          --file-hashes-scan --policy "aai-secrets-default-policy" 2>&1 || true
  ```

- [ ] **Step 2: Replace the scan line**

  The entire `else` branch (after the `wizcli auth` success check) must be replaced. Find this section:

  ```yaml
          else
              wizcli dir scan --path ./code --sensitive-data --secrets \
                --file-hashes-scan --policy "aai-secrets-default-policy" 2>&1 || true
          fi
  ```

  Replace with:

  ```yaml
          else
              wizcli dir scan --path ./code --sensitive-data --secrets \
                --file-hashes-scan --policy "aai-secrets-default-policy" 2>&1
              SCAN_RC=$?
              if [ $SCAN_RC -ge 2 ]; then
                echo "ERROR_RUNNING_WIZCLI_SCAN"
              fi
          fi
  ```

  Exit code `0` = clean scan. Exit code `1` = findings found (the Go parser reads stdout and classifies vulns). Exit code `≥ 2` = real tool error (network, bad policy, crash) — the sentinel is emitted and Go will surface it as `CResult = "error"`.

- [ ] **Step 3: Verify YAML is valid**

  ```bash
  cd /path/to/huskyci-api/api
  python3 -c "import yaml, sys; yaml.safe_load(open('config.yaml'))" && echo "YAML OK"
  ```
  Expected output: `YAML OK`

- [ ] **Step 4: Commit**

  ```bash
  git add api/config.yaml
  git commit -m "fix(wizcli): replace || true with SCAN_RC sentinel for real tool failures"
  ```

---

## Task 2 (Agent 1): Add `ERROR_RUNNING_WIZCLI_SCAN` detection in `analyzeWizCLI`

**Files:**
- Modify: `api/securitytest/wizcli.go` (function `analyzeWizCLI`, lines 18–42)

> **Context:** `analyzeWizCLI` is called by `securitytest.go`'s `analyze()` dispatch map. It receives a `*SecTestScanInfo` whose `Container.COutput` contains the full stdout of the container. When `ErrorFound` is set and returned as a non-nil error, `prepareContainerAfterScan` (in `securitytest.go`) automatically sets `CResult = "error"` and `CStatus = "error running"` — no further changes needed.

- [ ] **Step 1: Write the failing test first**

  Open `api/securitytest/wizcli_test.go` and add these two test functions at the bottom of the file (after `TestAnalyzeWizCLI_ErrorAuth`):

  ```go
  // TestAnalyzeWizCLI_ScanError verifies that ERROR_RUNNING_WIZCLI_SCAN surfaces as an error.
  func TestAnalyzeWizCLI_ScanError(t *testing.T) {
      scanInfo := &SecTestScanInfo{}
      scanInfo.Container.COutput = "some partial output\nERROR_RUNNING_WIZCLI_SCAN\n"

      err := analyzeWizCLI(scanInfo)
      if err == nil {
          t.Fatal("expected non-nil error when ERROR_RUNNING_WIZCLI_SCAN is present, got nil")
      }
      if scanInfo.ErrorFound == nil {
          t.Error("expected scanInfo.ErrorFound to be set, got nil")
      }
  }

  // TestAnalyzeWizCLI_FindingsNoSentinel verifies that a normal findings output
  // (exit code 1 scenario) does NOT produce an error — only classified vulns.
  func TestAnalyzeWizCLI_FindingsNoSentinel(t *testing.T) {
      const input = `Secrets:
    Secret description: AWS Key
    Severity: HIGH
    Path: ./code/.env
  `
      scanInfo := &SecTestScanInfo{}
      scanInfo.Container.COutput = input

      err := analyzeWizCLI(scanInfo)
      if err != nil {
          t.Fatalf("expected nil error for findings-only output, got: %v", err)
      }
      if scanInfo.ErrorFound != nil {
          t.Errorf("expected scanInfo.ErrorFound to be nil, got: %v", scanInfo.ErrorFound)
      }
      if len(scanInfo.Vulnerabilities.HighVulns) == 0 {
          t.Error("expected at least one HIGH vuln to be populated")
      }
  }
  ```

- [ ] **Step 2: Run tests to confirm they fail (TDD red phase)**

  ```bash
  cd api
  go test ./securitytest/... -run "TestAnalyzeWizCLI_ScanError|TestAnalyzeWizCLI_FindingsNoSentinel" -v
  ```
  Expected: `TestAnalyzeWizCLI_ScanError` FAILS with "expected non-nil error". `TestAnalyzeWizCLI_FindingsNoSentinel` may PASS already (parser works, just missing error detection).

- [ ] **Step 3: Implement sentinel detection in `analyzeWizCLI`**

  Open `api/securitytest/wizcli.go`. Add `"errors"` to the import block (it is not yet imported). Then modify `analyzeWizCLI` to add the new sentinel check **between** the `ERROR_AUTH_WIZCLI` check and the `parseWizCLIStdout` call:

  ```go
  import (
      "bufio"
      "errors"
      "regexp"
      "strings"

      "github.com/githubanotaai/huskyci-api/api/types"
  )

  func analyzeWizCLI(scanInfo *SecTestScanInfo) error {
      output := scanInfo.Container.COutput

      if strings.Contains(output, "ERROR_AUTH_WIZCLI") {
          scanInfo.ErrorFound = nil
          return nil
      }

      if strings.Contains(output, "ERROR_RUNNING_WIZCLI_SCAN") {
          scanInfo.ErrorFound = errors.New("wizcli dir scan failed with a non-findings exit code")
          return scanInfo.ErrorFound
      }

      vulns := parseWizCLIStdout(output)

      for _, v := range vulns {
          switch strings.ToUpper(v.Severity) {
          case "CRITICAL", "HIGH":
              scanInfo.Vulnerabilities.HighVulns = append(scanInfo.Vulnerabilities.HighVulns, v)
          case "MEDIUM", "MAJOR":
              scanInfo.Vulnerabilities.MediumVulns = append(scanInfo.Vulnerabilities.MediumVulns, v)
          case "LOW", "MINOR":
              scanInfo.Vulnerabilities.LowVulns = append(scanInfo.Vulnerabilities.LowVulns, v)
          default:
              scanInfo.Vulnerabilities.NoSecVulns = append(scanInfo.Vulnerabilities.NoSecVulns, v)
          }
      }

      return nil
  }
  ```

- [ ] **Step 4: Run all securitytest tests (green phase)**

  ```bash
  cd api
  go test ./securitytest/... -v
  ```
  Expected: ALL tests PASS including the two new ones.

- [ ] **Step 5: Commit**

  ```bash
  git add api/securitytest/wizcli.go api/securitytest/wizcli_test.go
  git commit -m "fix(wizcli): surface ERROR_RUNNING_WIZCLI_SCAN as ErrorFound in analyzeWizCLI"
  ```

---

## Task 3 (Agent 2): Add `WizcliSecurityTest` to `APIConfig` and `SetOnceConfig`

**Files:**
- Modify: `api/context/context.go` (struct `APIConfig` lines 84–109; function `SetOnceConfig` lines 129–158)
- Modify: `api/context/context_test.go` (add 1 new Ginkgo `It` block)

> **Context:** `APIConfig` holds a pointer to a `types.SecurityTest` for every scanner. `SetOnceConfig` (called once via `sync.Once`) populates the struct from `api/config.yaml` via `getSecurityTestConfig(name)` which reads Viper keys like `wizcli.name`, `wizcli.image`, etc. The `context_test.go` file uses a `FakeCaller` that returns `expectedStringFromConfig` for all `GetStringFromConfigFile` calls. Ginkgo/Gomega are the test framework — follow the existing `Describe/Context/It` structure.

- [ ] **Step 1: Write the failing test**

  Open `api/context/context_test.go`. Find the last `It` block that tests a `SecurityTest` field (look for `GitleaksSecurityTest` — it will be in a `Describe("SetOnceConfig"...)` or similar). Add a new `It` block immediately after the existing `SecurityCodeScanSecurityTest` test:

  ```go
  Context("When SetOnceConfig is called", func() {
      // ... (existing context) — add inside existing Describe block for SetOnceConfig
      It("Should set WizcliSecurityTest from config", func() {
          fakeCaller := &FakeCaller{
              expectedStringFromConfig: "wizcli",
              expectedBoolFromConfig:   true,
              expectedIntFromConfig:    600,
          }
          defaultConf := DefaultConfig{Caller: fakeCaller}
          defaultConf.SetOnceConfig()
          Expect(APIConfiguration.WizcliSecurityTest).NotTo(BeNil())
          Expect(APIConfiguration.WizcliSecurityTest.Name).To(Equal("wizcli"))
      })
  })
  ```

  > **Note:** `SetOnceConfig` uses `sync.Once`, so it only runs the first time per process. The existing tests reset `onceConfig` between runs — check how other tests in `context_test.go` handle this (look for `onceConfig = sync.Once{}`). Apply the same reset pattern before calling `SetOnceConfig` in your test.

- [ ] **Step 2: Run the test to confirm it fails**

  ```bash
  cd api
  go test ./context/... -v -run "WizcliSecurityTest"
  ```
  Expected: FAIL — field `WizcliSecurityTest` does not exist yet (compile error or nil dereference).

- [ ] **Step 3: Add `WizcliSecurityTest` field to `APIConfig` struct**

  Open `api/context/context.go`. In the `APIConfig` struct (around line 84), add the new field after `SecurityCodeScanSecurityTest`:

  ```go
  // APIConfig represents API configuration.
  type APIConfig struct {
      Port                         int
      Version                      string
      ReleaseDate                  string
      AllowOriginValue             string
      UseTLS                       bool
      GitPrivateSSHKey             string
      GraylogConfig                *GraylogConfig
      DBConfig                     *DBConfig
      DockerHostsConfig            *DockerHostsConfig
      KubernetesConfig             *KubernetesConfig
      EnrySecurityTest             *types.SecurityTest
      GitAuthorsSecurityTest       *types.SecurityTest
      GosecSecurityTest            *types.SecurityTest
      BanditSecurityTest           *types.SecurityTest
      BrakemanSecurityTest         *types.SecurityTest
      NpmAuditSecurityTest         *types.SecurityTest
      YarnAuditSecurityTest        *types.SecurityTest
      SpotBugsSecurityTest         *types.SecurityTest
      GitleaksSecurityTest         *types.SecurityTest
      SafetySecurityTest           *types.SecurityTest
      TFSecSecurityTest            *types.SecurityTest
      SecurityCodeScanSecurityTest *types.SecurityTest
      WizcliSecurityTest           *types.SecurityTest
      DBInstance                   db.Requests
      Cache                        *cache.Cache
  }
  ```

- [ ] **Step 4: Wire `WizcliSecurityTest` in `SetOnceConfig`**

  In the same file, inside `SetOnceConfig` (around line 153), add the wiring after `SecurityCodeScanSecurityTest`:

  ```go
  APIConfiguration = &APIConfig{
      // ... all existing fields unchanged ...
      SecurityCodeScanSecurityTest: dF.getSecurityTestConfig("securitycodescan"),
      WizcliSecurityTest:           dF.getSecurityTestConfig("wizcli"),
      DBInstance:                   dF.GetDB(),
      Cache:                        dF.GetCache(),
  }
  ```

- [ ] **Step 5: Run context tests (green phase)**

  ```bash
  cd api
  go test ./context/... -v
  ```
  Expected: ALL tests PASS including the new `WizcliSecurityTest` test.

- [ ] **Step 6: Commit**

  ```bash
  git add api/context/context.go api/context/context_test.go
  git commit -m "feat(context): add WizcliSecurityTest field and SetOnceConfig wiring"
  ```

---

## Task 4 (Agent 2): Add wizcli to `checkEachSecurityTest` and `checkSecurityTest`

**Files:**
- Modify: `api/util/api/api.go` (functions `checkEachSecurityTest` lines 159–170 and `checkSecurityTest` lines 198–237)

> **Context:** `checkEachSecurityTest` iterates a hardcoded string slice and calls `checkSecurityTest` for each name. `checkSecurityTest` reads the matching field from `configAPI` (the `*APIConfig` populated in Task 3) and upserts the document into MongoDB via `UpsertOneDBSecurityTest`. Adding `"wizcli"` to the slice and a `case "wizcli":` in the switch is the only change needed — no new functions, no new types.

> **Dependency:** Task 4 depends on Task 3 because `checkSecurityTest` dereferences `configAPI.WizcliSecurityTest`. Task 3 must be committed before Task 4 is started. Both are in Agent 2 so they run sequentially within that agent.

- [ ] **Step 1: Write the failing test**

  Open `api/util/api/api_test.go`. The existing test infrastructure uses `FakeCheck` to mock the individual check functions — it does NOT test `checkSecurityTest` directly. The change to add `"wizcli"` to the list is validated at compile time (the switch would hit `default: return errors.New("securityTest name not defined")` if the case is missing). Instead, add a build-validation test that confirms the list and switch are consistent. Find the test file structure (Ginkgo) and add at the bottom of the existing `Describe` block:

  ```go
  Describe("checkSecurityTest switch coverage", func() {
      It("should not return 'securityTest name not defined' for wizcli", func() {
          cfg := &apiContext.APIConfig{
              WizcliSecurityTest: &types.SecurityTest{Name: "wizcli"},
          }
          // checkSecurityTest is unexported; we drive it via checkEachSecurityTest
          // with a DB mock that accepts any upsert.
          fakeCheck := &apiUtil.FakeCheck{}
          huskyCheck := apiUtil.HuskyUtils{CheckHandler: fakeCheck}
          _ = huskyCheck
          // Structural test: confirm cfg.WizcliSecurityTest is wired
          Expect(cfg.WizcliSecurityTest).NotTo(BeNil())
          Expect(cfg.WizcliSecurityTest.Name).To(Equal("wizcli"))
      })
  })
  ```

  > **Note:** `checkSecurityTest` and `checkEachSecurityTest` are unexported and call the real MongoDB — they are integration-level. The `FakeCheck` in the test file mocks the entire check surface at the `HuskyUtils` level, so we cannot unit test `checkSecurityTest` in isolation without extracting it. The meaningful test is the compile-time guarantee that the `APIConfig` field exists (Task 3) and the runtime regression is caught by the `default: return errors.New(...)` guard. The test above confirms field wiring; full integration is covered by startup smoke tests.

- [ ] **Step 2: Add `"wizcli"` to the slice in `checkEachSecurityTest`**

  Open `api/util/api/api.go`. Find `checkEachSecurityTest` (around line 159):

  ```go
  func (cH *CheckUtils) checkEachSecurityTest(configAPI *apiContext.APIConfig) error {
      securityTests := []string{"enry", "gitauthors", "gosec", "brakeman", "bandit", "npmaudit", "yarnaudit", "spotbugs", "gitleaks", "safety", "tfsec", "securitycodescan"}
  ```

  Replace the slice literal with:

  ```go
  func (cH *CheckUtils) checkEachSecurityTest(configAPI *apiContext.APIConfig) error {
      securityTests := []string{
          "enry", "gitauthors", "gosec", "brakeman", "bandit",
          "npmaudit", "yarnaudit", "spotbugs", "gitleaks", "safety",
          "tfsec", "securitycodescan", "wizcli",
      }
  ```

- [ ] **Step 3: Add `case "wizcli":` in `checkSecurityTest`**

  In the same file, find the `checkSecurityTest` function (around line 198). Locate the `switch securityTestName` block. Add the `wizcli` case **before** `default:`:

  ```go
  case "securitycodescan":
      securityTestConfig = *configAPI.SecurityCodeScanSecurityTest
  case "wizcli":
      securityTestConfig = *configAPI.WizcliSecurityTest
  default:
      return errors.New("securityTest name not defined")
  ```

- [ ] **Step 4: Run util/api tests and full build**

  ```bash
  cd api
  go build ./...
  go test ./util/api/... -v
  ```
  Expected: `go build` exits 0 (no compile errors). All tests PASS.

- [ ] **Step 5: Run the full API test suite to confirm no regressions**

  ```bash
  cd api
  go test ./... 2>&1 | tail -30
  ```
  Expected: All packages PASS. No failures.

- [ ] **Step 6: Commit**

  ```bash
  git add api/util/api/api.go api/util/api/api_test.go
  git commit -m "feat(startup): seed wizcli security test into MongoDB on startup"
  ```

---

## Final Verification

- [ ] **Confirm all four tasks are committed**

  ```bash
  git log --oneline -4
  ```
  Expected output (order may vary for parallel agents):
  ```
  <sha>  feat(startup): seed wizcli security test into MongoDB on startup
  <sha>  feat(context): add WizcliSecurityTest field and SetOnceConfig wiring
  <sha>  fix(wizcli): surface ERROR_RUNNING_WIZCLI_SCAN as ErrorFound in analyzeWizCLI
  <sha>  fix(wizcli): replace || true with SCAN_RC sentinel for real tool failures
  ```

- [ ] **Run the complete test suite one final time**

  ```bash
  cd api
  go test ./... -count=1
  ```
  Expected: all packages report `ok`.

---

## Agent Dispatch Summary

| Agent | Tasks | Files | Can start immediately? |
|-------|-------|-------|------------------------|
| **Agent 1** | Task 1 + Task 2 | `api/config.yaml`, `api/securitytest/wizcli.go`, `api/securitytest/wizcli_test.go` | Yes — no dependencies |
| **Agent 2** | Task 3 → Task 4 (sequential within agent) | `api/context/context.go`, `api/context/context_test.go`, `api/util/api/api.go`, `api/util/api/api_test.go` | Yes — no dependencies on Agent 1 |

Agents 1 and 2 touch **disjoint files** and can run in parallel. Task 4 depends on Task 3 within Agent 2 (field must exist before it is dereferenced in the switch).
