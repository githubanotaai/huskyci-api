# Design: WizCLI Exit-Code Masking & MongoDB Seeding Fix

**Date:** 2026-04-24  
**Status:** Approved  
**Scope:** `huskyci-api` — two independent, parallelisable fixes

---

## Problem Summary

Two product gaps block reliable WizCLI scanning in HuskyCI:

### Gap 1 — `|| true` masks real tool failures (`api/config.yaml`)

The shell command for the `wizcli` security test ends with `|| true`:

```sh
wizcli dir scan --path ./code ... 2>&1 || true
```

This forces the container exit code to always be `0`. When `wizcli dir scan` exits with code `≥ 2` (a genuine tool error — network failure, bad policy name, internal crash), the error is silently swallowed. HuskyCI sees a clean exit, `analyzeWizCLI` finds no findings, and the analysis is marked **passed** even though the scan never completed.

Exit code semantics for `wizcli dir scan`:

| Exit code | Meaning | Desired HuskyCI behaviour |
|-----------|---------|---------------------------|
| `0` | Clean scan, no findings | Parse output → zero vulns → passed |
| `1` | Scan ok, findings present | Parse output → classify vulns → failed/warning |
| `≥ 2` | Real tool error | Surface `ERROR_RUNNING_WIZCLI_SCAN` → CResult = error |

### Gap 2 — wizcli never seeded in MongoDB on startup (`api/context/context.go`, `api/util/api/api.go`)

`wizcli` is defined in `api/config.yaml` but is absent from three startup wiring points:

1. `APIConfig` struct — no `WizcliSecurityTest` field.
2. `SetOnceConfig` — no call to `getSecurityTestConfig("wizcli")`.
3. `checkEachSecurityTest` — `"wizcli"` missing from the upsert list.

On a fresh MongoDB volume, `getAllDefaultSecurityTests("Generic", "")` never returns `wizcli`, so no WizCLI scan is ever dispatched.

---

## Architecture

Two independent sub-tasks touching disjoint files — safe to execute in parallel.

```
Agent 1 (Bug 1 — exit code)          Agent 2 (Bug 2 — seeding)
─────────────────────────────         ──────────────────────────
api/config.yaml                       api/context/context.go
api/securitytest/wizcli.go            api/util/api/api.go
api/securitytest/wizcli_test.go       api/context/context_test.go
```

---

## Detailed Changes

### Agent 1 — Shell Fix + Go Analyser

#### `api/config.yaml` — wizcli `cmd` block

Remove `|| true`. Capture `$?` and emit a sentinel if the exit code indicates a real failure:

```yaml
# BEFORE
wizcli dir scan --path ./code --sensitive-data --secrets \
  --file-hashes-scan --policy "aai-secrets-default-policy" 2>&1 || true

# AFTER
wizcli dir scan --path ./code --sensitive-data --secrets \
  --file-hashes-scan --policy "aai-secrets-default-policy" 2>&1
SCAN_RC=$?
if [ $SCAN_RC -ge 2 ]; then
  echo "ERROR_RUNNING_WIZCLI_SCAN"
fi
```

Exit code `1` (findings present) passes through silently; the Go parser reads the text output and classifies vulnerabilities as usual.

#### `api/securitytest/wizcli.go` — `analyzeWizCLI`

Add sentinel detection **before** the parse step, following the same pattern used by `analyseGitleaks` for `ERROR_RUNNING_GITLEAKS`:

```go
if strings.Contains(output, "ERROR_RUNNING_WIZCLI_SCAN") {
    scanInfo.ErrorFound = errors.New("wizcli dir scan failed with a non-findings exit code")
    return scanInfo.ErrorFound
}
```

`prepareContainerAfterScan` already handles `ErrorFound != nil` by setting `CResult = "error"` and `CStatus = "error running"` — no further changes needed.

#### `api/securitytest/wizcli_test.go` — new test cases

Two new unit tests:

1. **`TestAnalyzeWizCLI_ScanError`** — output containing `ERROR_RUNNING_WIZCLI_SCAN` must return a non-nil error and populate `ErrorFound`.
2. **`TestAnalyzeWizCLI_FindingsExitCode`** — output with real findings but no error sentinel must return `nil` error and populate `HighVulns`.

---

### Agent 2 — MongoDB Seeding Fix

#### `api/context/context.go` — `APIConfig` struct

Add field after `SecurityCodeScanSecurityTest`:

```go
WizcliSecurityTest *types.SecurityTest
```

#### `api/context/context.go` — `SetOnceConfig`

Wire the new field after `SecurityCodeScanSecurityTest`:

```go
WizcliSecurityTest: dF.getSecurityTestConfig("wizcli"),
```

#### `api/util/api/api.go` — `checkEachSecurityTest`

Append `"wizcli"` to the upsert list:

```go
securityTests := []string{
    "enry", "gitauthors", "gosec", "brakeman", "bandit",
    "npmaudit", "yarnaudit", "spotbugs", "gitleaks", "safety",
    "tfsec", "securitycodescan", "wizcli",
}
```

#### `api/util/api/api.go` — `checkSecurityTest` switch

Add case before `default`:

```go
case "wizcli":
    securityTestConfig = *configAPI.WizcliSecurityTest
```

#### `api/context/context_test.go` — new test case

Using the existing `FakeCaller` infrastructure, verify that after `SetOnceConfig`, `APIConfiguration.WizcliSecurityTest` is non-nil and its `Name` field equals the value returned by the fake config reader — consistent with the existing `GitleaksSecurityTest` test pattern.

---

## Data Flow After Fix

```
Startup
  └─ SetOnceConfig → loads WizcliSecurityTest from config.yaml
  └─ checkEachSecurityTest → upserts wizcli doc into MongoDB

Scan request
  └─ getAllDefaultSecurityTests("Generic", "") → returns wizcli ✓
  └─ container runs wizcli dir scan
       ├─ RC=0 → parser → zero vulns → passed
       ├─ RC=1 → parser → vulns classified → failed/warning
       └─ RC≥2 → ERROR_RUNNING_WIZCLI_SCAN → analyzeWizCLI → ErrorFound set → CResult=error
```

---

## Error Handling

| Failure scenario | Sentinel | `CResult` | Visible to user |
|-----------------|----------|-----------|-----------------|
| Auth failure | `ERROR_AUTH_WIZCLI` | passed (current behaviour — unchanged) | No vulns reported |
| Git clone failure | `ERROR_CLONING` | error | Error in container info |
| Tool crash / bad policy / network error | `ERROR_RUNNING_WIZCLI_SCAN` | error | Error in container info |
| Findings found | *(no sentinel)* | failed | Vulns listed |
| Clean scan | *(no sentinel)* | passed | No vulns |

---

## Testing Strategy

- All changes covered by existing Go unit test infrastructure (standard `testing` package for `securitytest`, Ginkgo/Gomega for `context` and `util/api`).
- No integration test changes required.
- `api/util/api/api_test.go` existing `FakeCheck` coverage already exercises `checkEachSecurityTest` path — build validation is sufficient.

---

## Files Changed

| File | Change | Agent |
|------|--------|-------|
| `api/config.yaml` | Remove `\|\| true`, add `SCAN_RC` sentinel block | 1 |
| `api/securitytest/wizcli.go` | Add `ERROR_RUNNING_WIZCLI_SCAN` detection | 1 |
| `api/securitytest/wizcli_test.go` | 2 new test cases | 1 |
| `api/context/context.go` | Add `WizcliSecurityTest` field + `SetOnceConfig` wiring | 2 |
| `api/util/api/api.go` | Add `"wizcli"` to list + switch case | 2 |
| `api/context/context_test.go` | 1 new test case for `WizcliSecurityTest` | 2 |
