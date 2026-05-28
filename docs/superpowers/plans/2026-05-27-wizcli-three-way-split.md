# WizCLI Three-Way Split Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Split the monolithic `wizcli` security test into three independent tests (`wizcli_secrets`, `wizcli_iac_sast`, `wizcli_vulns`) that run in parallel with independent timeout budgets, and extend the Wiz JSON parser to surface all scanner types (IaC, SAST, Malware, AIModels, SoftwareSupplyChain) instead of silently dropping them.

**Architecture:** Three new HuskyCI Generic security tests replace the old single `wizcli` test. Each uses the same Docker image but different `--disabled-scanners` flags via the new `wizcli scan dir` syntax. The Go parser (`wizCLIReport` + `parseWizCLIJSON`) is extended with new struct fields and extraction loops for the 5 missing scanners. The old `wizcli` config block, wiring, and all references are removed entirely. Client output and summary are updated to show three WizCLI result groups.

**Tech Stack:** Go (HuskyCI API + Client), YAML (config), Shell (pod commands), Wiz CLI v1.48+

---

## Decisions Locked (Grilling Session 2026-05-27)

| ID | Decision |
|----|----------|
| D1 | Three tests: `wizcli_secrets`, `wizcli_iac_sast`, `wizcli_vulns` |
| D2 | Use `wizcli scan dir` syntax (not legacy `wizcli dir scan`) |
| D3 | `--disabled-scanners` controls which scanners run per test |
| D4 | `--by-policy-hits=DISABLED` on all three tests |
| D5 | Keep Wiz CLI `latest` in Dockerfile (no version pin) |
| D6 | Remove old monolithic `wizcli` entirely (no disabled fallback) |
| D7 | Same Docker image for all three tests, flags differ in `cmd` |
| D8 | Same parser (`analyzeWizCLI` + `parseWizCLIJSON`) for all three |
| D9 | Same `setVulns` routing for all three in `runGenericScans` |
| D10 | Extend parser for `iac`, `sast`, `malwares`, `aiModels`, `softwareSupplyChain` |
| D11 | No `--types` restriction — let Wiz auto-detect IaC types |
| D12 | No diff-based filtering — scan all tracked files |
| D13 | Timeouts: `wizcli_secrets`=120s, `wizcli_iac_sast`=300s, `wizcli_vulns`=300s |

## Scanner Mapping

| `--disabled-scanners` value | `result.*` JSON key | Test that enables it |
|---|---|---|
| Vulnerability | `libraries` + `osPackages` | `wizcli_vulns` |
| Secret | `secrets` | `wizcli_secrets` |
| SensitiveData | `dataFindings` | `wizcli_secrets` |
| Misconfiguration | `iac` | `wizcli_iac_sast` |
| SAST | `sast` | `wizcli_iac_sast` |
| Malware | `malwares` | `wizcli_vulns` |
| AIModels | `aiModels` | `wizcli_vulns` |
| SoftwareSupplyChain | `softwareSupplyChain` | `wizcli_vulns` |
| *(always-on)* | `endOfLifeTechnologies` | all three |

## `--disabled-scanners` per Test

| Test | Disabled scanners |
|---|---|
| `wizcli_secrets` | `Vulnerability,Misconfiguration,SAST,Malware,AIModels,SoftwareSupplyChain` |
| `wizcli_iac_sast` | `Vulnerability,Secret,SensitiveData,Malware,AIModels,SoftwareSupplyChain` |
| `wizcli_vulns` | `Secret,SensitiveData,Misconfiguration,SAST` |

---

## HuskyCI Security Test Touchpoint Map

Every security test in HuskyCI requires changes across **12 touchpoints**. This plan walks through each one in dependency order. The touchpoints also serve as the checklist for the skill and documentation deliverable.

```
Touchpoint  1: api/config.yaml                              — test definition (image, cmd, type, timeout)
Touchpoint  2: api/types/types.go                            — output struct field in HuskyCIResults
Touchpoint  3: api/context/context.go                        — APIConfig field + SetOnceConfig wiring
Touchpoint  4: api/util/api/api.go                           — MongoDB upsert list + checkSecurityTest switch
Touchpoint  5: api/securitytest/securitytest.go              — securityTestAnalyze dispatch map
Touchpoint  6: api/securitytest/<scanner>.go                 — analyze* func + parser structs + parseJSON
Touchpoint  7: api/securitytest/run.go                       — runGenericScans switch + setVulns switch (4×)
Touchpoint  8: api/securitytest/<scanner>_test.go            — unit tests
Touchpoint  9: client/types/types.go                         — mirror output structs + summary fields
Touchpoint 10: client/analysis/output.go                     — output formatting + summary aggregation
Touchpoint 11: client/analysis/output_wiz_test.go            — client output tests
Touchpoint 12: client/integration/sonarqube/                 — SonarQube external issue integration
```

---

## Task 1: api/config.yaml — Replace `wizcli` block with three new blocks

**Touchpoint:** 1  
**Objective:** Remove the monolithic `wizcli:` config and add three new config blocks using the new `wizcli scan dir` syntax with `--disabled-scanners` and `--by-policy-hits=DISABLED`.

**Files:** Modify: `api/config.yaml`

**Step 1:** Replace the entire `wizcli:` block with three new blocks:

```yaml
wizcli_secrets:
  name: wizcli_secrets
  image: 939030204144.dkr.ecr.us-east-1.amazonaws.com/huskyci-wiz
  imageTag: "latest-amd64"
  cmd: |+
    mkdir -p ~/.ssh &&
    echo '%GIT_PRIVATE_SSH_KEY%' > ~/.ssh/huskyci_id_rsa &&
    chmod 600 ~/.ssh/huskyci_id_rsa &&
    echo "IdentityFile ~/.ssh/huskyci_id_rsa" >> /etc/ssh/ssh_config &&
    echo "StrictHostKeyChecking no" >> /etc/ssh/ssh_config &&
    GIT_TERMINAL_PROMPT=0 git clone -b %GIT_BRANCH% --single-branch --depth 1 %GIT_REPO% code --quiet 2>/tmp/errorGitCloneWiz
    if [ $? -eq 0 ]; then
        wizcli auth --id '%WIZ_CLIENT_ID%' --secret '%WIZ_CLIENT_SECRET%' > /tmp/errorWizAuth 2>&1
        if [ $? -ne 0 ]; then
            echo 'ERROR_AUTH_WIZCLI'
            cat /tmp/errorWizAuth
        else
            wizcli scan dir ./code \
              --disabled-scanners Vulnerability,Misconfiguration,SAST,Malware,AIModels,SoftwareSupplyChain \
              --by-policy-hits=DISABLED \
              --stdout=json --json-output-file=/tmp/wizResult.json 2> /tmp/errorWizScan
            SCAN_RC=$?
            if [ $SCAN_RC -ge 2 ]; then
              echo "ERROR_RUNNING_WIZCLI_SCAN"
              cat /tmp/errorWizScan
            else
              cat /tmp/wizResult.json
            fi
        fi
    else
        echo "ERROR_CLONING"
        cat /tmp/errorGitCloneWiz
    fi
  type: Generic
  default: true
  timeOutInSeconds: 120

wizcli_iac_sast:
  name: wizcli_iac_sast
  image: 939030204144.dkr.ecr.us-east-1.amazonaws.com/huskyci-wiz
  imageTag: "latest-amd64"
  cmd: |+
    mkdir -p ~/.ssh &&
    echo '%GIT_PRIVATE_SSH_KEY%' > ~/.ssh/huskyci_id_rsa &&
    chmod 600 ~/.ssh/huskyci_id_rsa &&
    echo "IdentityFile ~/.ssh/huskyci_id_rsa" >> /etc/ssh/ssh_config &&
    echo "StrictHostKeyChecking no" >> /etc/ssh/ssh_config &&
    GIT_TERMINAL_PROMPT=0 git clone -b %GIT_BRANCH% --single-branch --depth 1 %GIT_REPO% code --quiet 2>/tmp/errorGitCloneWiz
    if [ $? -eq 0 ]; then
        wizcli auth --id '%WIZ_CLIENT_ID%' --secret '%WIZ_CLIENT_SECRET%' > /tmp/errorWizAuth 2>&1
        if [ $? -ne 0 ]; then
            echo 'ERROR_AUTH_WIZCLI'
            cat /tmp/errorWizAuth
        else
            wizcli scan dir ./code \
              --disabled-scanners Vulnerability,Secret,SensitiveData,Malware,AIModels,SoftwareSupplyChain \
              --by-policy-hits=DISABLED \
              --stdout=json --json-output-file=/tmp/wizResult.json 2> /tmp/errorWizScan
            SCAN_RC=$?
            if [ $SCAN_RC -ge 2 ]; then
              echo "ERROR_RUNNING_WIZCLI_SCAN"
              cat /tmp/errorWizScan
            else
              cat /tmp/wizResult.json
            fi
        fi
    else
        echo "ERROR_CLONING"
        cat /tmp/errorGitCloneWiz
    fi
  type: Generic
  default: true
  timeOutInSeconds: 300

wizcli_vulns:
  name: wizcli_vulns
  image: 939030204144.dkr.ecr.us-east-1.amazonaws.com/huskyci-wiz
  imageTag: "latest-amd64"
  cmd: |+
    mkdir -p ~/.ssh &&
    echo '%GIT_PRIVATE_SSH_KEY%' > ~/.ssh/huskyci_id_rsa &&
    chmod 600 ~/.ssh/huskyci_id_rsa &&
    echo "IdentityFile ~/.ssh/huskyci_id_rsa" >> /etc/ssh/ssh_config &&
    echo "StrictHostKeyChecking no" >> /etc/ssh/ssh_config &&
    GIT_TERMINAL_PROMPT=0 git clone -b %GIT_BRANCH% --single-branch --depth 1 %GIT_REPO% code --quiet 2>/tmp/errorGitCloneWiz
    if [ $? -eq 0 ]; then
        wizcli auth --id '%WIZ_CLIENT_ID%' --secret '%WIZ_CLIENT_SECRET%' > /tmp/errorWizAuth 2>&1
        if [ $? -ne 0 ]; then
            echo 'ERROR_AUTH_WIZCLI'
            cat /tmp/errorWizAuth
        else
            wizcli scan dir ./code \
              --disabled-scanners Secret,SensitiveData,Misconfiguration,SAST,AIModels,SoftwareSupplyChain \
              --by-policy-hits=DISABLED \
              --stdout=json --json-output-file=/tmp/wizResult.json 2> /tmp/errorWizScan
            SCAN_RC=$?
            if [ $SCAN_RC -ge 2 ]; then
              echo "ERROR_RUNNING_WIZCLI_SCAN"
              cat /tmp/errorWizScan
            else
              cat /tmp/wizResult.json
            fi
        fi
    else
        echo "ERROR_CLONING"
        cat /tmp/errorGitCloneWiz
    fi
  type: Generic
  default: true
  timeOutInSeconds: 300
```

**Verify:** `python3 -c "import yaml; yaml.safe_load(open('api/config.yaml'))"` — no errors.  
**Commit:** `feat: split wizcli into 3 security tests in config.yaml`

---

## Task 2: api/types/types.go — Replace single WizCLI output field with three

**Touchpoint:** 2  
**Objective:** Replace `HuskyCIWizCLIOutput` in `GenericResults` with three output fields for the three split tests. Update `Summary` struct to have three WizCLI summary fields.

**Files:** Modify: `api/types/types.go`

**Step 1:** In `GenericResults` struct (line 133-137), replace:
```go
type GenericResults struct {
    HuskyCIGitleaksOutput  HuskyCISecurityTestOutput `bson:"gitleaksoutput,omitempty" json:"gitleaksoutput,omitempty"`
    HuskyCIWizCLIOutput    HuskyCISecurityTestOutput `bson:"wizclioutput,omitempty" json:"wizclioutput,omitempty"`
}
```
with:
```go
type GenericResults struct {
    HuskyCIGitleaksOutput      HuskyCISecurityTestOutput `bson:"gitleaksoutput,omitempty" json:"gitleaksoutput,omitempty"`
    HuskyCIWizCLISecretsOutput HuskyCISecurityTestOutput `bson:"wizclisecretsoutput,omitempty" json:"wizclisecretsoutput,omitempty"`
    HuskyCIIacSastOutput       HuskyCISecurityTestOutput `bson:"iavsastoutput,omitempty" json:"iavsastoutput,omitempty"`
    HuskyCIWizCLIVulnsOutput   HuskyCISecurityTestOutput `bson:"wizclivulnsoutput,omitempty" json:"wizclivulnsoutput,omitempty"`
}
```

**Step 2:** In `Summary` struct (line 189), replace:
```go
WizCLISummary           HuskyCISummary `json:"wizclisummary,omitempty"`
```
with:
```go
WizCLISecretsSummary   HuskyCISummary `json:"wizclisecretssummary,omitempty"`
WizCLIIacSastSummary   HuskyCISummary `json:"wizcliiacsastsummary,omitempty"`
WizCLIVulnsSummary      HuskyCISummary `json:"wizclivulnssummary,omitempty"`
```

**Verify:** `cd api/types && go build ./...` — will have compile errors in downstream files (expected, fixed in later tasks).  
**Commit:** `feat: replace single WizCLI output with three in api types`

---

## Task 3: api/context/context.go — Replace WizcliSecurityTest with three fields

**Touchpoint:** 3  
**Objective:** Update the Go config struct to hold three new security test configs instead of one.

**Files:** Modify: `api/context/context.go`

**Step 1:** In the `APIConfig` struct, replace:
```go
WizcliSecurityTest           *types.SecurityTest
```
with:
```go
WizcliiacSastSecurityTest    *types.SecurityTest
WizcliSecretsSecurityTest     *types.SecurityTest
WizcliVulnsSecurityTest       *types.SecurityTest
```

**Step 2:** In `SetOnceConfig` function, replace:
```go
WizcliSecurityTest:           dF.getSecurityTestConfig("wizcli"),
```
with:
```go
WizcliiacSastSecurityTest:     dF.getSecurityTestConfig("wizcli_iac_sast"),
WizcliSecretsSecurityTest:     dF.getSecurityTestConfig("wizcli_secrets"),
WizcliVulnsSecurityTest:       dF.getSecurityTestConfig("wizcli_vulns"),
```

**Verify:** `cd api/context && go build ./...` — compile errors in `api/util/api/api.go` expected.  
**Commit:** `feat: replace WizcliSecurityTest with three fields in APIConfig`

---

## Task 4: api/util/api/api.go — Update MongoDB seeding and security test switch

**Touchpoint:** 4  
**Objective:** Replace `wizcli` in the upsert list with the three new test names, and update the `checkSecurityTest` switch.

**Files:** Modify: `api/util/api/api.go`

**Step 1:** In `checkEachSecurityTest` upsert list, replace `"wizcli"` with `"wizcli_secrets", "wizcli_iac_sast", "wizcli_vulns"`.

**Step 2:** In `checkSecurityTest` switch, replace:
```go
case "wizcli":
    securityTestConfig = *configAPI.WizcliSecurityTest
```
with:
```go
case "wizcli_secrets":
    securityTestConfig = *configAPI.WizcliSecretsSecurityTest
case "wizcli_iac_sast":
    securityTestConfig = *configAPI.WizcliiacSastSecurityTest
case "wizcli_vulns":
    securityTestConfig = *configAPI.WizcliVulnsSecurityTest
```

**Verify:** `cd api/util/api && go build ./...` — PASS.  
**Commit:** `feat: seed three wizcli test configs into MongoDB`

---

## Task 5: api/securitytest/securitytest.go — Update securityTestAnalyze dispatch map

**Touchpoint:** 5  
**Objective:** Map the three new test names to `analyzeWizCLI` in the dispatch map. Remove old `"wizcli"` entry.

**Files:** Modify: `api/securitytest/securitytest.go`

**Step 1:** In `securityTestAnalyze` map (line 18-32), replace:
```go
"wizcli":           analyzeWizCLI,
```
with:
```go
"wizcli_secrets":   analyzeWizCLI,
"wizcli_iac_sast":  analyzeWizCLI,
"wizcli_vulns":     analyzeWizCLI,
```

**Verify:** `cd api/securitytest && go build ./...` — may have errors in `run.go` (fixed in Task 7).  
**Commit:** `feat: dispatch three wizcli test names to analyzeWizCLI`

---

## Task 6: api/securitytest/wizcli.go — Extend parser struct + extraction loops

**Touchpoint:** 6  
**Objective:** Add Go struct fields for 5 missing scanner result types so `json.Unmarshal` captures them, then add extraction loops in `parseWizCLIJSON`.

**Files:** Modify: `api/securitytest/wizcli.go`

**Step 1: Add new struct types** (after `wizEndOfLifeFinding`):

```go
type wizIacFinding struct {
    Name        string `json:"name"`
    Description string `json:"description"`
    Severity    string `json:"severity"`
    File        string `json:"file"`
    Line        int    `json:"line"`
    Rule        string `json:"rule"`
}

type wizSastFinding struct {
    Name        string `json:"name"`
    Description string `json:"description"`
    Severity    string `json:"severity"`
    File        string `json:"file"`
    Line        int    `json:"line"`
    Rule        string `json:"rule"`
}

type wizMalwareFinding struct {
    Name        string `json:"name"`
    Description string `json:"description"`
    Severity    string `json:"severity"`
    Path        string `json:"path"`
}

type wizAIModelFinding struct {
    Name     string `json:"name"`
    Version  string `json:"version"`
    Severity string `json:"severity"`
    Path     string `json:"path"`
}

type wizSupplyChainFinding struct {
    Name     string `json:"name"`
    Version  string `json:"version"`
    Severity string `json:"severity"`
    License  string `json:"license"`
    Path     string `json:"path"`
}
```

**Step 2: Add fields to `wizCLIReport.Result`** (after `EndOfLifeTechnologies`):

```go
Iac                 []wizIacFinding         `json:"iac"`
Sast                 []wizSastFinding        `json:"sast"`
Malwares            []wizMalwareFinding      `json:"malwares"`
AIModels            []wizAIModelFinding      `json:"aiModels"`
SoftwareSupplyChain []wizSupplyChainFinding  `json:"softwareSupplyChain"`
```

**Step 3: Add 5 extraction loops** in `parseWizCLIJSON` (after the existing `endOfLifeTechnologies` loop). Each follows the same `addFinding(title, severity, file, line, details)` pattern used by the existing loops:

- **IaC:** extract from `report.Result.Iac` — title from `Name` (fallback `Rule`), severity from `Severity` (default `"MEDIUM"`), file from `File`, line from `Line`, details from `Description`
- **SAST:** extract from `report.Result.Sast` — same pattern as IaC
- **Malware:** extract from `report.Result.Malwares` — title from `Name`, default severity `"HIGH"`, path from `Path`
- **AIModels:** extract from `report.Result.AIModels` — title from `Name`, default severity `"INFO"`, details = `Name:Version`
- **SoftwareSupplyChain:** extract from `report.Result.SoftwareSupplyChain` — title from `Name`, default severity `"MEDIUM"`, details = `Name:Version (license: License)`

**Verify:** `cd api/securitytest && go build ./...`  
**Commit:** `feat: extend wizCLI parser with iac, sast, malware, aiModels, softwareSupplyChain`

---

## Task 7: api/securitytest/run.go — Update runGenericScans switch + setVulns (4× switch blocks)

**Touchpoint:** 7  
**Objective:** Replace `case "wizcli"` in the `runGenericScans` switch and all four `setVulns` severity switch blocks (HighVulns, MediumVulns, LowVulns, NoSecVulns) with three new cases routing to the new `GenericResults` fields.

**Files:** Modify: `api/securitytest/run.go`

**Step 1:** In `runGenericScans` (around line 107), replace:
```go
case "gitleaks", "wizcli":
    results.setVulns(*scan)
```
with:
```go
case "gitleaks", "wizcli_secrets", "wizcli_iac_sast", "wizcli_vulns":
    results.setVulns(*scan)
```

**Step 2:** In `setVulns` — **all four switch blocks** (HighVulns ~line 185, MediumVulns ~line 212, LowVulns ~line 239, NoSecVulns ~line 266), replace each occurrence of:
```go
case wizcli:
    results.HuskyCIResults.GenericResults.HuskyCIWizCLIOutput.HighVulns = append(...)
```
with three new cases:
```go
case "wizcli_secrets":
    results.HuskyCIResults.GenericResults.HuskyCIWizCLISecretsOutput.HighVulns = append(...)
case "wizcli_iac_sast":
    results.HuskyCIResults.GenericResults.HuskyCIIacSastOutput.HighVulns = append(...)
case "wizcli_vulns":
    results.HuskyCIResults.GenericResults.HuskyCIWizCLIVulnsOutput.HighVulns = append(...)
```

Repeat for MediumVulns, LowVulns, NoSecVulns sections (changing `.HighVulns` to `.MediumVulns`, `.LowVulns`, `.NoSecVulns` respectively).

Note: `bandit`, `brakeman`, etc. are string constants defined in `run.go`. If `wizcli` is defined as a constant, remove it and add three new constants:
```go
wizcliSecrets   = "wizcli_secrets"
wizcliIacSast   = "wizcli_iac_sast"
wizcliVulns     = "wizcli_vulns"
```

**Verify:** `cd api/securitytest && go build ./...` — PASS  
**Commit:** `feat: route three wizcli tests to separate GenericResults fields in setVulns`

---

## Task 8: api/securitytest/wizcli_test.go — Add parser tests for 5 new scanner types

**Touchpoint:** 8  
**Objective:** Add unit tests for each new scanner type plus a null-safety test.

**Files:** Modify: `api/securitytest/wizcli_test.go`

Add these test cases:

1. `TestParseWizCLIJSON_IacFindings` — populates `result.iac` with one IaC finding, asserts Title, Severity, Line extracted correctly
2. `TestParseWizCLIJSON_SastFindings` — populates `result.sast`, same pattern
3. `TestParseWizCLIJSON_MalwareFindings` — populates `result.malwares`, same pattern
4. `TestParseWizCLIJSON_AIModelFindings` — populates `result.aiModels`, same pattern
5. `TestParseWizCLIJSON_SoftwareSupplyChainFindings` — populates `result.softwareSupplyChain`, asserts Details contains license info
6. `TestParseWizCLIJSON_NullNewFieldsIsNoError` — all 5 new fields as `null`, expects 0 findings and no error

**Verify:** `cd api/securitytest && go test -v -run "TestParseWizCLIJSON" -count=1` — all PASS  
**Commit:** `test: add parser tests for iac, sast, malwares, aiModels, softwareSupplyChain`

---

## Task 9: client/types/types.go — Mirror output structs + summary fields

**Touchpoint:** 9  
**Objective:** Mirror the API-side `GenericResults` and `Summary` changes in the client types package so the client can deserialize the new JSON structure.

**Files:** Modify: `client/types/types.go`

**Step 1:** In `GenericResults` struct (line 152-156), replace:
```go
type GenericResults struct {
    HuskyCIGitleaksOutput HuskyCISecurityTestOutput `bson:"gitleaksoutput,omitempty" json:"gitleaksoutput,omitempty"`
    HuskyCIWizCLIOutput   HuskyCISecurityTestOutput `bson:"wizclioutput,omitempty" json:"wizclioutput,omitempty"`
}
```
with:
```go
type GenericResults struct {
    HuskyCIGitleaksOutput      HuskyCISecurityTestOutput `bson:"gitleaksoutput,omitempty" json:"gitleaksoutput,omitempty"`
    HuskyCIWizCLISecretsOutput HuskyCISecurityTestOutput `bson:"wizclisecretsoutput,omitempty" json:"wizclisecretsoutput,omitempty"`
    HuskyCIIacSastOutput       HuskyCISecurityTestOutput `bson:"iavsastoutput,omitempty" json:"iavsastoutput,omitempty"`
    HuskyCIWizCLIVulnsOutput   HuskyCISecurityTestOutput `bson:"wizclivulnsoutput,omitempty" json:"wizclivulnsoutput,omitempty"`
}
```

**Step 2:** In `Summary` struct (line 189), replace:
```go
WizCLISummary           HuskyCISummary `json:"wizclisummary,omitempty"`
```
with:
```go
WizCLISecretsSummary   HuskyCISummary `json:"wizclisecretssummary,omitempty"`
WizCLIIacSastSummary   HuskyCISummary `json:"wizcliiacsastsummary,omitempty"`
WizCLIVulnsSummary      HuskyCISummary `json:"wizclivulnssummary,omitempty"`
```

**Verify:** `cd client/types && go build ./...` — will have errors in `client/analysis/output.go` (fixed in Task 10)  
**Commit:** `feat: mirror three wizcli output fields in client types`

---

## Task 10: client/analysis/output.go — Update output formatting + summary aggregation

**Touchpoint:** 10  
**Objective:** Replace all references to `HuskyCIWizCLIOutput` and `WizCLISummary` with the three new fields. Update print, summary, and exit-code logic.

**Files:** Modify: `client/analysis/output.go`

**Step 1: STDOUT print** (~line 54-55). Replace:
```go
printToolGroup("Generic - Wiz CLI", outputJSON.GenericResults.HuskyCIWizCLIOutput, printSTDOUTOutputWizCLI)
```
with:
```go
printToolGroup("Generic - Wiz CLI (Secrets)", outputJSON.GenericResults.HuskyCIWizCLISecretsOutput, printSTDOUTOutputWizCLI)
printToolGroup("Generic - Wiz CLI (IaC+SAST)", outputJSON.GenericResults.HuskyCIIacSastOutput, printSTDOUTOutputWizCLI)
printToolGroup("Generic - Wiz CLI (Vulns)", outputJSON.GenericResults.HuskyCIWizCLIVulnsOutput, printSTDOUTOutputWizCLI)
```

**Step 2: Summary aggregation** (~line 186-195). Replace all `WizCLISummary` / `HuskyCIWizCLIOutput` references with three separate summaries that aggregate from each output field:
```go
// WizCLI Secrets summary
outputJSON.Summary.WizCLISecretsSummary.NoSecVuln = len(outputJSON.GenericResults.HuskyCIWizCLISecretsOutput.NoSecVulns)
outputJSON.Summary.WizCLISecretsSummary.LowVuln = len(outputJSON.GenericResults.HuskyCIWizCLISecretsOutput.LowVulns)
outputJSON.Summary.WizCLISecretsSummary.MediumVuln = len(outputJSON.GenericResults.HuskyCIWizCLISecretsOutput.MediumVulns)
outputJSON.Summary.WizCLISecretsSummary.HighVuln = len(outputJSON.GenericResults.HuskyCIWizCLISecretsOutput.HighVulns)
// ... same pattern for WizCLIIacSastSummary and WizCLIVulnsSummary
```

For `FoundInfo` / `FoundVuln`, any of the three triggers the flag:
```go
if len(secrets.LowVulns) > 0 || len(iacSast.LowVulns) > 0 || len(vulns.LowVulns) > 0 || ... {
    outputJSON.Summary.WizCLISecretsSummary.FoundInfo = true
    // set FoundInfo on all three if any has findings
}
```

Or simpler: set `FoundInfo`/`FoundVuln` independently per summary.

**Step 3: Exit-code logic** (~line 221-235). Replace all `WizCLISummary` references in the `FoundVuln` / `FoundInfo` / total-count lines with the three new summary fields:
```go
// In FoundVuln check:
outputJSON.Summary.WizCLISecretsSummary.FoundVuln || outputJSON.Summary.WizCLIIacSastSummary.FoundVuln || outputJSON.Summary.WizCLIVulnsSummary.FoundVuln
// In total counts:
totalNoSec += outputJSON.Summary.WizCLISecretsSummary.NoSecVuln + outputJSON.Summary.WizCLIIacSastSummary.NoSecVuln + outputJSON.Summary.WizCLIVulnsSummary.NoSecVuln
// ... same for LowVuln, MediumVuln, HighVuln
```

**Verify:** `cd client/analysis && go build ./...`  
**Commit:** `feat: update client output formatting for three wizcli result groups`

---

## Task 11: client/analysis/output_wiz_test.go — Update client output tests

**Touchpoint:** 11  
**Objective:** Update existing WizCLI output tests to use the three new output fields instead of the single `HuskyCIWizCLIOutput`.

**Files:** Modify: `client/analysis/output_wiz_test.go`

Replace all occurrences of `HuskyCIWizCLIOutput` in test data with `HuskyCIWizCLISecretsOutput` (or distribute across the three as appropriate for each test scenario). Replace `WizCLISummary` with the three summary fields.

**Verify:** `cd client/analysis && go test -v -run "TestPrintSTDOUTOutput_IncludesWizCLI" -count=1`  
**Commit:** `test: update client output tests for three wizcli result groups`

---

## Task 12: client/integration/sonarqube/ — Update SonarQube integration

**Touchpoint:** 12  
**Objective:** Update SonarQube external issue generation to collect findings from all three WizCLI output fields instead of one.

**Files:** Modify: `client/integration/sonarqube/sonarqube.go`

**Step 1:** In the vulnerability collection section (~line 62-65), replace:
```go
allVulns = append(allVulns, analysis.HuskyCIResults.GenericResults.HuskyCIWizCLIOutput.LowVulns...)
allVulns = append(allVulns, analysis.HuskyCIResults.GenericResults.HuskyCIWizCLIOutput.MediumVulns...)
allVulns = append(allVulns, analysis.HuskyCIResults.GenericResults.HuskyCIWizCLIOutput.HighVulns...)
```
with:
```go
allVulns = append(allVulns, analysis.HuskyCIResults.GenericResults.HuskyCIWizCLISecretsOutput.LowVulns...)
allVulns = append(allVulns, analysis.HuskyCIResults.GenericResults.HuskyCIWizCLISecretsOutput.MediumVulns...)
allVulns = append(allVulns, analysis.HuskyCIResults.GenericResults.HuskyCIWizCLISecretsOutput.HighVulns...)
allVulns = append(allVulns, analysis.HuskyCIResults.GenericResults.HuskyCIIacSastOutput.LowVulns...)
allVulns = append(allVulns, analysis.HuskyCIResults.GenericResults.HuskyCIIacSastOutput.MediumVulns...)
allVulns = append(allVulns, analysis.HuskyCIResults.GenericResults.HuskyCIIacSastOutput.HighVulns...)
allVulns = append(allVulns, analysis.HuskyCIResults.GenericResults.HuskyCIWizCLIVulnsOutput.LowVulns...)
allVulns = append(allVulns, analysis.HuskyCIResults.GenericResults.HuskyCIWizCLIVulnsOutput.MediumVulns...)
allVulns = append(allVulns, analysis.HuskyCIResults.GenericResults.HuskyCIWizCLIVulnsOutput.HighVulns...)
```

**Step 2:** Update `sonarqube_wizcli_test.go` test data to use `HuskyCIWizCLISecretsOutput` instead of `HuskyCIWizCLIOutput`.

**Step 3:** Update testdata JSON fixtures if they reference `wizclioutput` → `wizclisecretsoutput` / `iavsastoutput` / `wizclivulnsoutput`.

**Verify:** `cd client/integration/sonarqube && go test -v -count=1`  
**Commit:** `feat: update SonarQube integration for three wizcli result groups`

---

## Task 13: Full regression check

**Step 1:** `cd api && go test ./... -count=1` — all PASS  
**Step 2:** `cd client && go test ./... -count=1` — all PASS  
**Step 3:** `cd api && go vet ./...` — no issues  
**Step 4:** `cd client && go vet ./...` — no issues  
**Step 5:** Commit any fixes if needed

---

## Summary: All Files Changed

| # | File | Touchpoint(s) | Change |
|---|---|---|---|
| 1 | `api/config.yaml` | 1 | Remove `wizcli:` block, add 3 new blocks |
| 2 | `api/types/types.go` | 2 | Replace `HuskyCIWizCLIOutput` → 3 fields in `GenericResults` + `Summary` |
| 3 | `api/context/context.go` | 3 | Replace `WizcliSecurityTest` → 3 fields + `SetOnceConfig` |
| 4 | `api/context/context_test.go` | 3 | Update test assertions |
| 5 | `api/util/api/api.go` | 4 | Upsert list + `checkSecurityTest` switch |
| 6 | `api/securitytest/securitytest.go` | 5 | `securityTestAnalyze` dispatch map |
| 7 | `api/securitytest/wizcli.go` | 6 | 5 new structs + 5 new Result fields + 5 extraction loops |
| 8 | `api/securitytest/wizcli_test.go` | 8 | 6 new test cases |
| 9 | `api/securitytest/run.go` | 7 | `runGenericScans` switch + `setVulns` 4× switch blocks |
| 10 | `client/types/types.go` | 9 | Mirror `GenericResults` + `Summary` changes |
| 11 | `client/analysis/output.go` | 10 | Print formatting + summary aggregation + exit-code logic |
| 12 | `client/analysis/output_wiz_test.go` | 11 | Update test data |
| 13 | `client/integration/sonarqube/sonarqube.go` | 12 | Collect from 3 output fields |
| 14 | `client/integration/sonarqube/sonarqube_wizcli_test.go` | 12 | Update test data |
| 15 | `client/integration/sonarqube/testdata/` | 12 | Update JSON fixtures |

## Deployment Notes

- **MongoDB:** Old `wizcli` document becomes orphaned on next API startup. The 3 new documents are upserted automatically. Manually delete the old `wizcli` document or leave inert.
- **Wiz CLI version:** All three tests use the same Docker image (`latest-amd64`). The `--disabled-scanners` flag requires Wiz CLI v1.48+. Current Dockerfile pulls `latest`.
- **Timeout tuning:** Initial timeouts (120s / 300s / 300s) are estimates. Monitor pod execution times and adjust.
- **Parser field accuracy:** New struct fields are based on inferred JSON shapes. If field names differ, findings are silently skipped (same as today). Validate with real Wiz output in production.
- **Backward compatibility:** Client JSON output shape changes (`wizclioutput` → `wizclisecretsoutput` + `iavsastoutput` + `wizclivulnsoutput`). Any downstream consumers parsing this JSON will need updating.

---

## DEPLOYMENT PHASE

The 12 touchpoints above cover HuskyCI **code changes**. But a security test is not live until its container image is in ECR and the API deployment picks up the new config. This phase covers everything from code merge to a running test in production.

### Release Tracks

HuskyCI has three release tracks in `k8s-infrastructure-live`:

| Track | Path | When to change |
|---|---|---|
| `unreleased` | `components/huskyci/unreleased/` | **This plan.** Every code change targets this track. |
| `next` | `components/huskyci/next/` | Manual — when promoting unreleased → next |
| `stable` | `components/huskyci/stable/` | Manual — when promoting next → stable |

**Rule:** Only update `unreleased/`. `next` and `stable` promotions are done manually by the team.

---

## Task 14: Validate security test output before implementing parser changes

**Objective:** Before writing or modifying any Go parser code, capture the **real JSON output** from the security test tool to verify struct field names and nesting. This prevents the most dangerous bug class: spec-to-code divergence where the parser silently drops findings because JSON keys don't match.

**When to do this:** Before Task 6 (parser changes). This is a **gate** — parser implementation must not proceed until output is validated.

**Steps:**

1. **Run the test tool locally** against a representative repo:
   ```sh
   cd /tmp
   git clone --depth 1 git@github.com:githubanotaai/infrastructure.git wiz-output-test
   cd wiz-output-test
   ~/wizcli scan dir . \
     --disabled-scanners <SCANNERS_FOR_YOUR_TEST> \
     --by-policy-hits=DISABLED \
     --stdout=json --json-output-file=/tmp/wiz-real-output.json
   ```

2. **Inspect the JSON structure** — focus on the `result.*` keys you're adding:
   ```sh
   python3 -c "
   import json
   with open('/tmp/wiz-real-output.json') as f:
       data = json.load(f)
   result = data.get('result', {})
   for key, val in result.items():
       if val is not None:
           print(f'{key}: type={type(val).__name__}, len={len(val) if isinstance(val, list) else \"N/A\"}')
           if isinstance(val, list) and len(val) > 0:
               print(f'  sample: {json.dumps(val[0], indent=2)[:500]}')
   "
   ```

3. **Compare against parser structs** — verify every JSON field name matches the Go struct tag. Common mismatches:
   - `snake_case` JSON vs `CamelCase` Go tags
   - Nested objects the parser flattens
   - Optional fields that may be absent vs empty string
   - `null` vs absent key (both must parse without error)

4. **If mismatches found** — update the struct definitions in Task 6 before implementing

**Output validation is mandatory for:**
- New security tests (validate entire output shape)
- Updated security tests where the tool version changed (check if output shape changed)
- Parser extensions where existing test adds new scanners (validate new `result.*` keys)

---

## Task 15: Build and push scanner container image to ECR

**Objective:** Build the Docker image for the security test scanner and push it to the `anotaai-platform-production` AWS account ECR.

**When to do this:** After Task 14 (output validation) and Task 1 (config.yaml), before any deployment.

**ECR details:**
- **Account:** anotaai-platform-production (account ID: `939030204144`)
- **Region:** `us-east-1`
- **Repository:** `939030204144.dkr.ecr.us-east-1.amazonaws.com/huskyci-wiz`

**Steps:**

1. **AWS login** (using `ifood-aws-login`):
   ```sh
   ifood-aws-login -r idp-aai-sec-team
   ```
   This assumes the `idp-aai-sec-team` role has ECR push permissions. If not, use the appropriate role.

2. **Docker ECR login:**
   ```sh
   aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 939030204144.dkr.ecr.us-east-1.amazonaws.com
   ```

3. **Build the image:**
   ```sh
   cd ~/Gits/huskyci-api
   docker build -t 939030204144.dkr.ecr.us-east-1.amazonaws.com/huskyci-wiz:latest-amd64 \
     -f deployments/dockerfiles/wizcli/Dockerfile .
   ```

4. **Push the image:**
   ```sh
   docker push 939030204144.dkr.ecr.us-east-1.amazonaws.com/huskyci-wiz:latest-amd64
   ```

5. **Verify the image is in ECR:**
   ```sh
   aws ecr describe-images --repository-name huskyci-wiz --region us-east-1 --registry-id 939030204144
   ```

**Note for new security tests:** If creating a brand-new scanner (not just updating wizcli), you also need to:
- Create the ECR repository: `aws ecr create-repository --repository-name huskyci-<scanner-name> --region us-east-1`
- Write a new `Dockerfile` under `deployments/dockerfiles/<scanner-name>/`

---

## Task 16: Build and push HuskyCI API container image to ECR

**Objective:** The `huskyci-api` image contains `config.yaml` baked in. After changing `config.yaml` (Task 1), you must rebuild the API image.

**ECR details:**
- **Repository:** `939030204144.dkr.ecr.us-east-1.amazonaws.com/huskyci-api`

**Steps:**

1. **AWS login** (if not already logged in):
   ```sh
   ifood-aws-login -r idp-aai-sec-team
   ```

2. **Docker ECR login** (if not already logged in):
   ```sh
   aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 939030204144.dkr.ecr.us-east-1.amazonaws.com
   ```

3. **Build the API image:**
   ```sh
   cd ~/Gits/huskyci-api
   docker build -t 939030204144.dkr.ecr.us-east-1.amazonaws.com/huskyci-api:prod.main.<SHORT_SHA>-amd64 \
     -f deployments/dockerfiles/api.Dockerfile .
   ```

4. **Push:**
   ```sh
   docker push 939030204144.dkr.ecr.us-east-1.amazonaws.com/huskyci-api:prod.main.<SHORT_SHA>-amd64
   ```

5. **Note the image tag** — you'll need it in Task 17 to update `values.yaml`.

---

## Task 16b: Build and push HuskyCI Client container image to ECR

**Objective:** Tasks 9-12 change the `client/` Go code. The client image is used as a **GitHub Actions container** in the `.github` org repo (`anotaai-sast.yml` workflow). After changing client code, you must rebuild the client image and update the workflow reference.

**ECR details:**
- **Repository:** `939030204144.dkr.ecr.us-east-1.amazonaws.com/huskyci-client`
- **Current tag:** `prod.main.9045189-amd64-v2`

**Steps:**

1. **Build the client image:**
   ```sh
   cd ~/Gits/huskyci-api
   docker build -t 939030204144.dkr.ecr.us-east-1.amazonaws.com/huskyci-client:prod.main.<SHORT_SHA>-amd64-v2 \
     -f deployments/dockerfiles/client.Dockerfile .
   ```

2. **Push:**
   ```sh
   docker push 939030204144.dkr.ecr.us-east-1.amazonaws.com/huskyci-client:prod.main.<SHORT_SHA>-amd64-v2
   ```

3. **Update `.github` org repo** — the client image tag is hardcoded in the reusable workflow:
   ```sh
   cd ~/Gits/.github
   ```
   Edit `.github/workflows/anotaai-sast.yml` line 24:
   ```yaml
   # Before:
   image: 939030204144.dkr.ecr.us-east-1.amazonaws.com/huskyci-client:prod.main.9045189-amd64-v2
   # After:
   image: 939030204144.dkr.ecr.us-east-1.amazonaws.com/huskyci-client:prod.main.<NEW_SHA>-amd64-v2
   ```
   Commit and push to `master`.

4. **Important:** This change affects **all repos** in the `githubanotaai` org that use the SAST workflow. The image tag must be correct before pushing — a broken client image would block all CI pipelines.

---

## Task 17: Update k8s-infrastructure-live unreleased values.yaml

**Objective:** Update the HuskyCI API deployment to use the new image tag that contains the three-test config.

**Files:** Modify: `k8s-infrastructure-live/components/huskyci/unreleased/values.yaml`

**Steps:**

1. **Update `image.tag`** to the tag pushed in Task 16:
   ```yaml
   image:
     repository: 939030204144.dkr.ecr.us-east-1.amazonaws.com/huskyci-api
     pullPolicy: IfNotPresent
     tag: "prod.main.<NEW_SHA>-amd64"
   ```

2. **Add disable flags** for the three new tests (if needed during rollout):
   ```yaml
   # Security test disable flags
   - name: HUSKYCI_DISABLE_GITAUTHORS
     value: "true"
   # Uncomment to disable individual WizCLI tests:
   # - name: HUSKYCI_DISABLE_WIZCLI_SECRETS
   #   value: "true"
   # - name: HUSKYCI_DISABLE_WIZCLI_IAC_SAST
   #   value: "true"
   # - name: HUSKYCI_DISABLE_WIZCLI_VULNS
   #   value: "true"
   ```

3. **Commit and push** to the `unreleased` branch

4. **Deploy** via GitOps (ArgoCD/Flux will pick up the change automatically, or manual apply)

**Note:** `next/` and `stable/` values.yaml are updated **manually** when promoting releases. Do NOT modify them in this plan.

---

## Task 18: End-to-end validation

**Objective:** Verify the three new security tests actually run in the deployed environment.

**Steps:**

1. **Trigger a HuskyCI scan** against a test repo (e.g., `infrastructure` or a small test repo):
   ```sh
   curl -X POST https://<huskyci-endpoint>/api/v1/token \
     -H 'Content-Type: application/json' \
     -d '{"repositoryURL":"git@github.com:githubanotaai/<test-repo>.git","repositoryBranch":"main"}'
   ```

2. **Check that three WizCLI pods are created** (one per test):
   ```sh
   kubectl get pods -n huskyci -l app=huskyci --sort-by='.status.startTime' | grep wizcli
   ```

3. **Check pod logs** for each test:
   ```sh
   kubectl logs -n huskyci <pod-name-wizcli-secrets>
   kubectl logs -n huskyci <pod-name-wizcli-iac-sast>
   kubectl logs -n huskyci <pod-name-wizcli-vulns>
   ```

4. **Check HuskyCI API response** — the analysis result should contain three separate output groups:
   ```sh
   curl https://<huskyci-endpoint>/api/v1/analysis/<RID>
   ```
   Verify `genericresults` contains `wizclisecretsoutput`, `iavsastoutput`, `wizclivulnsoutput` (not the old `wizclioutput`).

5. **Check client output** — run the HuskyCI client and verify three WizCLI sections appear in the summary.

6. **Check SonarQube** — if SonarQube integration is active, verify WizCLI findings from all three tests appear as external issues.

---

## COMPLETE SECURITY TEST LIFECYCLE CHECKLIST

This checklist applies to **any** new or updated HuskyCI security test. Use it as the definitive reference.

### A. Code Changes (12 Touchpoints)

| # | File | What to change |
|---|---|---|
| 1 | `api/config.yaml` | Add/modify test block: name, image, cmd, type, default, timeOutInSeconds |
| 2 | `api/types/types.go` | Add/modify output field in the appropriate `*Results` struct + `Summary` field |
| 3 | `api/context/context.go` | Add/modify `APIConfig` field + `SetOnceConfig` wiring |
| 4 | `api/util/api/api.go` | Add to `checkEachSecurityTest` upsert list + `checkSecurityTest` switch |
| 5 | `api/securitytest/securitytest.go` | Add to `securityTestAnalyze` dispatch map: `name: analyzeFunc` |
| 6 | `api/securitytest/<scanner>.go` | Write/modify `analyze*` func + parser structs + `parseJSON` func |
| 7 | `api/securitytest/run.go` | Add to `runGenericScans` switch + `setVulns` 4× switch blocks (High/Med/Low/NoSec) |
| 8 | `api/securitytest/<scanner>_test.go` | Write/modify parser unit tests |
| 9 | `client/types/types.go` | Mirror API `*Results` + `Summary` struct changes |
| 10 | `client/analysis/output.go` | Add/modify print formatting + summary aggregation + exit-code logic |
| 11 | `client/analysis/output_<scanner>_test.go` | Write/modify client output tests |
| 12 | `client/integration/sonarqube/` | Add/modify SonarQube collection + tests + testdata |

### B. Output Validation (Gate — before parser implementation)

| Step | Action |
|---|---|
| 1 | Run the security test tool locally against a representative repo |
| 2 | Capture real JSON output with `--stdout=json` |
| 3 | Inspect every `result.*` key — type, nesting, sample values |
| 4 | Compare JSON keys against Go struct tags |
| 5 | Fix any mismatches before writing parser code |

### C. Container Image Build + ECR Push

| Step | Action |
|---|---|
| 1 | AWS login: `ifood-aws-login -r idp-aai-sec-team` |
| 2 | Docker ECR login: `aws ecr get-login-password \| docker login` |
| 3 | Build scanner image: `docker build -t <ECR_REPO>:<TAG> -f Dockerfile .` |
| 4 | Push scanner image: `docker push <ECR_REPO>:<TAG>` |
| 5 | *(For new scanners)* Create ECR repo: `aws ecr create-repository` |
| 6 | Build API image (contains config.yaml): `docker build -t huskyci-api:<TAG> -f api.Dockerfile .` |
| 7 | Push API image: `docker push huskyci-api:<TAG>` |
| 8 | *(If client code changed)* Build client image: `docker build -t huskyci-client:<TAG> -f client.Dockerfile .` |
| 9 | *(If client code changed)* Push client image: `docker push huskyci-client:<TAG>` |
| 10 | *(If client code changed)* Update `.github` org repo `anotaai-sast.yml` container image tag |

### D. Deployment to k8s-infrastructure-live

| Step | Action |
|---|---|
| 1 | Update `unreleased/values.yaml` image tag |
| 2 | Add/update `HUSKYCI_DISABLE_*` env vars if needed |
| 3 | Commit + push to unreleased track |
| 4 | *(GitOps auto-deploys, or manual apply)* |
| 5 | **DO NOT modify** `next/` or `stable/` — those are manual promotions |

### E. End-to-End Validation

| Step | Action |
|---|---|
| 1 | Trigger a HuskyCI scan against a test repo |
| 2 | Verify pods are created with correct test names |
| 3 | Check pod logs for expected output |
| 4 | Check API response for correct output grouping |
| 5 | Check client output for correct display |
| 6 | Check SonarQube integration (if active) |

### F. Post-Deployment

| Step | Action |
|---|---|
| 1 | Monitor pod execution times — adjust timeouts if needed |
| 2 | Monitor for timed-out pods — may need to adjust scan flags |
| 3 | Check MongoDB for orphaned old test documents |
| 4 | Update documentation/skill if any gotchas discovered |