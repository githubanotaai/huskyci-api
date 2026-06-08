# pnpm audit Security Test Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Add a new `pnpmaudit` security test that runs `pnpm audit` on JavaScript repos using pnpm as their package manager, alongside the existing `npmaudit` (npm) and `yarnaudit` (yarn) tests.

**Architecture:** In-cmd detection — the pnpm audit cmd script checks for `pnpm-lock.yaml` and silently skips if not found, matching the existing npm/yarn pattern. Both npm and pnpm tests run in parallel for all JavaScript repos (via errgroup in `runLanguageScans`); the wrong package manager test produces empty output. This avoids changes to the language scan dispatch logic.

**Tech Stack:** Go (parser + types), Docker (scanner image), Node.js (pnpm runtime), Bash (cmd script)

**Key Design Decisions:**
- Test name: `pnpmaudit` (follows `npmaudit`/`yarnaudit` naming convention)
- Output struct uses `json:"advisories"` (pnpm queries the npm registry `/bulk` endpoint, which returns `advisories`, not `vulnerabilities`)
- Docker base image: `node:alpine` + `pnpm` installed via `npm install -g pnpm`
- Severity mapping: low→low, moderate→medium, high/critical→high (same as npm audit)
- SecurityTool label: `PnpmAudit`
- Language: JavaScript

---

### Task 1: Output Validation — capture pnpm audit JSON format

**Objective:** Verify the pnpm audit JSON output schema before writing any parser code.

**Files:**
- Create: `docs/plans/pnpm-audit-output-sample.json`

**Step 1: Create test repo with intentional vulnerabilities**

```bash
mkdir -p /tmp/pnpm-test && cd /tmp/pnpm-test
cat > package.json << 'EOF'
{
  "name": "pnpm-test",
  "version": "1.0.0",
  "dependencies": { "lodash": "4.17.20" }
}
EOF
pnpm install
```

**Step 2: Capture real pnpm audit JSON output**

```bash
pnpm audit --json --prod > /tmp/pnpm-audit-output.json 2>/dev/null
```

**Step 3: Inspect output schema**

```bash
python3 -c "
import json
d = json.load(open('/tmp/pnpm-audit-output.json'))
print('Top-level keys:', list(d.keys()))
print('advisories type:', type(d['advisories']))
if d['advisories']:
    adv = list(d['advisories'].values())[0]
    print('Advisory keys:', list(adv.keys()))
    print('Severity:', adv['severity'])
    print('Findings type:', type(adv['findings']))
print('metadata keys:', list(d['metadata'].keys()))
print('vulnerabilities keys:', list(d['metadata']['vulnerabilities'].keys()))
"
```

**Step 4: Save sample output**

```bash
cp /tmp/pnpm-audit-output.json docs/plans/pnpm-audit-output-sample.json
```

**Verification:** All keys match expected schema: `advisories`, `metadata.vulnerabilities`, advisory fields (`id`, `title`, `module_name`, `severity`, `vulnerable_versions`, `cwe`, `github_advisory_id`, `url`, `findings`).

---

### Task 2: Add pnpmaudit config to config.yaml

**Objective:** Define the pnpmaudit security test configuration.

**Files:**
- Modify: `api/config.yaml` (after `yarnaudit` block, around line 300)

**Step 1: Add pnpmaudit config block**

Insert after the `yarnaudit` block in `api/config.yaml`:

```yaml
pnpmaudit:
  name: pnpmaudit
  image: huskyci/pnpmaudit
  imageTag: "11.5.2"
  cmd: |+
    mkdir -p ~/.ssh &&
    echo '%GIT_PRIVATE_SSH_KEY%' > ~/.ssh/huskyci_id_rsa &&
    chmod 600 ~/.ssh/huskyci_id_rsa &&
    echo "IdentityFile ~/.ssh/huskyci_id_rsa" >> /etc/ssh/ssh_config &&
    echo "StrictHostKeyChecking no" >> /etc/ssh/ssh_config &&
    GIT_TERMINAL_PROMPT=0 git clone -b "%GIT_BRANCH%" --single-branch --depth 1 "%GIT_REPO%" code --quiet 2> /tmp/errorGitClonePnpmAudit
    if [ $? -eq 0 ]; then
      cd code
      if [ -f .npmrc ]; then
        rm -f .npmrc
      fi
      if [ -f pnpm-lock.yaml ]; then
        pnpm audit --json --prod > /tmp/results.json 2> /tmp/errorPnpmaudit
        RC=$?
        if [ $RC -eq 0 ] || [ $RC -eq 1 ]; then
          cat /tmp/results.json
        else
          echo 'ERROR_RUNNING_PNPM_AUDIT'
          cat /tmp/errorPnpmaudit
        fi
      fi
    else
      echo "ERROR_CLONING"
      cat /tmp/errorGitClonePnpmAudit
    fi
  type: Language
  language: JavaScript
  default: true
  timeOutInSeconds: 360
```

**Key details:**
- `image: huskyci/pnpmaudit` — new scanner image
- `imageTag: "11.5.2"` — pnpm version
- `pnpm-lock.yaml` check — silent skip if not found (matches npm audit pattern)
- Exit code 0 or 1 both produce JSON output (pnpm exits 1 when vulns found)
- Exit code ≥ 2 → error sentinel `ERROR_RUNNING_PNPM_AUDIT`

**Verification:** YAML parses without errors. Check: `python3 -c "import yaml; yaml.safe_load(open('api/config.yaml'))"`

---

### Task 3: Add PnpmAuditOutput to API types

**Objective:** Add `HuskyCIPnpmAuditOutput` to `JavaScriptResults` struct.

**Files:**
- Modify: `api/types/types.go:117-121`

**Step 1: Add the field to JavaScriptResults**

```go
// JavaScriptResults represents all JavaScript security tests results.
type JavaScriptResults struct {
	HuskyCINpmAuditOutput   HuskyCISecurityTestOutput `bson:"npmauditoutput,omitempty" json:"npmauditoutput,omitempty"`
	HuskyCIYarnAuditOutput  HuskyCISecurityTestOutput `bson:"yarnauditoutput,omitempty" json:"yarnauditoutput,omitempty"`
	HuskyCIPnpmAuditOutput  HuskyCISecurityTestOutput `bson:"pnpmauditoutput,omitempty" json:"pnpmauditoutput,omitempty"`
}
```

**Verification:** `go build ./api/types/` compiles without errors.

---

### Task 4: Add PnpmAuditSecurityTest to API context

**Objective:** Add config field and wiring for the pnpm audit security test.

**Files:**
- Modify: `api/context/context.go`

**Step 1: Add field to APIConfig struct** (around line 101, after YarnAuditSecurityTest)

```go
PnpmAuditSecurityTest        *types.SecurityTest
```

**Step 2: Add SetOnceConfig wiring** (around line 157, after YarnAuditSecurityTest)

```go
PnpmAuditSecurityTest:        dF.getSecurityTestConfig("pnpmaudit"),
```

**Verification:** `go build ./api/context/` compiles without errors.

---

### Task 5: Add pnpmaudit to checkEachSecurityTest and checkSecurityTest

**Objective:** Register pnpmaudit in the DB seeding and config validation path.

**Files:**
- Modify: `api/util/api/api.go`

**Step 1: Add to securityTests list in checkEachSecurityTest** (line ~162)

Add `"pnpmaudit"` to the `securityTests` slice after `"yarnaudit"`.

**Step 2: Add case to checkSecurityTest switch** (after yarnaudit case, line ~220)

```go
case "pnpmaudit":
    securityTestConfig = *configAPI.PnpmAuditSecurityTest
```

**Verification:** `go build ./api/util/api/` compiles. Check `api/util/api/api_test.go` for any struct literal references that need updating.

---

### Task 6: Create pnpm audit analyzer (pnpmaudit.go)

**Objective:** Write the Go parser for pnpm audit JSON output.

**Files:**
- Create: `api/securitytest/pnpmaudit.go`

**Step 1: Define parser structs**

```go
package securitytest

import (
	"encoding/json"
	"fmt"

	"github.com/githubanotaai/huskyci-api/api/log"
	"github.com/githubanotaai/huskyci-api/api/types"
	"github.com/githubanotaai/huskyci-api/api/util"
)

// PnpmAuditOutput is the struct that stores all pnpm audit output.
type PnpmAuditOutput struct {
	Advisories map[string]PnpmAdvisory `json:"advisories"`
	Metadata   PnpmMetadata            `json:"metadata"`
}

// PnpmAdvisory is a single advisory from pnpm audit.
type PnpmAdvisory struct {
	ID                 int             `json:"id"`
	Title              string          `json:"title"`
	ModuleName         string          `json:"module_name"`
	VulnerableVersions string          `json:"vulnerable_versions"`
	PatchedVersions    string          `json:"patched_versions"`
	Severity           string          `json:"severity"`
	CWE                string          `json:"cwe"`
	GithubAdvisoryID   string          `json:"github_advisory_id"`
	URL                string          `json:"url"`
	Findings           []PnpmFinding   `json:"findings"`
}

// PnpmFinding represents a specific finding of a vulnerable dependency.
type PnpmFinding struct {
	Version  string   `json:"version"`
	Paths    []string `json:"paths"`
	Dev      bool     `json:"dev"`
	Optional bool     `json:"optional"`
	Bundled  bool     `json:"bundled"`
}

// PnpmMetadata is the struct that holds vulnerabilities summary.
type PnpmMetadata struct {
	Vulnerabilities PnpmVulnerabilitiesSummary `json:"vulnerabilities"`
}

// PnpmVulnerabilitiesSummary is the struct that has all types of possible vulnerabilities.
type PnpmVulnerabilitiesSummary struct {
	Info     int `json:"info"`
	Low      int `json:"low"`
	Moderate int `json:"moderate"`
	High     int `json:"high"`
	Critical int `json:"critical"`
}
```

**Step 2: Write analyzePnpmaudit function**

```go
func analyzePnpmaudit(pnpmAuditScan *SecTestScanInfo) error {
	pnpmAuditOutput := PnpmAuditOutput{}
	pnpmAuditScan.FinalOutput = pnpmAuditOutput

	// nil cOutput states that no Issues were found (pnpm-lock.yaml not present).
	if pnpmAuditScan.Container.COutput == "" {
		pnpmAuditScan.prepareContainerAfterScan()
		return nil
	}

	// Unmarshal rawOutput into finalOutput.
	if err := json.Unmarshal([]byte(pnpmAuditScan.Container.COutput), &pnpmAuditOutput); err != nil {
		log.Error("analyzePnpmaudit", "PNPMAUDIT", 1014, pnpmAuditScan.Container.COutput, err)
		pnpmAuditScan.ErrorFound = util.HandleScanError(pnpmAuditScan.Container.COutput, err)
		pnpmAuditScan.prepareContainerAfterScan()
		return pnpmAuditScan.ErrorFound
	}
	pnpmAuditScan.FinalOutput = pnpmAuditOutput

	pnpmAuditScan.preparePnpmAuditVulns()
	pnpmAuditScan.prepareContainerAfterScan()
	return nil
}
```

**Step 3: Write preparePnpmAuditVulns method**

```go
func (pnpmAuditScan *SecTestScanInfo) preparePnpmAuditVulns() {
	huskyCIPnpmauditResults := types.HuskyCISecurityTestOutput{}
	pnpmAuditOutput := pnpmAuditScan.FinalOutput.(PnpmAuditOutput)

	for _, advisory := range pnpmAuditOutput.Advisories {
		pnpmauditVuln := types.HuskyCIVulnerability{}
		pnpmauditVuln.Language = "JavaScript"
		pnpmauditVuln.SecurityTool = "PnpmAudit"
		pnpmauditVuln.File = "pnpm-lock.yaml"
		pnpmauditVuln.Title = fmt.Sprintf("Vulnerable Dependency: %s %s (%s)", advisory.ModuleName, advisory.VulnerableVersions, advisory.Title)
		pnpmauditVuln.VunerableBelow = advisory.VulnerableVersions
		pnpmauditVuln.Code = advisory.ModuleName
		pnpmauditVuln.Details = fmt.Sprintf("GHSA: %s\nCWE: %s\nURL: %s\nPatched: %s", advisory.GithubAdvisoryID, advisory.CWE, advisory.URL, advisory.PatchedVersions)

		for i, finding := range advisory.Findings {
			pnpmauditVuln.Version += fmt.Sprintf("Finding %d:\n", i)
			pnpmauditVuln.Version += fmt.Sprintf("  Version: %s\n", finding.Version)
			for _, path := range finding.Paths {
				pnpmauditVuln.Version += fmt.Sprintf("  Path: %s\n", path)
			}
		}

		switch advisory.Severity {
		case "info", "low":
			pnpmauditVuln.Severity = "low"
			huskyCIPnpmauditResults.LowVulns = append(huskyCIPnpmauditResults.LowVulns, pnpmauditVuln)
		case "moderate":
			pnpmauditVuln.Severity = "medium"
			huskyCIPnpmauditResults.MediumVulns = append(huskyCIPnpmauditResults.MediumVulns, pnpmauditVuln)
		case "high", "critical":
			pnpmauditVuln.Severity = "high"
			huskyCIPnpmauditResults.HighVulns = append(huskyCIPnpmauditResults.HighVulns, pnpmauditVuln)
		}
	}

	pnpmAuditScan.Vulnerabilities = huskyCIPnpmauditResults
}
```

**Verification:** `go build ./api/securitytest/` compiles without errors.

---

### Task 7: Wire pnpmaudit into dispatch map and run.go

**Objective:** Register the analyzer in the dispatch map and output routing.

**Files:**
- Modify: `api/securitytest/securitytest.go` (line ~24)
- Modify: `api/securitytest/run.go`

**Step 1: Add to securityTestAnalyze dispatch map**

After `"npmaudit": analyzeNpmaudit,`:
```go
"pnpmaudit":        analyzePnpmaudit,
```

**Step 2: Add const in run.go** (line ~33, after yarnaudit)

```go
const pnpmaudit = "pnpmaudit"
```

**Step 3: Add case to vulnOutput switch** (after yarnaudit case, line ~183)

```go
case pnpmaudit:
    return &results.HuskyCIResults.JavaScriptResults.HuskyCIPnpmAuditOutput
```

**Verification:** `go build ./api/securitytest/` compiles without errors.

---

### Task 8: Write API parser unit tests

**Objective:** Test the pnpm audit parser with real output.

**Files:**
- Create: `api/securitytest/pnpmaudit_test.go`

**Step 1: Write test fixture based on captured output**

```go
package securitytest

import (
	"testing"

	"github.com/githubanotaai/huskyci-api/api/types"
)

func TestAnalyzePnpmaudit(t *testing.T) {
	// Real pnpm audit --json --prod output with lodash@4.17.20
	pnpmOutput := `{"advisories":{"1106913":{"findings":[{"version":"4.17.20","paths":[".>lodash"],"dev":false,"optional":false,"bundled":false}],"id":1106913,"title":"Command Injection in lodash","module_name":"lodash","vulnerable_versions":"<4.17.21","patched_versions":">=4.17.21","severity":"high","cwe":"CWE-77, CWE-94","github_advisory_id":"GHSA-35jh-r3h4-6jhm","url":"https://github.com/advisories/GHSA-35jh-r3h4-6jhm"}},"metadata":{"vulnerabilities":{"info":0,"low":0,"moderate":0,"high":1,"critical":0},"dependencies":1,"devDependencies":0,"optionalDependencies":0,"totalDependencies":1}}`

	scan := &SecTestScanInfo{
		Container: types.Container{
			COutput: pnpmOutput,
		},
	}

	err := analyzePnpmaudit(scan)
	if err != nil {
		t.Fatalf("analyzePnpmaudit returned error: %v", err)
	}

	if len(scan.Vulnerabilities.HighVulns) != 1 {
		t.Errorf("expected 1 high vuln, got %d", len(scan.Vulnerabilities.HighVulns))
	}

	vuln := scan.Vulnerabilities.HighVulns[0]
	if vuln.SecurityTool != "PnpmAudit" {
		t.Errorf("expected SecurityTool PnpmAudit, got %s", vuln.SecurityTool)
	}
	if vuln.Severity != "high" {
		t.Errorf("expected severity high, got %s", vuln.Severity)
	}
	if vuln.File != "pnpm-lock.yaml" {
		t.Errorf("expected file pnpm-lock.yaml, got %s", vuln.File)
	}
}

func TestAnalyzePnpmauditEmpty(t *testing.T) {
	// Empty COutput (pnpm-lock.yaml not found → silent skip)
	scan := &SecTestScanInfo{
		Container: types.Container{
			COutput: "",
		},
	}

	err := analyzePnpmaudit(scan)
	if err != nil {
		t.Fatalf("analyzePnpmaudit returned error: %v", err)
	}

	if len(scan.Vulnerabilities.HighVulns) != 0 {
		t.Errorf("expected 0 vulns for empty output, got high=%d", len(scan.Vulnerabilities.HighVulns))
	}
}
```

**Step 2: Run tests**

```bash
cd api/securitytest && go test -run TestAnalyzePnpmaudit -v
```

Expected: PASS

---

### Task 9: Add PnpmAuditOutput to client types

**Objective:** Mirror the API type changes in the client.

**Files:**
- Modify: `client/types/types.go:137-140`

**Step 1: Add field to client JavaScriptResults**

```go
type JavaScriptResults struct {
	HuskyCINpmAuditOutput   HuskyCISecurityTestOutput `bson:"npmauditoutput,omitempty" json:"npmauditoutput,omitempty"`
	HuskyCIYarnAuditOutput  HuskyCISecurityTestOutput `bson:"yarnauditoutput,omitempty" json:"yarnauditoutput,omitempty"`
	HuskyCIPnpmAuditOutput  HuskyCISecurityTestOutput `bson:"pnpmauditoutput,omitempty" json:"pnpmauditoutput,omitempty"`
}
```

**Step 2: Create client-level pnpm audit output struct**

Create: `client/types/pnpmaudit.go`

```go
package types

// PnpmAuditOutput is the struct that stores all pnpm audit output.
type PnpmAuditOutput struct {
	Advisories map[string]PnpmAdvisory `json:"advisories"`
	Metadata   PnpmMetadata            `json:"metadata"`
}

// PnpmAdvisory is a single advisory from pnpm audit.
type PnpmAdvisory struct {
	Findings           []PnpmFinding `json:"findings"`
	ID                 int           `json:"id"`
	Title              string        `json:"title"`
	ModuleName         string        `json:"module_name"`
	VulnerableVersions string        `json:"vulnerable_versions"`
	Severity           string        `json:"severity"`
}

// PnpmFinding represents a specific finding of a vulnerable dependency.
type PnpmFinding struct {
	Version string `json:"version"`
}

// PnpmMetadata is the struct that holds vulnerabilities summary.
type PnpmMetadata struct {
	Vulnerabilities PnpmVulnerabilitiesSummary `json:"vulnerabilities"`
}

// PnpmVulnerabilitiesSummary holds the count of vulnerabilities by severity.
type PnpmVulnerabilitiesSummary struct {
	Info     int `json:"info"`
	Low      int `json:"low"`
	Moderate int `json:"moderate"`
	High     int `json:"high"`
	Critical int `json:"critical"`
}
```

**Verification:** `go build ./client/types/` compiles.

---

### Task 10: Add pnpm audit client output formatting

**Objective:** Add pnpm audit to the client's stdout output and summary.

**Files:**
- Modify: `client/analysis/output.go`

**Step 1: Add print call in printSTDOUTOutput** (after yarnaudit line ~49)

```go
// pnpmaudit
printToolGroup("JavaScript - PnpmAudit", outputJSON.JavaScriptResults.HuskyCIPnpmAuditOutput, printSTDOUTOutputPnpmAudit)
```

**Step 2: Add printSTDOUTOutputPnpmAudit function**

```go
func printSTDOUTOutputPnpmAudit(output types.HuskyCISecurityTestOutput) {
	printDefaultOutput(output)
}
```

**Step 3: Add PnpmAuditSummary to Summary struct** (in `client/types/types.go`, after YarnAuditSummary)

Add field:
```go
PnpmAuditSummary         HuskyCISummary `json:"pnpmauditsummary,omitempty"`
```

**Step 4: Add summary aggregation** (after NpmAudit summary block, around line ~145)

```go
// PnpmAudit summary
outputJSON.Summary.PnpmAuditSummary.LowVuln = len(outputJSON.JavaScriptResults.HuskyCIPnpmAuditOutput.LowVulns)
outputJSON.Summary.PnpmAuditSummary.MediumVuln = len(outputJSON.JavaScriptResults.HuskyCIPnpmAuditOutput.MediumVulns)
outputJSON.Summary.PnpmAuditSummary.HighVuln = len(outputJSON.JavaScriptResults.HuskyCIPnpmAuditOutput.HighVulns)
if len(outputJSON.JavaScriptResults.HuskyCIPnpmAuditOutput.LowVulns) > 0 || len(outputJSON.JavaScriptResults.HuskyCIPnpmAuditOutput.NoSecVulns) > 0 {
    outputJSON.Summary.PnpmAuditSummary.FoundInfo = true
}
if len(outputJSON.JavaScriptResults.HuskyCIPnpmAuditOutput.MediumVulns) > 0 || len(outputJSON.JavaScriptResults.HuskyCIPnpmAuditOutput.HighVulns) > 0 {
    outputJSON.Summary.PnpmAuditSummary.FoundVuln = true
}
```

**Step 5: Exit-code logic**

No explicit exit-code logic needed — the client uses global `types.FoundVuln`/`types.FoundInfo` booleans set during summary aggregation (Step 4). When pnpm audit finds HIGH/MEDIUM vulns, `FoundVuln` becomes true and the client exits 190 automatically (matching npm/yarn audit behavior).

**Verification:** `go build ./client/analysis/` compiles.

---

### Task 11: Write client output tests

**Objective:** Test the client-side pnpm audit output formatting.

**Files:**
- Create: `client/analysis/output_pnpmaudit_test.go`

**Step 1: Write test with pnpm audit findings**

```go
package analysis

import (
	"testing"

	"github.com/githubanotaai/huskyci-api/client/types"
)

func TestPrintSTDOUTOutputPnpmAudit(t *testing.T) {
	output := types.HuskyCISecurityTestOutput{
		HighVulns: []types.HuskyCIVulnerability{
			{
				Language:     "JavaScript",
				SecurityTool: "PnpmAudit",
				Severity:     "high",
				File:         "pnpm-lock.yaml",
				Code:         "lodash",
				Title:        "Vulnerable Dependency: lodash <4.17.21 (Command Injection)",
			},
		},
	}
	// Verify no panic on nil/missing fields
	printSTDOUTOutputPnpmAudit(output)
}
```

**Step 2: Run tests**

```bash
cd client/analysis && go test -run TestPrintSTDOUTOutputPnpmAudit -v
```

Expected: PASS

---

### Task 12: Add pnpm audit to SonarQube integration

**Objective:** Include pnpm audit findings in the SonarQube external issues report.

**Files:**
- Modify: `client/integration/sonarqube/sonarqube.go`

**Step 1: Add collection block** (after yarnaudit block, line ~55)

```go
// pnpmaudit
allVulns = append(allVulns, analysis.HuskyCIResults.JavaScriptResults.HuskyCIPnpmAuditOutput.LowVulns...)
allVulns = append(allVulns, analysis.HuskyCIResults.JavaScriptResults.HuskyCIPnpmAuditOutput.MediumVulns...)
allVulns = append(allVulns, analysis.HuskyCIResults.JavaScriptResults.HuskyCIPnpmAuditOutput.HighVulns...)
```

**Step 2: Check for SonarQube test fixture updates**

Check `client/integration/sonarqube/testdata/` for any test fixtures that reference JavaScriptResults — add `pnpmauditoutput` if needed.

**Verification:** `go build ./client/integration/sonarqube/` compiles. Run SonarQube tests: `go test ./client/integration/sonarqube/ -v`

---

### Task 13: Create pnpmaudit Dockerfile

**Objective:** Create the scanner container image with pnpm installed.

**Files:**
- Create: `deployments/dockerfiles/pnpmaudit/Dockerfile`

**Step 1: Write Dockerfile**

```dockerfile
# Dockerfile used to create "huskyci/pnpmaudit" image

FROM node:alpine

RUN apk update && apk upgrade \
	&& apk add --no-cache alpine-sdk bash openssh-client \
	&& apk add git

RUN npm install -g pnpm@11.5.2
RUN wget -O jq https://github.com/stedolan/jq/releases/download/jq-1.5/jq-linux64
RUN chmod +x ./jq
RUN cp jq /usr/bin
```

**Verification:** `docker build -f deployments/dockerfiles/pnpmaudit/Dockerfile -t huskyci/pnpmaudit:test .` (builds successfully)

---

### Task 14: Final verification — build and test

**Objective:** Verify the full API compiles and all tests pass.

**Files:** N/A

**Step 1: Build API**

```bash
cd api && go build ./...
```

**Step 2: Run all securitytest tests**

```bash
cd api/securitytest && go test -v -run "TestAnalyze"
```

**Step 3: Run all client tests**

```bash
cd client && go test ./...
```

**Step 4: Check for missing references**

```bash
cd ~/Gits/huskyci-api
grep -r "npmaudit" --include="*.go" | grep -v "_test.go" | grep -v "npmaudit.go"
```

Review all references — pnpm audit should be handled in all the same places.

---

## Summary of All Touchpoints

| # | File | Change |
|---|---|---|
| 1 | `api/config.yaml` | Add `pnpmaudit` test block |
| 2 | `api/types/types.go` | Add `HuskyCIPnpmAuditOutput` to `JavaScriptResults` |
| 3 | `api/context/context.go` | Add `PnpmAuditSecurityTest` field + wiring |
| 4 | `api/util/api/api.go` | Add to `checkEachSecurityTest` + `checkSecurityTest` switch |
| 5 | `api/securitytest/securitytest.go` | Add to `securityTestAnalyze` dispatch map |
| 6 | `api/securitytest/pnpmaudit.go` | **NEW**: analyzer + parser structs |
| 7 | `api/securitytest/run.go` | Add const + `vulnOutput` case |
| 8 | `api/securitytest/pnpmaudit_test.go` | **NEW**: parser unit tests |
| 9 | `client/types/types.go` | Add `HuskyCIPnpmAuditOutput` to `JavaScriptResults` |
| 10 | `client/types/pnpmaudit.go` | **NEW**: client-level pnpm audit types |
| 11 | `client/analysis/output.go` | Add print call, summary aggregation, exit-code logic |
| 12 | `client/analysis/output_pnpmaudit_test.go` | **NEW**: client output tests |
| 13 | `client/integration/sonarqube/sonarqube.go` | Add SonarQube collection for pnpm audit |
| 14 | `deployments/dockerfiles/pnpmaudit/Dockerfile` | **NEW**: scanner Docker image |

## Container Build (Phase C — after code is merged)

| Step | Action |
|---|---|
| 1 | `ifood-aws-login -r anotaai-platform-production:idp-aai-sec-team` |
| 2 | Docker ECR login |
| 3 | Build + push scanner image: `docker buildx build --platform linux/amd64 --builder huskyci-buildx -f deployments/dockerfiles/pnpmaudit/Dockerfile -t 939030204144.dkr.ecr.us-east-1.amazonaws.com/huskyci-pnpmaudit:f793155-amd64 --push .` |
| 4 | Create ECR repo: `aws ecr create-repository --repository-name huskyci-pnpmaudit --region us-east-1` |
| 5 | Build + push API image (config.yaml is baked in) |
| 6 | Build + push client image |
| 7 | Update k8s-infrastructure-live values.yaml |
| 8 | Update .github anotaai-sast.yml client image tag |
