package securitytest

import (
	"strings"
	"testing"

	"github.com/githubanotaai/huskyci-api/api/types"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func findVuln(vulns []types.HuskyCIVulnerability, title string) *types.HuskyCIVulnerability {
	for i := range vulns {
		if vulns[i].Title == title {
			return &vulns[i]
		}
	}
	return nil
}

// ── fixtures ─────────────────────────────────────────────────────────────────

const secretsFixture = `Secrets:
  Secret description: AWS Access Key
  Severity: HIGH
  Path: ./code/config/settings.py, Line 42

  Secret description: Generic API Key
  Severity: MEDIUM
  Path: ./code/src/client.go
`

const dataFindingsFixture = `Data Findings:
  Data finding for classifier: Email Address
  Match count: 3
  Severity: LOW
  Path: ./code/data/users.csv
`

const cvesFixture = `Library vulnerabilities:
  Name: lodash, Version: 4.17.15, Path: package-lock.json
    CVE-2021-23337 Severity: HIGH
    Fixed version: 4.17.21
`

const eolFixture = `End of life technologies:
  Name: Python, Version: 2.7
`

const ansiFixture = "Secrets:\n  Secret description: \x1b[31mAWS Access Key\x1b[0m\n  Severity: HIGH\n  Path: ./code/config/aws.yaml, Line 10\n"

const mixedFixture = `Secrets:
  Secret description: AWS Access Key
  Severity: HIGH
  Path: ./code/config/settings.py, Line 42

Library vulnerabilities:
  Name: lodash, Version: 4.17.15, Path: package-lock.json
    CVE-2021-23337 Severity: HIGH
    Fixed version: 4.17.21
`

// ── TestParseWizCLIStdout_Empty ───────────────────────────────────────────────

func TestParseWizCLIStdout_Empty(t *testing.T) {
	result := parseWizCLIStdout("")
	if len(result) != 0 {
		t.Errorf("expected empty slice, got %d findings", len(result))
	}
}

// ── TestParseWizCLIStdout_Secrets ────────────────────────────────────────────

func TestParseWizCLIStdout_Secrets(t *testing.T) {
	result := parseWizCLIStdout(secretsFixture)
	if len(result) == 0 {
		t.Fatal("expected findings from Secrets section, got none")
	}

	awsKey := findVuln(result, "AWS Access Key")
	if awsKey == nil {
		t.Fatal("expected finding with Title 'AWS Access Key'")
	}
	if awsKey.Severity != "HIGH" {
		t.Errorf("expected severity HIGH, got %s", awsKey.Severity)
	}
	if !strings.Contains(awsKey.File, "settings.py") {
		t.Errorf("expected file to contain 'settings.py', got %s", awsKey.File)
	}

	genericKey := findVuln(result, "Generic API Key")
	if genericKey == nil {
		t.Fatal("expected finding with Title 'Generic API Key'")
	}
	if genericKey.Severity != "MEDIUM" {
		t.Errorf("expected severity MEDIUM, got %s", genericKey.Severity)
	}
	if !strings.Contains(genericKey.File, "client.go") {
		t.Errorf("expected file to contain 'client.go', got %s", genericKey.File)
	}
}

// ── TestParseWizCLIStdout_DataFindings ───────────────────────────────────────

func TestParseWizCLIStdout_DataFindings(t *testing.T) {
	result := parseWizCLIStdout(dataFindingsFixture)
	if len(result) == 0 {
		t.Fatal("expected findings from Data Findings section, got none")
	}

	var emailFinding *types.HuskyCIVulnerability
	for i := range result {
		if strings.Contains(result[i].Title, "Email Address") {
			emailFinding = &result[i]
			break
		}
	}
	if emailFinding == nil {
		t.Fatal("expected finding containing 'Email Address'")
	}
	if emailFinding.Severity != "LOW" {
		t.Errorf("expected severity LOW, got %s", emailFinding.Severity)
	}
	if !strings.Contains(emailFinding.File, "users.csv") {
		t.Errorf("expected file to contain 'users.csv', got %s", emailFinding.File)
	}
}

// ── TestParseWizCLIStdout_CVEs ────────────────────────────────────────────────

func TestParseWizCLIStdout_CVEs(t *testing.T) {
	result := parseWizCLIStdout(cvesFixture)
	if len(result) == 0 {
		t.Fatal("expected CVE findings, got none")
	}

	var cveFinding *types.HuskyCIVulnerability
	for i := range result {
		if strings.Contains(result[i].Title, "CVE-2021-23337") {
			cveFinding = &result[i]
			break
		}
	}
	if cveFinding == nil {
		t.Fatal("expected finding containing 'CVE-2021-23337'")
	}
	if cveFinding.Severity != "HIGH" {
		t.Errorf("expected severity HIGH, got %s", cveFinding.Severity)
	}
	if !strings.Contains(cveFinding.File, "lodash") {
		t.Errorf("expected file/location to contain 'lodash', got %s", cveFinding.File)
	}
}

// ── TestParseWizCLIStdout_EOL ─────────────────────────────────────────────────

func TestParseWizCLIStdout_EOL(t *testing.T) {
	result := parseWizCLIStdout(eolFixture)
	if len(result) == 0 {
		t.Fatal("expected EOL findings, got none")
	}

	var eolFinding *types.HuskyCIVulnerability
	for i := range result {
		if result[i].Title == "End of Life Technology" {
			eolFinding = &result[i]
			break
		}
	}
	if eolFinding == nil {
		t.Fatal("expected finding with Title 'End of Life Technology'")
	}
	if eolFinding.Severity != "MEDIUM" {
		t.Errorf("expected severity MEDIUM, got %s", eolFinding.Severity)
	}
	if !strings.Contains(eolFinding.File, "Python") {
		t.Errorf("expected file/location to contain 'Python', got %s", eolFinding.File)
	}
}

// ── TestParseWizCLIStdout_AnsiStripping ──────────────────────────────────────

func TestParseWizCLIStdout_AnsiStripping(t *testing.T) {
	result := parseWizCLIStdout(ansiFixture)
	if len(result) == 0 {
		t.Fatal("expected findings from ANSI fixture, got none")
	}

	for _, v := range result {
		if strings.Contains(v.Title, "\x1b") {
			t.Errorf("ANSI escape code not stripped from Title: %q", v.Title)
		}
		if strings.Contains(v.File, "\x1b") {
			t.Errorf("ANSI escape code not stripped from File: %q", v.File)
		}
	}

	awsKey := findVuln(result, "AWS Access Key")
	if awsKey == nil {
		t.Fatal("expected finding with Title 'AWS Access Key' after ANSI stripping")
	}
	if awsKey.Severity != "HIGH" {
		t.Errorf("expected severity HIGH, got %s", awsKey.Severity)
	}
}

// ── TestParseWizCLIStdout_MixedSections ──────────────────────────────────────

func TestParseWizCLIStdout_MixedSections(t *testing.T) {
	result := parseWizCLIStdout(mixedFixture)

	hasSecret := false
	hasCVE := false
	for _, v := range result {
		if v.Title == "AWS Access Key" {
			hasSecret = true
		}
		if strings.Contains(v.Title, "CVE-2021-23337") {
			hasCVE = true
		}
	}
	if !hasSecret {
		t.Error("expected secret finding in mixed output")
	}
	if !hasCVE {
		t.Error("expected CVE finding in mixed output")
	}
}

// ── TestAnalyzeWizCLI_SeverityBuckets ────────────────────────────────────────

func TestAnalyzeWizCLI_SeverityBuckets(t *testing.T) {
	const input = `Secrets:
  Secret description: High Secret
  Severity: HIGH
  Path: ./high.py

  Secret description: Medium Secret
  Severity: MEDIUM
  Path: ./medium.py

  Secret description: Low Secret
  Severity: LOW
  Path: ./low.py

  Secret description: Info Note
  Severity: INFO
  Path: ./info.py
`
	scanInfo := &SecTestScanInfo{}
	scanInfo.Container.COutput = input

	if err := analyzeWizCLI(scanInfo); err != nil {
		t.Fatalf("analyzeWizCLI returned unexpected error: %v", err)
	}

	if len(scanInfo.Vulnerabilities.HighVulns) == 0 {
		t.Error("expected at least one HIGH vuln")
	}
	if len(scanInfo.Vulnerabilities.MediumVulns) == 0 {
		t.Error("expected at least one MEDIUM vuln")
	}
	if len(scanInfo.Vulnerabilities.LowVulns) == 0 {
		t.Error("expected at least one LOW vuln")
	}
	if len(scanInfo.Vulnerabilities.NoSecVulns) == 0 {
		t.Error("expected at least one INFO/NoSec vuln")
	}

	for _, v := range scanInfo.Vulnerabilities.HighVulns {
		sev := strings.ToUpper(v.Severity)
		if sev != "HIGH" && sev != "CRITICAL" {
			t.Errorf("unexpected severity in HighVulns: %s", v.Severity)
		}
	}
	for _, v := range scanInfo.Vulnerabilities.MediumVulns {
		sev := strings.ToUpper(v.Severity)
		if sev != "MEDIUM" && sev != "MAJOR" {
			t.Errorf("unexpected severity in MediumVulns: %s", v.Severity)
		}
	}
	for _, v := range scanInfo.Vulnerabilities.LowVulns {
		sev := strings.ToUpper(v.Severity)
		if sev != "LOW" && sev != "MINOR" {
			t.Errorf("unexpected severity in LowVulns: %s", v.Severity)
		}
	}
}

// ── TestAnalyzeWizCLI_ErrorAuth ───────────────────────────────────────────────

func TestAnalyzeWizCLI_ErrorAuth(t *testing.T) {
	scanInfo := &SecTestScanInfo{}
	scanInfo.Container.COutput = "ERROR_AUTH_WIZCLI: authentication failed"
	scanInfo.ErrorFound = nil

	if err := analyzeWizCLI(scanInfo); err != nil {
		t.Fatalf("analyzeWizCLI returned unexpected error: %v", err)
	}
	if scanInfo.ErrorFound != nil {
		t.Errorf("expected ErrorFound to be nil after auth error, got %v", scanInfo.ErrorFound)
	}

	total := len(scanInfo.Vulnerabilities.HighVulns) +
		len(scanInfo.Vulnerabilities.MediumVulns) +
		len(scanInfo.Vulnerabilities.LowVulns) +
		len(scanInfo.Vulnerabilities.NoSecVulns)
	if total != 0 {
		t.Errorf("expected zero vulns on auth error, got %d", total)
	}
}

// ── TestAnalyzeWizCLI_ScanError ───────────────────────────────────────────────

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

// ── TestAnalyzeWizCLI_FindingsNoSentinel ─────────────────────────────────────

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
