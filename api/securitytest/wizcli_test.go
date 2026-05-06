package securitytest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/githubanotaai/huskyci-api/api/types"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func findVuln(vulns []types.HuskyCIVulnerability, predicate func(types.HuskyCIVulnerability) bool) *types.HuskyCIVulnerability {
	for i := range vulns {
		if predicate(vulns[i]) {
			return &vulns[i]
		}
	}
	return nil
}

func loadJSONFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join("testdata", "wizcli_v1_json_sample.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read fixture %s: %v", path, err)
	}
	return string(b)
}

// ── parser tests ─────────────────────────────────────────────────────────────

func TestParseWizCLIJSON_Empty(t *testing.T) {
	_, err := parseWizCLIJSON("")
	if err == nil {
		t.Error("expected error parsing empty JSON, got nil")
	}
}

func TestParseWizCLIJSON_InvalidJSON(t *testing.T) {
	_, err := parseWizCLIJSON("not json")
	if err == nil {
		t.Error("expected error parsing invalid JSON, got nil")
	}
}

func TestParseWizCLIJSON_NoFindings(t *testing.T) {
	out, err := parseWizCLIJSON(`{"status":{"state":"SUCCESS","verdict":"PASSED_BY_POLICY"},"result":{}}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected zero findings, got %d", len(out))
	}
}

func TestParseWizCLIJSON_LibraryCVEs(t *testing.T) {
	const input = `{"status":{"state":"SUCCESS","verdict":"PASSED_BY_POLICY"},"result":{"libraries":[
		{"name":"lodash","version":"4.17.4","path":"/package-lock.json","startLine":5,"endLine":5,
		 "vulnerabilities":[
		   {"name":"CVE-2021-23337","severity":"HIGH","fixedVersion":"4.17.21"},
		   {"name":"CVE-2018-3721","severity":"MEDIUM","fixedVersion":"4.17.5"}
		 ]}
	]}}`
	out, err := parseWizCLIJSON(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(out))
	}
	high := findVuln(out, func(v types.HuskyCIVulnerability) bool {
		return v.Title == "CVE-2021-23337"
	})
	if high == nil {
		t.Fatal("expected CVE-2021-23337 finding")
	}
	if high.Severity != "HIGH" {
		t.Errorf("expected severity HIGH, got %q", high.Severity)
	}
	if !strings.Contains(high.File, "lodash:4.17.4") {
		t.Errorf("expected location to contain 'lodash:4.17.4', got %q", high.File)
	}
	if high.Line != "5" {
		t.Errorf("expected line '5', got %q", high.Line)
	}
	if !strings.Contains(high.Details, "fixed: 4.17.21") {
		t.Errorf("expected details to mention fixed version, got %q", high.Details)
	}
	if high.SecurityTool != "WizCLI" {
		t.Errorf("expected tool WizCLI, got %q", high.SecurityTool)
	}
}

func TestParseWizCLIJSON_OSPackagesUseSamePath(t *testing.T) {
	const input = `{"result":{"osPackages":[
		{"name":"openssl","version":"1.1.1","path":"/usr/lib","vulnerabilities":[
			{"name":"CVE-2024-0001","severity":"CRITICAL"}
		]}
	]}}`
	out, err := parseWizCLIJSON(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 1 || out[0].Title != "CVE-2024-0001" {
		t.Fatalf("expected one CVE-2024-0001 finding, got %+v", out)
	}
	if out[0].Severity != "CRITICAL" {
		t.Errorf("expected CRITICAL severity, got %q", out[0].Severity)
	}
}

func TestParseWizCLIJSON_Secrets(t *testing.T) {
	const input = `{"result":{"secrets":[
		{"description":"GitHub Classic PAT","path":"/leaky.env","lineNumber":1,"severity":"HIGH","type":"SAAS_API_KEY"},
		{"description":"AWS access key","path":"/cfg.yaml","lineNumber":42,"severity":"INFORMATIONAL","type":"GENERIC"}
	]}}`
	out, err := parseWizCLIJSON(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 secret findings, got %d", len(out))
	}
	pat := findVuln(out, func(v types.HuskyCIVulnerability) bool {
		return v.Title == "GitHub Classic PAT"
	})
	if pat == nil || pat.Severity != "HIGH" || pat.Line != "1" {
		t.Errorf("unexpected PAT finding: %+v", pat)
	}
	info := findVuln(out, func(v types.HuskyCIVulnerability) bool {
		return v.Title == "AWS access key"
	})
	if info == nil || info.Severity != "INFO" {
		t.Errorf("expected INFORMATIONAL secret to bucket as INFO, got %+v", info)
	}
}

func TestParseWizCLIJSON_DataFindings(t *testing.T) {
	const input = `{"result":{"dataFindings":[
		{"classifier":"Email Address","matchCount":3,"severity":"LOW","path":"/users.csv"}
	]}}`
	out, err := parseWizCLIJSON(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 data finding, got %d", len(out))
	}
	if !strings.Contains(out[0].Title, "Email Address") || !strings.Contains(out[0].Title, "3 matches") {
		t.Errorf("expected title to mention classifier+count, got %q", out[0].Title)
	}
	if out[0].Severity != "LOW" {
		t.Errorf("expected LOW severity, got %q", out[0].Severity)
	}
}

func TestParseWizCLIJSON_EOLTechnologies(t *testing.T) {
	const input = `{"result":{"endOfLifeTechnologies":[{"name":"Python","version":"2.7"}]}}`
	out, err := parseWizCLIJSON(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 EOL finding, got %d", len(out))
	}
	if out[0].Title != "End of Life Technology" {
		t.Errorf("expected EOL title, got %q", out[0].Title)
	}
	if out[0].Severity != "MEDIUM" {
		t.Errorf("expected MEDIUM severity, got %q", out[0].Severity)
	}
	if !strings.Contains(out[0].File, "Python:2.7") {
		t.Errorf("expected location to contain 'Python:2.7', got %q", out[0].File)
	}
}

func TestParseWizCLIJSON_Deduplicates(t *testing.T) {
	const input = `{"result":{"libraries":[
		{"name":"lodash","version":"4.17.4","path":"/package-lock.json",
		 "vulnerabilities":[
		   {"name":"CVE-2021-23337","severity":"HIGH","fixedVersion":"4.17.21"},
		   {"name":"CVE-2021-23337","severity":"HIGH","fixedVersion":"4.17.21"}
		 ]}
	]}}`
	out, err := parseWizCLIJSON(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected dedup to 1 finding, got %d", len(out))
	}
}

// ── analyzeWizCLI tests ──────────────────────────────────────────────────────

func TestAnalyzeWizCLI_RealJSONFixture_BucketsAllSeverities(t *testing.T) {
	scanInfo := &SecTestScanInfo{}
	scanInfo.Container.COutput = loadJSONFixture(t)

	if err := analyzeWizCLI(scanInfo); err != nil {
		t.Fatalf("analyzeWizCLI returned unexpected error: %v", err)
	}

	high := len(scanInfo.Vulnerabilities.HighVulns)
	med := len(scanInfo.Vulnerabilities.MediumVulns)
	low := len(scanInfo.Vulnerabilities.LowVulns)
	info := len(scanInfo.Vulnerabilities.NoSecVulns)
	total := high + med + low + info

	if total < 12 {
		t.Errorf("expected at least 12 findings from fixture (12 lib CVEs + 1 secret), got %d (high=%d med=%d low=%d info=%d)",
			total, high, med, low, info)
	}
	if high == 0 {
		t.Error("expected HIGH-severity library CVEs from fixture")
	}
	if med == 0 {
		t.Error("expected MEDIUM-severity library CVEs from fixture")
	}

	// Ensure every finding is tagged WizCLI.
	for _, v := range scanInfo.Vulnerabilities.HighVulns {
		if v.SecurityTool != "WizCLI" {
			t.Errorf("expected SecurityTool=WizCLI, got %q", v.SecurityTool)
		}
	}
}

func TestAnalyzeWizCLI_ErrorAuth(t *testing.T) {
	scanInfo := &SecTestScanInfo{}
	scanInfo.Container.COutput = "ERROR_AUTH_WIZCLI: authentication failed"

	err := analyzeWizCLI(scanInfo)
	if err == nil {
		t.Fatal("expected non-nil error when ERROR_AUTH_WIZCLI is present, got nil")
	}
	if scanInfo.ErrorFound == nil {
		t.Error("expected scanInfo.ErrorFound to be set, got nil")
	}
}

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

func TestAnalyzeWizCLI_InvalidJSONIsError(t *testing.T) {
	scanInfo := &SecTestScanInfo{}
	scanInfo.Container.COutput = "this is not json at all"

	err := analyzeWizCLI(scanInfo)
	if err == nil {
		t.Fatal("expected non-nil error for non-JSON output, got nil")
	}
	if scanInfo.ErrorFound == nil {
		t.Error("expected scanInfo.ErrorFound to be set, got nil")
	}
}

func TestAnalyzeWizCLI_EmptyOutputIsNoFindings(t *testing.T) {
	scanInfo := &SecTestScanInfo{}
	scanInfo.Container.COutput = ""

	err := analyzeWizCLI(scanInfo)
	if err != nil {
		t.Fatalf("expected nil error for empty output, got %v", err)
	}
	total := len(scanInfo.Vulnerabilities.HighVulns) +
		len(scanInfo.Vulnerabilities.MediumVulns) +
		len(scanInfo.Vulnerabilities.LowVulns) +
		len(scanInfo.Vulnerabilities.NoSecVulns)
	if total != 0 {
		t.Errorf("expected 0 findings for empty output, got %d", total)
	}
}
