package sonarqube

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/githubanotaai/huskyci-api/client/types"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func makeWizSecretsAnalysis(high, medium, low []types.HuskyCIVulnerability) types.Analysis {
	return makeWizSecretsAnalysisWithNoSec(high, medium, low, nil)
}

func makeWizSecretsAnalysisWithNoSec(high, medium, low, nosec []types.HuskyCIVulnerability) types.Analysis {
	return types.Analysis{
		HuskyCIResults: types.HuskyCIResults{
			GenericResults: types.GenericResults{
				HuskyCIWizCLISecretsOutput: types.HuskyCISecurityTestOutput{
					HighVulns:   high,
					MediumVulns: medium,
					LowVulns:    low,
					NoSecVulns:  nosec,
				},
			},
		},
	}
}

func makeWizIacSastAnalysis(high, medium, low []types.HuskyCIVulnerability) types.Analysis {
	return types.Analysis{
		HuskyCIResults: types.HuskyCIResults{
			GenericResults: types.GenericResults{
				HuskyCIIacSastOutput: types.HuskyCISecurityTestOutput{
					HighVulns:   high,
					MediumVulns: medium,
					LowVulns:    low,
				},
			},
		},
	}
}

func makeWizVulnsAnalysis(high, medium, low []types.HuskyCIVulnerability) types.Analysis {
	return types.Analysis{
		HuskyCIResults: types.HuskyCIResults{
			GenericResults: types.GenericResults{
				HuskyCIWizCLIVulnsOutput: types.HuskyCISecurityTestOutput{
					HighVulns:   high,
					MediumVulns: medium,
					LowVulns:    low,
				},
			},
		},
	}
}

func makeWizVuln(title, severity, file string) types.HuskyCIVulnerability {
	return types.HuskyCIVulnerability{
		Language:     "Generic",
		SecurityTool: "WizCLI",
		Title:        title,
		Severity:     severity,
		File:         file,
		Details:      title,
	}
}

func readSonarOutput(t *testing.T, outputPath, outputFileName string) HuskyCISonarOutput {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(outputPath, outputFileName))
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	var out HuskyCISonarOutput
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("failed to parse sonar output JSON: %v", err)
	}
	return out
}

func findIssueByTitle(out HuskyCISonarOutput, title string) *SonarIssue {
	for i := range out.Issues {
		if strings.Contains(out.Issues[i].RuleID, title) || strings.Contains(out.Issues[i].PrimaryLocation.Message, title) {
			return &out.Issues[i]
		}
	}
	return nil
}

// ── TestGenerateOutputFile_WizCLI_HighVuln ───────────────────────────────────

func TestGenerateOutputFile_WizCLI_HighVuln(t *testing.T) {
	outputPath := t.TempDir()
	outputFileName := "sonarqube.json"

	vuln := makeWizVuln("AWS Access Key", "HIGH", "./code/config/settings.py")
	analysis := makeWizSecretsAnalysis([]types.HuskyCIVulnerability{vuln}, nil, nil)

	if err := GenerateOutputFile(analysis, outputPath+"/", outputFileName); err != nil {
		t.Fatalf("GenerateOutputFile returned error: %v", err)
	}

	out := readSonarOutput(t, outputPath, outputFileName)

	if len(out.Issues) == 0 {
		t.Fatal("expected at least one issue in sonar output, got none")
	}
	issue := findIssueByTitle(out, "AWS Access Key")
	if issue == nil {
		t.Fatalf("expected issue for 'AWS Access Key', not found in: %+v", out.Issues)
	}
	if issue.RuleID == "" {
		t.Error("expected non-empty ruleId")
	}
}

// ── TestGenerateOutputFile_WizCLI_MediumVuln ─────────────────────────────────

func TestGenerateOutputFile_WizCLI_MediumVuln(t *testing.T) {
	outputPath := t.TempDir()
	outputFileName := "sonarqube.json"

	vuln := makeWizVuln("Generic API Key", "MEDIUM", "./code/src/client.go")
	analysis := makeWizSecretsAnalysis(nil, []types.HuskyCIVulnerability{vuln}, nil)

	if err := GenerateOutputFile(analysis, outputPath+"/", outputFileName); err != nil {
		t.Fatalf("GenerateOutputFile returned error: %v", err)
	}

	out := readSonarOutput(t, outputPath, outputFileName)

	if len(out.Issues) == 0 {
		t.Fatal("expected at least one issue in sonar output, got none")
	}
	issue := findIssueByTitle(out, "Generic API Key")
	if issue == nil {
		t.Fatalf("expected issue for 'Generic API Key', not found in: %+v", out.Issues)
	}

	var foundRule *SonarRule
	for i := range out.Rules {
		if out.Rules[i].ID == issue.RuleID {
			foundRule = &out.Rules[i]
			break
		}
	}
	if foundRule == nil {
		t.Fatalf("no rule found for ruleId %s", issue.RuleID)
	}
	if foundRule.Severity != "MAJOR" {
		t.Errorf("expected rule severity MAJOR for MEDIUM vuln, got %s", foundRule.Severity)
	}
}

// ── TestGenerateOutputFile_WizCLI_LowVuln ────────────────────────────────────

func TestGenerateOutputFile_WizCLI_LowVuln(t *testing.T) {
	outputPath := t.TempDir()
	outputFileName := "sonarqube.json"

	vuln := makeWizVuln("Email Address", "LOW", "./code/data/users.csv")
	analysis := makeWizSecretsAnalysis(nil, nil, []types.HuskyCIVulnerability{vuln})

	if err := GenerateOutputFile(analysis, outputPath+"/", outputFileName); err != nil {
		t.Fatalf("GenerateOutputFile returned error: %v", err)
	}

	out := readSonarOutput(t, outputPath, outputFileName)

	if len(out.Issues) == 0 {
		t.Fatal("expected at least one issue in sonar output, got none")
	}
	issue := findIssueByTitle(out, "Email Address")
	if issue == nil {
		t.Fatalf("expected issue for 'Email Address', not found in: %+v", out.Issues)
	}

	var foundRule *SonarRule
	for i := range out.Rules {
		if out.Rules[i].ID == issue.RuleID {
			foundRule = &out.Rules[i]
			break
		}
	}
	if foundRule == nil {
		t.Fatalf("no rule found for ruleId %s", issue.RuleID)
	}
	if foundRule.Severity != "MINOR" {
		t.Errorf("expected rule severity MINOR for LOW vuln, got %s", foundRule.Severity)
	}
}

// ── TestGenerateOutputFile_WizCLI_NoVulns ────────────────────────────────────

func TestGenerateOutputFile_WizCLI_NoVulns(t *testing.T) {
	outputPath := t.TempDir()
	outputFileName := "sonarqube.json"

	analysis := makeWizSecretsAnalysis(nil, nil, nil)

	if err := GenerateOutputFile(analysis, outputPath+"/", outputFileName); err != nil {
		t.Fatalf("GenerateOutputFile returned error: %v", err)
	}

	out := readSonarOutput(t, outputPath, outputFileName)

	// Must produce valid JSON with empty (but non-nil) rules/issues arrays
	if out.Rules == nil {
		t.Error("expected Rules to be non-nil (even if empty)")
	}
	if out.Issues == nil {
		t.Error("expected Issues to be non-nil (even if empty)")
	}

	wizIssues := 0
	for _, issue := range out.Issues {
		if strings.Contains(issue.RuleID, "WizCLI") {
			wizIssues++
		}
	}
	if wizIssues != 0 {
		t.Errorf("expected no WizCLI issues, got %d", wizIssues)
	}
}

// ── TestGenerateOutputFile_WizCLI_AllSeverities ───────────────────────────────

func TestGenerateOutputFile_WizCLI_AllSeverities(t *testing.T) {
	outputPath := t.TempDir()
	outputFileName := "sonarqube.json"

	highVuln := makeWizVuln("CVE-2021-23337", "HIGH", "package-lock.json")
	medVuln := makeWizVuln("Generic API Key", "MEDIUM", "./code/src/client.go")
	lowVuln := makeWizVuln("Email Address", "LOW", "./code/data/users.csv")

	analysis := makeWizSecretsAnalysis(
		[]types.HuskyCIVulnerability{highVuln},
		[]types.HuskyCIVulnerability{medVuln},
		[]types.HuskyCIVulnerability{lowVuln},
	)

	if err := GenerateOutputFile(analysis, outputPath+"/", outputFileName); err != nil {
		t.Fatalf("GenerateOutputFile returned error: %v", err)
	}

	out := readSonarOutput(t, outputPath, outputFileName)

	if len(out.Issues) < 3 {
		t.Errorf("expected at least 3 issues (one per severity), got %d", len(out.Issues))
	}

	severityMap := map[string]string{
		"CVE-2021-23337": "BLOCKER",
		"Generic API Key": "MAJOR",
		"Email Address":  "MINOR",
	}

	for title, expectedRuleSev := range severityMap {
		issue := findIssueByTitle(out, title)
		if issue == nil {
			t.Errorf("expected issue for %q not found", title)
			continue
		}
		var rule *SonarRule
		for i := range out.Rules {
			if out.Rules[i].ID == issue.RuleID {
				rule = &out.Rules[i]
				break
			}
		}
		if rule == nil {
			t.Errorf("no rule found for issue %q (ruleId=%s)", title, issue.RuleID)
			continue
		}
		if rule.Severity != expectedRuleSev {
			t.Errorf("issue %q: expected rule severity %s, got %s", title, expectedRuleSev, rule.Severity)
		}
	}
}

// ── TestGenerateOutputFile_WizCLI_IacSast_HighVuln ─────────────────────────────

func TestGenerateOutputFile_WizCLI_IacSast_HighVuln(t *testing.T) {
	outputPath := t.TempDir()
	outputFileName := "sonarqube.json"

	vuln := makeWizVuln("S3 bucket without encryption", "HIGH", "./infra/main.tf")
	analysis := makeWizIacSastAnalysis([]types.HuskyCIVulnerability{vuln}, nil, nil)

	if err := GenerateOutputFile(analysis, outputPath+"/", outputFileName); err != nil {
		t.Fatalf("GenerateOutputFile returned error: %v", err)
	}

	out := readSonarOutput(t, outputPath, outputFileName)

	if len(out.Issues) == 0 {
		t.Fatal("expected at least one issue in sonar output, got none")
	}
	issue := findIssueByTitle(out, "S3 bucket without encryption")
	if issue == nil {
		t.Fatalf("expected issue for 'S3 bucket without encryption', not found in: %+v", out.Issues)
	}
	if issue.RuleID == "" {
		t.Error("expected non-empty ruleId")
	}
}

// ── TestGenerateOutputFile_WizCLI_IacSast_AllSeverities ────────────────────────

func TestGenerateOutputFile_WizCLI_IacSast_AllSeverities(t *testing.T) {
	outputPath := t.TempDir()
	outputFileName := "sonarqube.json"

	highVuln := makeWizVuln("S3 bucket without encryption", "HIGH", "./infra/main.tf")
	medVuln := makeWizVuln("IAM policy too permissive", "MEDIUM", "./infra/iam.tf")
	lowVuln := makeWizVuln("Missing tags on resource", "LOW", "./infra/tags.tf")

	analysis := makeWizIacSastAnalysis(
		[]types.HuskyCIVulnerability{highVuln},
		[]types.HuskyCIVulnerability{medVuln},
		[]types.HuskyCIVulnerability{lowVuln},
	)

	if err := GenerateOutputFile(analysis, outputPath+"/", outputFileName); err != nil {
		t.Fatalf("GenerateOutputFile returned error: %v", err)
	}

	out := readSonarOutput(t, outputPath, outputFileName)

	if len(out.Issues) < 3 {
		t.Errorf("expected at least 3 issues (one per severity), got %d", len(out.Issues))
	}

	severityMap := map[string]string{
		"S3 bucket without encryption":  "BLOCKER",
		"IAM policy too permissive":      "MAJOR",
		"Missing tags on resource":       "MINOR",
	}

	for title, expectedRuleSev := range severityMap {
		issue := findIssueByTitle(out, title)
		if issue == nil {
			t.Errorf("expected issue for %q not found", title)
			continue
		}
		var rule *SonarRule
		for i := range out.Rules {
			if out.Rules[i].ID == issue.RuleID {
				rule = &out.Rules[i]
				break
			}
		}
		if rule == nil {
			t.Errorf("no rule found for issue %q (ruleId=%s)", title, issue.RuleID)
			continue
		}
		if rule.Severity != expectedRuleSev {
			t.Errorf("issue %q: expected rule severity %s, got %s", title, expectedRuleSev, rule.Severity)
		}
	}
}

// ── TestGenerateOutputFile_WizCLI_Vulns_HighVuln ──────────────────────────────

func TestGenerateOutputFile_WizCLI_Vulns_HighVuln(t *testing.T) {
	outputPath := t.TempDir()
	outputFileName := "sonarqube.json"

	vuln := makeWizVuln("CVE-2024-0001 in library foo", "HIGH", "./code/package-lock.json")
	analysis := makeWizVulnsAnalysis([]types.HuskyCIVulnerability{vuln}, nil, nil)

	if err := GenerateOutputFile(analysis, outputPath+"/", outputFileName); err != nil {
		t.Fatalf("GenerateOutputFile returned error: %v", err)
	}

	out := readSonarOutput(t, outputPath, outputFileName)

	if len(out.Issues) == 0 {
		t.Fatal("expected at least one issue in sonar output, got none")
	}
	issue := findIssueByTitle(out, "CVE-2024-0001")
	if issue == nil {
		t.Fatalf("expected issue for 'CVE-2024-0001', not found in: %+v", out.Issues)
	}
	if issue.RuleID == "" {
		t.Error("expected non-empty ruleId")
	}
}

// ── TestGenerateOutputFile_WizCLI_Vulns_AllSeverities ──────────────────────────

func TestGenerateOutputFile_WizCLI_Vulns_AllSeverities(t *testing.T) {
	outputPath := t.TempDir()
	outputFileName := "sonarqube.json"

	highVuln := makeWizVuln("CVE-2024-0001 in library foo", "HIGH", "./code/package-lock.json")
	medVuln := makeWizVuln("CVE-2023-9999 in library bar", "MEDIUM", "./code/yarn.lock")
	lowVuln := makeWizVuln("CVE-2022-5555 in library baz", "LOW", "./code/requirements.txt")

	analysis := makeWizVulnsAnalysis(
		[]types.HuskyCIVulnerability{highVuln},
		[]types.HuskyCIVulnerability{medVuln},
		[]types.HuskyCIVulnerability{lowVuln},
	)

	if err := GenerateOutputFile(analysis, outputPath+"/", outputFileName); err != nil {
		t.Fatalf("GenerateOutputFile returned error: %v", err)
	}

	out := readSonarOutput(t, outputPath, outputFileName)

	if len(out.Issues) < 3 {
		t.Errorf("expected at least 3 issues (one per severity), got %d", len(out.Issues))
	}

	severityMap := map[string]string{
		"CVE-2024-0001": "BLOCKER",
		"CVE-2023-9999": "MAJOR",
		"CVE-2022-5555": "MINOR",
	}

	for title, expectedRuleSev := range severityMap {
		issue := findIssueByTitle(out, title)
		if issue == nil {
			t.Errorf("expected issue for %q not found", title)
			continue
		}
		var rule *SonarRule
		for i := range out.Rules {
			if out.Rules[i].ID == issue.RuleID {
				rule = &out.Rules[i]
				break
			}
		}
		if rule == nil {
			t.Errorf("no rule found for issue %q (ruleId=%s)", title, issue.RuleID)
			continue
		}
		if rule.Severity != expectedRuleSev {
			t.Errorf("issue %q: expected rule severity %s, got %s", title, expectedRuleSev, rule.Severity)
		}
	}
}

// ── TestGenerateOutputFile_WizCLI_Secrets_NoSecVulns_PromotedToMedium ────────

func TestGenerateOutputFile_WizCLI_Secrets_NoSecVulns_PromotedToMedium(t *testing.T) {
	outputPath := t.TempDir()
	outputFileName := "sonarqube.json"

	// Wiz classifies secrets as INFORMATIONAL → they land in NoSecVulns
	infoVuln := makeWizVuln("AWS Access Key ID detected", "INFORMATIONAL", "./code/config/secrets.js")
	analysis := makeWizSecretsAnalysisWithNoSec(nil, nil, nil, []types.HuskyCIVulnerability{infoVuln})

	if err := GenerateOutputFile(analysis, outputPath+"/", outputFileName); err != nil {
		t.Fatalf("GenerateOutputFile returned error: %v", err)
	}

	out := readSonarOutput(t, outputPath, outputFileName)

	if len(out.Issues) == 0 {
		t.Fatal("expected at least one issue (promoted NoSecVuln), got none")
	}

	issue := findIssueByTitle(out, "AWS Access Key ID detected")
	if issue == nil {
		t.Fatalf("expected issue for 'AWS Access Key ID detected', not found in: %+v", out.Issues)
	}

	// Verify the rule was created with MAJOR severity (MEDIUM → MAJOR in SonarQube format)
	var foundRule *SonarRule
	for i := range out.Rules {
		if out.Rules[i].ID == issue.RuleID {
			foundRule = &out.Rules[i]
			break
		}
	}
	if foundRule == nil {
		t.Fatalf("no rule found for ruleId %s", issue.RuleID)
	}
	if foundRule.Severity != "MAJOR" {
		t.Errorf("expected promoted NoSecVuln to have severity MAJOR, got %s", foundRule.Severity)
	}

	// Verify impact severity is also promoted
	if len(foundRule.Impacts) == 0 {
		t.Fatal("expected at least one impact on the rule")
	}
	if foundRule.Impacts[0].Severity != "MEDIUM" {
		t.Errorf("expected impact severity MEDIUM for promoted NoSecVuln, got %s", foundRule.Impacts[0].Severity)
	}
}

// ── TestGenerateOutputFile_WizCLI_Secrets_NoSecVulns_DoesNotAffectOriginalObject ──

func TestGenerateOutputFile_WizCLI_Secrets_NoSecVulns_DoesNotAffectOriginalObject(t *testing.T) {
	outputPath := t.TempDir()
	outputFileName := "sonarqube.json"

	// The original vuln object must retain INFORMATIONAL severity (promotion is copy-on-write)
	originalVuln := makeWizVuln("Private Key detected", "INFORMATIONAL", "./code/config/keys.pem")
	analysis := makeWizSecretsAnalysisWithNoSec(nil, nil, nil, []types.HuskyCIVulnerability{originalVuln})

	if err := GenerateOutputFile(analysis, outputPath+"/", outputFileName); err != nil {
		t.Fatalf("GenerateOutputFile returned error: %v", err)
	}

	// Verify original vuln was NOT mutated
	if originalVuln.Severity != "INFORMATIONAL" {
		t.Errorf("original NoSecVuln was mutated! Severity=%s, expected INFORMATIONAL", originalVuln.Severity)
	}
}

// ── TestGenerateOutputFile_WizCLI_Secrets_NoSecVulns_DeltaOnly ─────────────────

func TestGenerateOutputFile_WizCLI_Secrets_NoSecVulns_DeltaOnly(t *testing.T) {
	outputPath := t.TempDir()
	outputFileName := "sonarqube.json"

	// Gitleaks already found the AWS secret at this file+line
	gitleaksVuln := makeWizVuln("AWS Access Key ID detected", "HIGH", "./code/config/settings.py")
	gitleaksVuln.Line = "42"

	// WizCLI NoSecVuln at the SAME file+line → should be SKIPPED (duplicate)
	wizDuplicate := makeWizVuln("AWS Access Key ID detected", "INFORMATIONAL", "./code/config/settings.py")
	wizDuplicate.Line = "42"

	// WizCLI NoSecVuln at a DIFFERENT file+line → should be PROMOTED (delta)
	wizDelta := makeWizVuln("Database URL with embedded password", "INFORMATIONAL", "./code/config/db.js")
	wizDelta.Line = "15"

	analysis := types.Analysis{
		HuskyCIResults: types.HuskyCIResults{
			GenericResults: types.GenericResults{
				HuskyCIGitleaksOutput: types.HuskyCISecurityTestOutput{
					HighVulns: []types.HuskyCIVulnerability{gitleaksVuln},
				},
				HuskyCIWizCLISecretsOutput: types.HuskyCISecurityTestOutput{
					NoSecVulns: []types.HuskyCIVulnerability{wizDuplicate, wizDelta},
				},
			},
		},
	}

	if err := GenerateOutputFile(analysis, outputPath+"/", outputFileName); err != nil {
		t.Fatalf("GenerateOutputFile returned error: %v", err)
	}

	out := readSonarOutput(t, outputPath, outputFileName)

	// Count WizCLI issues — should have Gitleaks AWS + promoted WizCLI delta, but NOT duplicate
	wizIssues := 0
	for _, issue := range out.Issues {
		if strings.Contains(issue.RuleID, "Database") {
			wizIssues++
		}
	}
	if wizIssues != 1 {
		t.Errorf("expected exactly 1 promoted WizCLI delta issue, got %d", wizIssues)
	}

	// Verify the DUPLICATE (same file+line as Gitleaks) was NOT promoted
	dupIssue := findIssueByTitle(out, "AWS Access Key ID detected")
	if dupIssue == nil {
		t.Fatal("expected Gitleaks AWS issue to exist (from Gitleaks, not WizCLI)")
	}
	// The AWS issue should come from Gitleaks (BLOCKER severity), not from promoted WizCLI (MAJOR)
	for _, rule := range out.Rules {
		if rule.ID == dupIssue.RuleID && rule.Severity == "MAJOR" && rule.EngineID == "huskyCI/WizCLI" {
			t.Error("found promoted WizCLI duplicate for AWS key — should have been skipped")
		}
	}

	// Verify the DELTA finding was promoted to MAJOR
	deltaIssue := findIssueByTitle(out, "Database URL with embedded password")
	if deltaIssue == nil {
		t.Fatal("expected promoted WizCLI delta issue for Database URL to exist")
	}
	var deltaRule *SonarRule
	for i := range out.Rules {
		if out.Rules[i].ID == deltaIssue.RuleID {
			deltaRule = &out.Rules[i]
			break
		}
	}
	if deltaRule == nil {
		t.Fatalf("no rule found for delta issue (ruleId=%s)", deltaIssue.RuleID)
	}
	if deltaRule.Severity != "MAJOR" {
		t.Errorf("expected delta NoSecVuln promoted to MAJOR, got %s", deltaRule.Severity)
	}
	if deltaRule.EngineID != "huskyCI/WizCLI" {
		t.Errorf("expected delta engine ID huskyCI/WizCLI, got %s", deltaRule.EngineID)
	}
}
