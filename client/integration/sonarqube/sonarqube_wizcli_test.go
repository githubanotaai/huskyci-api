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

func makeWizAnalysis(high, medium, low []types.HuskyCIVulnerability) types.Analysis {
	return types.Analysis{
		HuskyCIResults: types.HuskyCIResults{
			GenericResults: types.GenericResults{
				HuskyCIWizCLIOutput: types.HuskyCISecurityTestOutput{
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
	analysis := makeWizAnalysis([]types.HuskyCIVulnerability{vuln}, nil, nil)

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
	analysis := makeWizAnalysis(nil, []types.HuskyCIVulnerability{vuln}, nil)

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
	analysis := makeWizAnalysis(nil, nil, []types.HuskyCIVulnerability{vuln})

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

	analysis := makeWizAnalysis(nil, nil, nil)

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

	analysis := makeWizAnalysis(
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
