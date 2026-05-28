// Copyright 2019 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package analysis

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"testing"
	"time"

	"github.com/githubanotaai/huskyci-api/client/types"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = orig
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	_ = r.Close()
	return buf.String()
}

// #region agent log
const agentDebugLogPathA1ae76 = "/Users/guilherme.ferreira/Gits/k8s-infrastructure-live/.cursor/debug-a1ae76.log"

func testAgentDebugLog(t *testing.T, hypothesisID, message string, data map[string]any) {
	t.Helper()
	payload := map[string]any{
		"sessionId":    "a1ae76",
		"hypothesisId": hypothesisID,
		"location":     "output_wiz_test.go",
		"message":      message,
		"data":         data,
		"timestamp":    time.Now().UnixMilli(),
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return
	}
	f, err := os.OpenFile(agentDebugLogPathA1ae76, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Logf("debug log skip: %v", err)
		return
	}
	_, _ = f.Write(append(b, '\n'))
	_ = f.Close()
}

// #endregion

func TestShortImageName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"939030204144.dkr.ecr.us-east-1.amazonaws.com/huskyci-wiz", "huskyci-wiz"},
		{"939030204144.dkr.ecr.us-east-1.amazonaws.com/huskyci-gitleaks", "huskyci-gitleaks"},
		{"huskyci/safety", "huskyci/safety"},
		{"gosec", "gosec"},
		{"123456789012.dkr.ecr.eu-west-1.amazonaws.com/my-tool", "my-tool"},
	}
	for _, tc := range tests {
		got := shortImageName(tc.input)
		if got != tc.expected {
			t.Errorf("shortImageName(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestPrintSTDOUTOutput_IncludesWizCLIDetailsGroup(t *testing.T) {
	types.FoundVuln = false
	types.FoundInfo = false
	types.IsJSONoutput = false

	analysis := types.Analysis{
		Containers: []types.Container{
			{
				SecurityTest: types.SecurityTest{Name: "wizcli_secrets", Image: "939030204144.dkr.ecr.us-east-1.amazonaws.com/huskyci-wiz", ImageTag: "f793155-amd64"},
			},
		},
		HuskyCIResults: types.HuskyCIResults{
			GenericResults: types.GenericResults{
				HuskyCIWizCLISecretsOutput: types.HuskyCISecurityTestOutput{
					MediumVulns: []types.HuskyCIVulnerability{
						{Title: "Secret in env", SecurityTool: "WizCLI", Severity: "MEDIUM", Details: "mock", File: "x.env"},
					},
				},
				HuskyCIIacSastOutput: types.HuskyCISecurityTestOutput{
					HighVulns: []types.HuskyCIVulnerability{
						{
							Title:        "S3 bucket without encryption",
							Language:     "HCL",
							SecurityTool: "WizCLI",
							Severity:     "HIGH",
							Details:      "Enable server-side encryption",
							File:         "main.tf",
							Line:         "15",
							Code:         "aws_s3_bucket.example",
						},
					},
					LowVulns: []types.HuskyCIVulnerability{
						{
							Title:        "Missing tags on resource",
							Language:     "HCL",
							SecurityTool: "WizCLI",
							Severity:     "LOW",
							Details:      "Add tags for cost tracking",
							File:         "main.tf",
							Line:         "22",
						},
					},
				},
				HuskyCIWizCLIVulnsOutput: types.HuskyCISecurityTestOutput{
					HighVulns: []types.HuskyCIVulnerability{
						{
							Title:        "CVE-2024-0001 in library foo",
							Language:     "JavaScript",
							SecurityTool: "WizCLI",
							Severity:     "HIGH",
							Details:      "Upgrade dependency",
							File:         "package-lock.json",
							Line:         "42",
							Code:         "foo@1.0.0",
						},
					},
				},
			},
		},
	}

	// #region agent log
	secrets := analysis.HuskyCIResults.GenericResults.HuskyCIWizCLISecretsOutput
	vulns := analysis.HuskyCIResults.GenericResults.HuskyCIWizCLIVulnsOutput
	testAgentDebugLog(t, "H1", "fixture wiz counts", map[string]any{
		"secrets_high": len(secrets.HighVulns), "secrets_medium": len(secrets.MediumVulns),
		"vulns_high": len(vulns.HighVulns), "vulns_medium": len(vulns.MediumVulns),
	})
	// #endregion

	out := captureStdout(t, func() {
		prepareAllSummary(analysis)
		printSTDOUTOutput(analysis)
	})

	if !bytes.Contains([]byte(out), []byte("::group::Generic - Wiz CLI (Secrets)")) {
		t.Fatalf("expected Wiz CLI Secrets collapsible group in stdout, got excerpt:\n%s", truncate(out, 2000))
	}
	if !bytes.Contains([]byte(out), []byte("::group::Generic - Wiz CLI (IaC+SAST)")) {
		t.Fatalf("expected Wiz CLI IaC+SAST collapsible group in stdout, got excerpt:\n%s", truncate(out, 2000))
	}
	if !bytes.Contains([]byte(out), []byte("::group::Generic - Wiz CLI (Vulns)")) {
		t.Fatalf("expected Wiz CLI Vulns collapsible group in stdout, got excerpt:\n%s", truncate(out, 2000))
	}
	if !bytes.Contains([]byte(out), []byte("[HUSKYCI][SUMMARY] Generic -> huskyci-wiz:f793155-amd64")) {
		t.Fatalf("expected Wiz summary line with short image ref 'huskyci-wiz:f793155-amd64', got excerpt:\n%s", truncate(out, 2000))
	}
	// Verify ECR registry prefix is NOT present in output
	if bytes.Contains([]byte(out), []byte("939030204144.dkr.ecr.us-east-1.amazonaws.com")) {
		t.Fatalf("ECR registry prefix should be stripped from version string, got excerpt:\n%s", truncate(out, 2000))
	}
	if !bytes.Contains([]byte(out), []byte("CVE-2024-0001")) {
		t.Fatalf("expected Wiz finding title in stdout")
	}
	if !bytes.Contains([]byte(out), []byte("S3 bucket without encryption")) {
		t.Fatalf("expected IaC+SAST finding title in stdout")
	}
	if !bytes.Contains([]byte(out), []byte("Missing tags on resource")) {
		t.Fatalf("expected IaC+SAST low finding title in stdout")
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
