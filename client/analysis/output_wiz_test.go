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

func TestPrintSTDOUTOutput_IncludesWizCLIDetailsGroup(t *testing.T) {
	types.FoundVuln = false
	types.FoundInfo = false
	types.IsJSONoutput = false

	analysis := types.Analysis{
		Containers: []types.Container{
			{
				SecurityTest: types.SecurityTest{Name: "wizcli", Image: "ecr/huskyci-wiz", ImageTag: "latest-amd64"},
			},
		},
		HuskyCIResults: types.HuskyCIResults{
			GenericResults: types.GenericResults{
				HuskyCIWizCLIOutput: types.HuskyCISecurityTestOutput{
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
					MediumVulns: []types.HuskyCIVulnerability{
						{Title: "Secret in env", SecurityTool: "WizCLI", Severity: "MEDIUM", Details: "mock", File: "x.env"},
					},
				},
			},
		},
	}

	// #region agent log
	wiz := analysis.HuskyCIResults.GenericResults.HuskyCIWizCLIOutput
	testAgentDebugLog(t, "H1", "fixture wiz counts", map[string]any{
		"high": len(wiz.HighVulns), "medium": len(wiz.MediumVulns), "low": len(wiz.LowVulns),
	})
	// #endregion

	out := captureStdout(t, func() {
		prepareAllSummary(analysis)
		printSTDOUTOutput(analysis)
	})

	if !bytes.Contains([]byte(out), []byte("::group::Generic - Wiz CLI Details")) {
		t.Fatalf("expected Wiz CLI collapsible group in stdout, got excerpt:\n%s", truncate(out, 2000))
	}
	if !bytes.Contains([]byte(out), []byte("[HUSKYCI][SUMMARY] Generic ->")) || !bytes.Contains([]byte(out), []byte("huskyci-wiz")) {
		t.Fatalf("expected Wiz summary line with image ref")
	}
	if !bytes.Contains([]byte(out), []byte("CVE-2024-0001")) {
		t.Fatalf("expected Wiz finding title in stdout")
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
