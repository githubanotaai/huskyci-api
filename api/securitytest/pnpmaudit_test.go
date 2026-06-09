package securitytest

import (
	"strings"
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
	if vuln.Language != "JavaScript" {
		t.Errorf("expected language JavaScript, got %s", vuln.Language)
	}
}

func TestAnalyzePnpmauditEmpty(t *testing.T) {
	// Empty COutput (another lockfile present, silent skip — e.g. npm repo)
	scan := &SecTestScanInfo{
		Container: types.Container{
			COutput: "",
		},
	}

	err := analyzePnpmaudit(scan)
	if err != nil {
		t.Fatalf("analyzePnpmaudit returned error for empty output: %v", err)
	}

	if len(scan.Vulnerabilities.HighVulns) != 0 {
		t.Errorf("expected 0 vulns for empty output, got high=%d", len(scan.Vulnerabilities.HighVulns))
	}
	if len(scan.Vulnerabilities.MediumVulns) != 0 {
		t.Errorf("expected 0 vulns for empty output, got medium=%d", len(scan.Vulnerabilities.MediumVulns))
	}
	if len(scan.Vulnerabilities.LowVulns) != 0 {
		t.Errorf("expected 0 vulns for empty output, got low=%d", len(scan.Vulnerabilities.LowVulns))
	}
}

func TestAnalyzePnpmauditModerateSeverity(t *testing.T) {
	// pnpm audit output with moderate severity
	pnpmOutput := `{"advisories":{"1108258":{"findings":[{"version":"4.17.20","paths":[".>lodash"],"dev":false,"optional":false,"bundled":false}],"id":1108258,"title":"Regular Expression Denial of Service (ReDoS) in lodash","module_name":"lodash","vulnerable_versions":">=4.0.0 <4.17.21","patched_versions":">=4.17.21","severity":"moderate","cwe":"CWE-400, CWE-1333","github_advisory_id":"GHSA-29mw-wpgm-hmr9","url":"https://github.com/advisories/GHSA-29mw-wpgm-hmr9"}},"metadata":{"vulnerabilities":{"info":0,"low":0,"moderate":1,"high":0,"critical":0},"dependencies":1,"devDependencies":0,"optionalDependencies":0,"totalDependencies":1}}`

	scan := &SecTestScanInfo{
		Container: types.Container{
			COutput: pnpmOutput,
		},
	}

	err := analyzePnpmaudit(scan)
	if err != nil {
		t.Fatalf("analyzePnpmaudit returned error: %v", err)
	}

	if len(scan.Vulnerabilities.MediumVulns) != 1 {
		t.Errorf("expected 1 medium vuln, got %d", len(scan.Vulnerabilities.MediumVulns))
	}

	vuln := scan.Vulnerabilities.MediumVulns[0]
	if vuln.Severity != "medium" {
		t.Errorf("expected severity medium, got %s", vuln.Severity)
	}
}

func TestAnalyzePnpmauditMultipleAdvisories(t *testing.T) {
	// Two advisories: one high, one moderate
	pnpmOutput := `{"advisories":{"1106913":{"findings":[{"version":"4.17.20","paths":[".>lodash"],"dev":false,"optional":false,"bundled":false}],"id":1106913,"title":"Command Injection in lodash","module_name":"lodash","vulnerable_versions":"<4.17.21","patched_versions":">=4.17.21","severity":"high","cwe":"CWE-77, CWE-94","github_advisory_id":"GHSA-35jh-r3h4-6jhm","url":"https://github.com/advisories/GHSA-35jh-r3h4-6jhm"},"1108258":{"findings":[{"version":"4.17.20","paths":[".>lodash"],"dev":false,"optional":false,"bundled":false}],"id":1108258,"title":"ReDoS in lodash","module_name":"lodash","vulnerable_versions":">=4.0.0 <4.17.21","patched_versions":">=4.17.21","severity":"moderate","cwe":"CWE-400","github_advisory_id":"GHSA-29mw-wpgm-hmr9","url":"https://github.com/advisories/GHSA-29mw-wpgm-hmr9"}},"metadata":{"vulnerabilities":{"info":0,"low":0,"moderate":1,"high":1,"critical":0},"dependencies":1}}`

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
	if len(scan.Vulnerabilities.MediumVulns) != 1 {
		t.Errorf("expected 1 medium vuln, got %d", len(scan.Vulnerabilities.MediumVulns))
	}
}

func TestAnalyzePnpmauditLockfileNotFound(t *testing.T) {
	// ERROR_PNPM_LOCK_NOT_FOUND — no lockfile at all in the repo
	scan := &SecTestScanInfo{
		Container: types.Container{
			COutput: "ERROR_PNPM_LOCK_NOT_FOUND",
		},
	}

	err := analyzePnpmaudit(scan)
	if err != nil {
		t.Fatalf("analyzePnpmaudit returned error: %v", err)
	}

	if !scan.PnpmLockNotFound {
		t.Error("expected PnpmLockNotFound to be true")
	}

	if len(scan.Vulnerabilities.LowVulns) != 1 {
		t.Errorf("expected 1 low vuln for lockfile not found, got %d", len(scan.Vulnerabilities.LowVulns))
	}

	vuln := scan.Vulnerabilities.LowVulns[0]
	if vuln.Severity != "low" {
		t.Errorf("expected severity low, got %s", vuln.Severity)
	}
	if !strings.Contains(vuln.Title, "pnpm-lock.yaml") {
		t.Errorf("expected title to mention pnpm-lock.yaml, got: %s", vuln.Title)
	}
}
