package analysis

import (
	"testing"

	"github.com/githubanotaai/huskyci-api/client/types"
)

func TestPrintSTDOUTOutputPnpmAudit(t *testing.T) {
	output := types.HuskyCISecurityTestOutput{
		HighVulns: []types.HuskyCIVulnerability{
			{
				Language:       "JavaScript",
				SecurityTool:   "PnpmAudit",
				Severity:       "high",
				File:           "pnpm-lock.yaml",
				Code:           "lodash",
				Title:          "Vulnerable Dependency: lodash <4.17.21 (Command Injection)",
				VunerableBelow: "<4.17.21",
				Version:        "Finding 0:\n  Version: 4.17.20\n  Path: .>lodash\n",
				Details:        "GHSA: GHSA-35jh-r3h4-6jhm\nCWE: CWE-77\nURL: https://...",
			},
		},
	}
	// Verify no panic on valid output
	printSTDOUTOutputPnpmAudit(output.HighVulns)
}

func TestPrintSTDOUTOutputPnpmAuditEmpty(t *testing.T) {
	// Verify no panic on empty output
	printSTDOUTOutputPnpmAudit(nil)
}
