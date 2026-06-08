// Copyright 2019 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
	ID                 int           `json:"id"`
	Title              string        `json:"title"`
	ModuleName         string        `json:"module_name"`
	VulnerableVersions string        `json:"vulnerable_versions"`
	PatchedVersions    string        `json:"patched_versions"`
	Severity           string        `json:"severity"`
	CWE                string        `json:"cwe"`
	GithubAdvisoryID   string        `json:"github_advisory_id"`
	URL                string        `json:"url"`
	Findings           []PnpmFinding `json:"findings"`
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
