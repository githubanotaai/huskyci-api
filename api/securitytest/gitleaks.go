// Copyright 2019 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securitytest

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/githubanotaai/huskyci-api/api/log"
	"github.com/githubanotaai/huskyci-api/api/types"
	"github.com/githubanotaai/huskyci-api/api/util"
)

// GitleaksOutput is the struct that holds all data from Gitleaks output.
type GitleaksOutput []GitLeaksIssue

// GitLeaksIssue holds gitleaks/gitleaks v8 JSON findings; v7 fields are preserved for legacy cOutput.
// See https://github.com/gitleaks/gitleaks/blob/master/report/finding.go
type GitLeaksIssue struct {
	RuleID        string   `json:"RuleID"`
	Description   string   `json:"Description"`
	StartLine     int      `json:"StartLine"`
	EndLine       int      `json:"EndLine"`
	StartColumn   int      `json:"StartColumn"`
	EndColumn     int      `json:"EndColumn"`
	Match         string   `json:"Match"`
	Secret        string   `json:"Secret"`
	File          string   `json:"File"`
	SymlinkFile   string   `json:"SymlinkFile"`
	Commit        string   `json:"Commit"`
	Entropy       float64  `json:"Entropy"`
	Author        string   `json:"Author"`
	Email         string   `json:"Email"`
	Date          string   `json:"Date"`
	Message       string   `json:"Message"`
	Tags          []string `json:"Tags"`
	Fingerprint   string   `json:"Fingerprint"`
	LineContentV8 string   `json:"Line"`

	// v7 legacy (gitleaks v6/v7 report)
	Offender      string `json:"offender"`
	Info          string `json:"info"`
	CommitMessage string `json:"commitMsg"`
	Repository    string `json:"repo"`
	RuleV7        string `json:"rule"`
	SeverityV7    string `json:"severity"`
	LineV7        string `json:"line"`
	TagsV7        string `json:"tags"`
}

func (i GitLeaksIssue) effectiveRule() string {
	if i.RuleID != "" {
		return i.RuleID
	}
	return i.RuleV7
}

func (i GitLeaksIssue) lineNumberString() string {
	if i.StartLine > 0 {
		return strconv.Itoa(i.StartLine)
	}
	if n, err := strconv.Atoi(strings.TrimSpace(i.LineV7)); err == nil && n > 0 {
		return strconv.Itoa(n)
	}
	return ""
}

func (i GitLeaksIssue) codeSnippet() string {
	if i.Match != "" {
		return i.Match
	}
	if i.LineContentV8 != "" {
		return i.LineContentV8
	}
	return i.LineV7
}

func analyseGitleaks(gitleaksScan *SecTestScanInfo) error {
	gitLeaksOutput := GitleaksOutput{}
	gitleaksScan.FinalOutput = gitLeaksOutput

	// nil cOutput states that no Issues were found.
	if gitleaksScan.Container.COutput == "" {
		gitleaksScan.prepareContainerAfterScan()
		return nil
	}

	// if gitleaks timeout, a warning will be generated as a low vuln
	gitleaksTimeout := strings.Contains(gitleaksScan.Container.COutput, "ERROR_TIMEOUT_GITLEAKS")
	if gitleaksTimeout {
		gitleaksScan.GitleaksTimeout = true
		gitleaksScan.prepareGitleaksVulns()
		gitleaksScan.prepareContainerAfterScan()
		return nil
	}

	gitleaksErrorRunning := strings.Contains(gitleaksScan.Container.COutput, "ERROR_RUNNING_GITLEAKS")
	if gitleaksErrorRunning {
		gitleaksScan.GitleaksErrorRunning = true
		gitleaksScan.prepareGitleaksVulns()
		gitleaksScan.prepareContainerAfterScan()
		return nil
	}

	// Unmarshall rawOutput into finalOutput, that is a GitleaksOutput struct.
	if err := json.Unmarshal([]byte(gitleaksScan.Container.COutput), &gitLeaksOutput); err != nil {
		log.Error("analyzeGitleaks", "GITLEAKS", 1038, gitleaksScan.Container.COutput, err)
		gitleaksScan.ErrorFound = util.HandleScanError(gitleaksScan.Container.COutput, err)
		gitleaksScan.prepareContainerAfterScan()
		return gitleaksScan.ErrorFound
	}
	gitleaksScan.FinalOutput = gitLeaksOutput

	// check results and prepare all vulnerabilities found
	gitleaksScan.prepareGitleaksVulns()
	gitleaksScan.prepareContainerAfterScan()
	return nil
}

func (gitleaksScan *SecTestScanInfo) prepareGitleaksVulns() {

	huskyCIgitleaksResults := types.HuskyCISecurityTestOutput{}
	gitleaksOutput := gitleaksScan.FinalOutput.(GitleaksOutput)

	if gitleaksScan.GitleaksTimeout {
		gitleaksVuln := types.HuskyCIVulnerability{}
		gitleaksVuln.Language = "Generic"
		gitleaksVuln.SecurityTool = "Gitleaks"
		gitleaksVuln.Severity = "low"
		gitleaksVuln.Title = "Too big project for Gitleaks scan"
		gitleaksVuln.Details = "It looks like your project is too big and huskyCI was not able to run Gitleaks."

		gitleaksScan.Vulnerabilities.LowVulns = append(gitleaksScan.Vulnerabilities.LowVulns, gitleaksVuln)
		return
	}

	if gitleaksScan.GitleaksErrorRunning {
		gitleaksVuln := types.HuskyCIVulnerability{}
		gitleaksVuln.Language = "Generic"
		gitleaksVuln.SecurityTool = "Gitleaks"
		gitleaksVuln.Severity = "low"
		gitleaksVuln.Title = "Gitleaks internal error"
		gitleaksVuln.Details = "Internal error running Gitleaks."

		gitleaksScan.Vulnerabilities.LowVulns = append(gitleaksScan.Vulnerabilities.LowVulns, gitleaksVuln)
		return
	}

	for _, issue := range gitleaksOutput {
		// dependencies issues will not checked at this moment by huskyCI
		if strings.Contains(issue.File, "vendor/") || strings.Contains(issue.File, "node_modules/") {
			continue
		}

		rule := issue.effectiveRule()
		gitleaksVuln := types.HuskyCIVulnerability{}
		gitleaksVuln.SecurityTool = "GitLeaks"
		gitleaksVuln.File = issue.File
		gitleaksVuln.Code = issue.codeSnippet()
		gitleaksVuln.Line = issue.lineNumberString()
		if issue.Description != "" {
			gitleaksVuln.Details = issue.Description
		} else if issue.Info != "" {
			gitleaksVuln.Details = issue.Info
		}
		gitleaksVuln.Title = "Hard Coded " + rule + " in: " + issue.File

		bucket := gitleaksBucketSeverity(rule)
		gitleaksVuln.Severity = strings.ToLower(bucket)

		switch bucket {
		case "LOW":
			huskyCIgitleaksResults.LowVulns = append(huskyCIgitleaksResults.LowVulns, gitleaksVuln)
		case "MEDIUM":
			huskyCIgitleaksResults.MediumVulns = append(huskyCIgitleaksResults.MediumVulns, gitleaksVuln)
		case "HIGH":
			huskyCIgitleaksResults.HighVulns = append(huskyCIgitleaksResults.HighVulns, gitleaksVuln)
		}
	}

	gitleaksScan.Vulnerabilities = huskyCIgitleaksResults
}
