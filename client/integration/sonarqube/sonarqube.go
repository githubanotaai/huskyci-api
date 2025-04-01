// Copyright 2019 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sonarqube

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/githubanotaai/huskyci-api/client/types"
	"github.com/githubanotaai/huskyci-api/client/util"
)

const goContainerBasePath = `/go/src/code/`
const placeholderFileName = "huskyCI_Placeholder_File"
const placeholderFileText = `
Placeholder file indicating that no file was associated with this vulnerability.
This usually means that the vulnerability is related to a missing file
or is not associated with any specific file, i.e.: vulnerable dependency versions.
`

// GenerateOutputFile prints the analysis output in a JSON format
func GenerateOutputFile(analysis types.Analysis, outputPath, outputFileName string) error {

	allVulns := make([]types.HuskyCIVulnerability, 0)

	// gosec
	allVulns = append(allVulns, analysis.HuskyCIResults.GoResults.HuskyCIGosecOutput.LowVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.GoResults.HuskyCIGosecOutput.MediumVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.GoResults.HuskyCIGosecOutput.HighVulns...)

	// bandit
	allVulns = append(allVulns, analysis.HuskyCIResults.PythonResults.HuskyCIBanditOutput.NoSecVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.PythonResults.HuskyCIBanditOutput.LowVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.PythonResults.HuskyCIBanditOutput.MediumVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.PythonResults.HuskyCIBanditOutput.HighVulns...)

	// safety
	allVulns = append(allVulns, analysis.HuskyCIResults.PythonResults.HuskyCISafetyOutput.LowVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.PythonResults.HuskyCISafetyOutput.MediumVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.PythonResults.HuskyCISafetyOutput.HighVulns...)

	// brakeman
	allVulns = append(allVulns, analysis.HuskyCIResults.RubyResults.HuskyCIBrakemanOutput.LowVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.RubyResults.HuskyCIBrakemanOutput.MediumVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.RubyResults.HuskyCIBrakemanOutput.HighVulns...)

	// npmaudit
	allVulns = append(allVulns, analysis.HuskyCIResults.JavaScriptResults.HuskyCINpmAuditOutput.LowVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.JavaScriptResults.HuskyCINpmAuditOutput.MediumVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.JavaScriptResults.HuskyCINpmAuditOutput.HighVulns...)

	// yarnaudit
	allVulns = append(allVulns, analysis.HuskyCIResults.JavaScriptResults.HuskyCIYarnAuditOutput.LowVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.JavaScriptResults.HuskyCIYarnAuditOutput.MediumVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.JavaScriptResults.HuskyCIYarnAuditOutput.HighVulns...)

	// gitleaks
	allVulns = append(allVulns, analysis.HuskyCIResults.GenericResults.HuskyCIGitleaksOutput.LowVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.GenericResults.HuskyCIGitleaksOutput.MediumVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.GenericResults.HuskyCIGitleaksOutput.HighVulns...)

	// spotbugs
	allVulns = append(allVulns, analysis.HuskyCIResults.JavaResults.HuskyCISpotBugsOutput.LowVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.JavaResults.HuskyCISpotBugsOutput.MediumVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.JavaResults.HuskyCISpotBugsOutput.HighVulns...)

	var sonarOutput HuskyCISonarOutput
	sonarOutput.Rules = make([]SonarRule, 0)
	sonarOutput.Issues = make([]SonarIssue, 0)

	ruleMap := make(map[string]bool) // Track unique rule IDs

	// Generate rules and issues
	for _, vuln := range allVulns {
		ruleID := generateRuleID(&vuln)

		// Add the rule only if it hasn't been added before
		if !ruleMap[ruleID] {
			rule := SonarRule{
				ID:                 ruleID,
				Name:               vuln.Title,
				Description:        getDescription(vuln),
				EngineID:           "huskyCI/" + vuln.SecurityTool,
				CleanCodeAttribute: "TRUSTWORTHY",
				Type:               "VULNERABILITY",
				Severity:           mapRuleSeverity(vuln.Severity),
				Impacts: []SonarImpact{
					{SoftwareQuality: "SECURITY", Severity: mapImpactSeverity(vuln.Severity)},
				},
			}
			sonarOutput.Rules = append(sonarOutput.Rules, rule)
			ruleMap[ruleID] = true // Mark this rule ID as added
		}

		// Create an issue for the vulnerability
		issue := SonarIssue{
			RuleID: ruleID,
			PrimaryLocation: SonarLocation{
				Message:  getDescription(vuln),
				FilePath: getFilePath(vuln, outputPath),
				TextRange: SonarTextRange{
					StartLine: getStartLine(vuln.Line),
				},
			},
		}

		// Add the issue to the output
		sonarOutput.Issues = append(sonarOutput.Issues, issue)
	}

	// Serialize the output to JSON through Pretty-Print
	sonarOutputString, err := json.MarshalIndent(sonarOutput, "", "  ")
	if err != nil {
		return err
	}

	absolutePath, err := filepath.Abs(filepath.Join(outputPath, outputFileName))
	if err != nil {
		return fmt.Errorf("failed to resolve absolute path: %w", err)
	}
	fmt.Printf("[DEBUG] Absolute path for SonarQube JSON file: %s\n", absolutePath)

	err = util.CreateFile(sonarOutputString, outputPath, outputFileName)
	if err != nil {
		return err
	}

	return nil
}

// Helper function to get the message for the primary location
func getDescription(vuln types.HuskyCIVulnerability) string {
	if vuln.Details == "" {

		if vuln.Version != "" && len(vuln.Version) > len(vuln.Details) {
			return vuln.Version
		}

		return vuln.Title
	}
	return vuln.Details
}

// Helper function to map severity levels for rules
func mapRuleSeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "low":
		return "MINOR"
	case "medium":
		return "MAJOR"
	case "high":
		return "BLOCKER"
	default:
		return "INFO"
	}
}

// Helper function to map severity levels for impacts
func mapImpactSeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "low":
		return "LOW"
	case "medium":
		return "MEDIUM"
	case "high":
		return "HIGH"
	default:
		return "INFO"
	}
}

// Helper function to get the file path
func getFilePath(vuln types.HuskyCIVulnerability, outputPath string) string {
	if vuln.File == "" {
		err := util.CreateFile([]byte(placeholderFileText), outputPath, placeholderFileName)
		if err != nil {
			return filepath.Join(outputPath, placeholderFileName)
		}
		return filepath.Join(outputPath, placeholderFileName)
	}
	if vuln.Language == "Go" {
		return strings.Replace(vuln.File, goContainerBasePath, "", 1)
	}
	return vuln.File
}

// Helper function to get the start line
func getStartLine(line string) int {
	lineNum, err := strconv.Atoi(line)
	if err != nil || lineNum <= 0 {
		return 1
	}
	return lineNum
}

// Helper function to process vulnerabilities and adjust their titles
func generateRuleID(vuln *types.HuskyCIVulnerability) string {
	if vuln.SecurityTool == "GitLeaks" {
		// Slice the Title string using " in:" as a separator
		parts := strings.SplitN(vuln.Title, " in:", 2)
		// Set the Title to the first part of the slice
		if len(parts) > 0 {
			vuln.Title = strings.TrimSpace(parts[0])
		}

		return vuln.Title
	} else {
		// Check if the Title contains "vulnerable dependency" (case-insensitive)
		if strings.Contains(strings.ToLower(vuln.Title), "vulnerable dependency") {
			// Use a regular expression to extract the part before a number, math symbol, backslash or asterisk
			re := regexp.MustCompile(`^[^0-9<>=*\\]+`)
			match := re.FindString(vuln.Title)
			if match != "" {
				return fmt.Sprintf("(%s) %s", vuln.Language, strings.TrimSpace(match))
			} else {
				// Default case: Trim the Title by the ":" character
				parts := strings.SplitN(vuln.Title, ":", 2)
				if len(parts) > 0 {
					vuln.Title = strings.TrimSpace(parts[0])
				}
			}
		}

		return fmt.Sprintf("%s - %s", vuln.Language, vuln.Title)
	}
}
