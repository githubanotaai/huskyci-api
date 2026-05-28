// Copyright 2019 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sonarqube

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/githubanotaai/huskyci-api/client/types"
	"github.com/githubanotaai/huskyci-api/client/util"
)

const goContainerBasePath = `/go/src/code/`
const placeholderFileFallback = "README.md"

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

	// wizcli
	allVulns = append(allVulns, analysis.HuskyCIResults.GenericResults.HuskyCIWizCLISecretsOutput.LowVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.GenericResults.HuskyCIWizCLISecretsOutput.MediumVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.GenericResults.HuskyCIWizCLISecretsOutput.HighVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.GenericResults.HuskyCIIacSastOutput.LowVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.GenericResults.HuskyCIIacSastOutput.MediumVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.GenericResults.HuskyCIIacSastOutput.HighVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.GenericResults.HuskyCIWizCLIVulnsOutput.LowVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.GenericResults.HuskyCIWizCLIVulnsOutput.MediumVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.GenericResults.HuskyCIWizCLIVulnsOutput.HighVulns...)

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
	// Handle empty file - remap to README.md for SonarQube compatibility
	// SonarQube requires issues to be attached to existing files in the project.
	// README.md exists in almost all repositories and provides a visible location
	// for these findings.
	if vuln.File == "" {
		return placeholderFileFallback
	}

	// Handle Go container paths
	if vuln.Language == "Go" {
		return strings.Replace(vuln.File, goContainerBasePath, "", 1)
	}

	// Handle dependency findings: normalize various formats to manifest file path
	// These come from tools like Safety, NpmAudit, WizCLI for library CVEs
	filePath := vuln.File

	// Format 1: "package:version (manifest)" - from Safety, some WizCLI versions
	// Example: "pytest:7.4.3 (requirements.txt)"
	if strings.Contains(filePath, "(") && strings.Contains(filePath, ")") {
		// Extract manifest name from parentheses
		startIdx := strings.Index(filePath, "(")
		endIdx := strings.Index(filePath, ")")
		if startIdx != -1 && endIdx != -1 && endIdx > startIdx {
			manifestName := filePath[startIdx+1 : endIdx]
			// Return just the manifest file path (e.g., "requirements.txt")
			// SonarQube expects relative paths from project root
			return manifestName
		}
	}

	// Format 2: "manifest:package:version" - from WizCLI normalized output
	// Example: "requirements.txt:pytest:7.4.3" or "poetry.lock:requests:2.28.0"
	// Detect this by checking if it starts with a known manifest file pattern
	if strings.Contains(filePath, ":") {
		// Common manifest file patterns
		manifestPatterns := []string{
			"requirements.txt:",
			"requirements-dev.txt:",
			"poetry.lock:",
			"Pipfile.lock:",
			"pyproject.toml:",
			"package-lock.json:",
			"yarn.lock:",
			"pnpm-lock.yaml:",
			"package.json:",
			"go.sum:",
			"go.mod:",
			"pom.xml:",
			"build.gradle:",
			"Gemfile.lock:",
			"Cargo.lock:",
			"composer.lock:",
		}
		for _, pattern := range manifestPatterns {
			if strings.HasPrefix(filePath, pattern) {
				// Extract just the manifest file name (before the first colon)
				colonIdx := strings.Index(filePath, ":")
				if colonIdx != -1 {
					return filePath[:colonIdx]
				}
			}
		}
	}

	// Handle placeholder file references - remap to README.md for SonarQube compatibility
	// SonarQube requires issues to be attached to existing files in the project.
	if strings.Contains(filePath, "huskyCI_Placeholder_File") {
		return placeholderFileFallback
	}

	// Strip leading "./" prefix if present - SonarQube expects relative paths
	// without the "./" prefix (e.g., "im_sync/auth.py" not "./im_sync/auth.py")
	filePath = strings.TrimPrefix(filePath, "./")

	return filePath
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
