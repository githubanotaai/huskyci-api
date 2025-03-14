package sonarqube

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/githubanotaai/huskyci-api/client/types"
	"github.com/githubanotaai/huskyci-api/client/util"
)

const goContainerBasePath = `/go/src/code/`            // Base path for Go files inside the container
const placeholderFileName = "huskyCI_Placeholder_File" // Placeholder file name for vulnerabilities without a file
const placeholderFileText = `
Placeholder file indicating that no file was associated with this vulnerability.
This usually means that the vulnerability is related to a missing file
or is not associated with any specific file, i.e.: vulnerable dependency versions.
`

// GenerateOutputFile creates a SonarQube-compatible JSON file from the analysis results
func GenerateOutputFile(analysis types.Analysis, outputPath, outputFileName string) error {
	fmt.Println("[DEBUG] Starting GenerateOutputFile...")
	fmt.Printf("[DEBUG] Output Path: %s, Output File Name: %s\n", outputPath, outputFileName)

	// Resolve the absolute path for the output directory
	absoluteOutputPath, err := filepath.Abs(outputPath)
	if err != nil {
		return fmt.Errorf("failed to resolve absolute path for output directory: %w", err)
	}

	// Print the current working directory
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Printf("[DEBUG] Failed to get current working directory: %v\n", err)
	} else {
		fmt.Printf("[DEBUG] Current working directory: %s\n", cwd)
	}

	// Ensure the output directory exists
	if _, err := os.Stat(absoluteOutputPath); os.IsNotExist(err) {
		fmt.Printf("[DEBUG] Output directory does not exist. Creating: %s\n", absoluteOutputPath)
		err := os.MkdirAll(absoluteOutputPath, os.ModePerm)
		if err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	// Collect all vulnerabilities from different tools into a single slice
	allVulns := make([]types.HuskyCIVulnerability, 0)

	// Aggregate vulnerabilities from Go tools
	allVulns = append(allVulns, analysis.HuskyCIResults.GoResults.HuskyCIGosecOutput.LowVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.GoResults.HuskyCIGosecOutput.MediumVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.GoResults.HuskyCIGosecOutput.HighVulns...)

	// Aggregate vulnerabilities from Python tools
	allVulns = append(allVulns, analysis.HuskyCIResults.PythonResults.HuskyCIBanditOutput.LowVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.PythonResults.HuskyCIBanditOutput.MediumVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.PythonResults.HuskyCIBanditOutput.HighVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.PythonResults.HuskyCISafetyOutput.LowVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.PythonResults.HuskyCISafetyOutput.MediumVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.PythonResults.HuskyCISafetyOutput.HighVulns...)

	// Aggregate vulnerabilities from JavaScript tools
	allVulns = append(allVulns, analysis.HuskyCIResults.JavaScriptResults.HuskyCINpmAuditOutput.LowVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.JavaScriptResults.HuskyCINpmAuditOutput.MediumVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.JavaScriptResults.HuskyCINpmAuditOutput.HighVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.JavaScriptResults.HuskyCIYarnAuditOutput.LowVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.JavaScriptResults.HuskyCIYarnAuditOutput.MediumVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.JavaScriptResults.HuskyCIYarnAuditOutput.HighVulns...)

	// Aggregate vulnerabilities from generic tools
	allVulns = append(allVulns, analysis.HuskyCIResults.GenericResults.HuskyCIGitleaksOutput.LowVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.GenericResults.HuskyCIGitleaksOutput.MediumVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.GenericResults.HuskyCIGitleaksOutput.HighVulns...)

	// Aggregate vulnerabilities from Ruby tools
	allVulns = append(allVulns, analysis.HuskyCIResults.RubyResults.HuskyCIBrakemanOutput.LowVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.RubyResults.HuskyCIBrakemanOutput.MediumVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.RubyResults.HuskyCIBrakemanOutput.HighVulns...)

	// Aggregate vulnerabilities from Java tools
	allVulns = append(allVulns, analysis.HuskyCIResults.JavaResults.HuskyCISpotBugsOutput.LowVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.JavaResults.HuskyCISpotBugsOutput.MediumVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.JavaResults.HuskyCISpotBugsOutput.HighVulns...)

	fmt.Printf("[DEBUG] Total Vulnerabilities: %d\n", len(allVulns))

	// Initialize the SonarQube output structure
	var sonarOutput HuskyCISonarOutput
	sonarOutput.Issues = make([]SonarIssue, 0)

	// Convert each vulnerability into a SonarQube issue
	for _, vuln := range allVulns {
		var issue SonarIssue
		issue.EngineID = "huskyCI"
		issue.Type = "VULNERABILITY"
		issue.RuleID = vuln.Language + " - " + vuln.SecurityTool

		// Map severity levels to SonarQube-compatible values
		switch strings.ToLower(vuln.Severity) {
		case `low`:
			issue.Severity = "MINOR"
		case `medium`:
			issue.Severity = "MAJOR"
		case `high`:
			issue.Severity = "BLOCKER"
		default:
			issue.Severity = "INFO"
		}

		// Handle vulnerabilities without an associated file
		if vuln.File == "" {
			err := util.CreateFile([]byte(placeholderFileText), absoluteOutputPath, placeholderFileName)
			if err != nil {
				return err
			}
			issue.PrimaryLocation.FilePath = filepath.Join(absoluteOutputPath, placeholderFileName)
		} else {
			var filePath string
			if vuln.Language == "Go" {
				filePath = strings.Replace(vuln.File, goContainerBasePath, "", 1)
			} else {
				filePath = vuln.File
			}
			issue.PrimaryLocation.FilePath = filePath
		}

		issue.PrimaryLocation.Message = vuln.Details
		issue.PrimaryLocation.TextRange.StartLine = 1
		lineNum, err := strconv.Atoi(vuln.Line)
		if err != nil {
			lineNum = 1
		}
		if lineNum != 1 && lineNum > 0 {
			issue.PrimaryLocation.TextRange.StartLine = lineNum
		}

		sonarOutput.Issues = append(sonarOutput.Issues, issue)
	}

	if len(sonarOutput.Issues) == 0 {
		fmt.Println("[DEBUG] No vulnerabilities found. Creating an empty SonarQube JSON file.")
	}

	sonarOutputString, err := json.Marshal(sonarOutput)
	if err != nil {
		return err
	}

	fmt.Printf("[DEBUG] Writing SonarQube JSON file to: %s/%s\n", absoluteOutputPath, outputFileName)
	err = util.CreateFile(sonarOutputString, absoluteOutputPath, outputFileName)
	if err != nil {
		return err
	}

	return nil
}
