package sonarqube

import (
	"encoding/json"
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

	// Collect all vulnerabilities from different tools into a single slice
	allVulns := make([]types.HuskyCIVulnerability, 0)
	allVulns = append(allVulns, analysis.HuskyCIResults.GoResults.HuskyCIGosecOutput.LowVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.GoResults.HuskyCIGosecOutput.MediumVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.GoResults.HuskyCIGosecOutput.HighVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.PythonResults.HuskyCIBanditOutput.NoSecVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.PythonResults.HuskyCIBanditOutput.LowVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.PythonResults.HuskyCIBanditOutput.MediumVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.PythonResults.HuskyCIBanditOutput.HighVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.PythonResults.HuskyCISafetyOutput.LowVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.PythonResults.HuskyCISafetyOutput.MediumVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.PythonResults.HuskyCISafetyOutput.HighVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.RubyResults.HuskyCIBrakemanOutput.LowVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.RubyResults.HuskyCIBrakemanOutput.MediumVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.RubyResults.HuskyCIBrakemanOutput.HighVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.JavaScriptResults.HuskyCINpmAuditOutput.LowVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.JavaScriptResults.HuskyCINpmAuditOutput.MediumVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.JavaScriptResults.HuskyCINpmAuditOutput.HighVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.JavaScriptResults.HuskyCIYarnAuditOutput.LowVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.JavaScriptResults.HuskyCIYarnAuditOutput.MediumVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.JavaScriptResults.HuskyCIYarnAuditOutput.HighVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.GenericResults.HuskyCIGitleaksOutput.LowVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.GenericResults.HuskyCIGitleaksOutput.MediumVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.GenericResults.HuskyCIGitleaksOutput.HighVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.JavaResults.HuskyCISpotBugsOutput.LowVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.JavaResults.HuskyCISpotBugsOutput.MediumVulns...)
	allVulns = append(allVulns, analysis.HuskyCIResults.JavaResults.HuskyCISpotBugsOutput.HighVulns...)

	// Initialize the SonarQube output structure
	var sonarOutput HuskyCISonarOutput
	sonarOutput.Issues = make([]SonarIssue, 0)

	// Convert each vulnerability into a SonarQube issue
	for _, vuln := range allVulns {
		var issue SonarIssue
		issue.EngineID = "huskyCI"                               // Identifier for the analysis engine
		issue.Type = "VULNERABILITY"                             // Issue type (e.g., vulnerability)
		issue.RuleID = vuln.Language + " - " + vuln.SecurityTool // Rule identifier

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
			err := util.CreateFile([]byte(placeholderFileText), outputPath, placeholderFileName)
			if err != nil {
				return err
			}
			issue.PrimaryLocation.FilePath = filepath.Join(outputPath, placeholderFileName)
		} else {
			// Adjust file paths for Go vulnerabilities or use the provided file path
			var filePath string
			if vuln.Language == "Go" {
				filePath = strings.Replace(vuln.File, goContainerBasePath, "", 1)
			} else {
				filePath = vuln.File
			}
			issue.PrimaryLocation.FilePath = filePath
		}

		// Set the issue message and line number
		issue.PrimaryLocation.Message = vuln.Details
		issue.PrimaryLocation.TextRange.StartLine = 1
		lineNum, err := strconv.Atoi(vuln.Line)
		if err != nil {
			lineNum = 1
		}
		if lineNum != 1 && lineNum > 0 {
			issue.PrimaryLocation.TextRange.StartLine = lineNum
		}

		// Add the issue to the SonarQube output
		sonarOutput.Issues = append(sonarOutput.Issues, issue)
	}

	// Serialize the SonarQube output to JSON
	sonarOutputString, err := json.Marshal(sonarOutput)
	if err != nil {
		return err
	}

	// Write the JSON output to the specified file
	err = util.CreateFile(sonarOutputString, outputPath, outputFileName)
	if err != nil {
		return err
	}

	return nil // Return nil if everything succeeds
}
