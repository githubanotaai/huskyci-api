package securitytest

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/githubanotaai/huskyci-api/api/types"
)

// wizCLIReport models the subset of `wizcli dir scan -f json` output that
// huskyCI surfaces as findings. Unrelated metadata (analytics, sbomOutput,
// hostConfiguration, ...) is intentionally ignored.
type wizCLIReport struct {
	Status struct {
		State   string `json:"state"`
		Verdict string `json:"verdict"`
	} `json:"status"`
	Result struct {
		Libraries             []wizPackageWithVulns  `json:"libraries"`
		OSPackages            []wizPackageWithVulns  `json:"osPackages"`
		Secrets               []wizSecretFinding     `json:"secrets"`
		DataFindings          []wizDataFinding       `json:"dataFindings"`
		EndOfLifeTechnologies []wizEndOfLifeFinding  `json:"endOfLifeTechnologies"`
	} `json:"result"`
}

type wizPackageWithVulns struct {
	Name            string             `json:"name"`
	Version         string             `json:"version"`
	Path            string             `json:"path"`
	StartLine       int                `json:"startLine"`
	Vulnerabilities []wizVulnerability `json:"vulnerabilities"`
}

type wizVulnerability struct {
	Name         string `json:"name"`
	Severity     string `json:"severity"`
	FixedVersion string `json:"fixedVersion"`
	Description  string `json:"description"`
	HasExploit   bool   `json:"hasExploit"`
}

type wizSecretFinding struct {
	Description string `json:"description"`
	Path        string `json:"path"`
	LineNumber  int    `json:"lineNumber"`
	Severity    string `json:"severity"`
	Type        string `json:"type"`
}

type wizDataFinding struct {
	Classifier string `json:"classifier"`
	MatchCount int    `json:"matchCount"`
	Severity   string `json:"severity"`
	Path       string `json:"path"`
}

type wizEndOfLifeFinding struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func analyzeWizCLI(scanInfo *SecTestScanInfo) error {
	output := scanInfo.Container.COutput

	if strings.Contains(output, "ERROR_AUTH_WIZCLI") {
		scanInfo.ErrorFound = errors.New("wizcli authentication failed (ERROR_AUTH_WIZCLI)")
		return scanInfo.ErrorFound
	}

	if strings.Contains(output, "ERROR_RUNNING_WIZCLI_SCAN") {
		scanInfo.ErrorFound = errors.New("wizcli dir scan failed with a non-findings exit code")
		return scanInfo.ErrorFound
	}

	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return nil
	}

	vulns, err := parseWizCLIJSON(trimmed)
	if err != nil {
		scanInfo.ErrorFound = fmt.Errorf("wizcli json parse failed: %w", err)
		return scanInfo.ErrorFound
	}

	for _, v := range vulns {
		switch strings.ToUpper(v.Severity) {
		case "CRITICAL", "HIGH":
			scanInfo.Vulnerabilities.HighVulns = append(scanInfo.Vulnerabilities.HighVulns, v)
		case "MEDIUM", "MAJOR":
			scanInfo.Vulnerabilities.MediumVulns = append(scanInfo.Vulnerabilities.MediumVulns, v)
		case "LOW", "MINOR":
			scanInfo.Vulnerabilities.LowVulns = append(scanInfo.Vulnerabilities.LowVulns, v)
		default:
			scanInfo.Vulnerabilities.NoSecVulns = append(scanInfo.Vulnerabilities.NoSecVulns, v)
		}
	}

	return nil
}

// manifestFileTypes maps manifest file names/basenames to their language ecosystem.
var manifestFileTypes = map[string]string{
	// Python
	"requirements.txt":    "python",
	"requirements":        "python", // prefix match for requirements-*.txt
	"pyproject.toml":      "python",
	"setup.py":            "python",
	"Pipfile":             "python",
	"Pipfile.lock":        "python",
	// Node.js
	"package-lock.json": "node",
	"package.json":       "node",
	"yarn.lock":          "node",
	"npm-shrinkwrap.json": "node",
	"pnpm-lock.yaml":    "node",
	// Go
	"go.mod": "go",
	"go.sum": "go",
	// Java
	"pom.xml":           "java",
	"build.gradle":      "java",
	"build.gradle.kts":  "java",
	// Ruby
	"Gemfile":      "ruby",
	"Gemfile.lock": "ruby",
	// PHP
	"composer.json": "php",
	"composer.lock": "php",
	// .NET
	"packages.config":  "dotnet",
	"project.json":     "dotnet",
	"project.lock.json": "dotnet",
	// Rust
	"Cargo.toml": "rust",
	"Cargo.lock": "rust",
}

// detectManifestType returns the language/ecosystem type for a manifest file path.
// Returns empty string if not a recognized manifest file.
func detectManifestType(filePath string) string {
	// Get basename of file
	base := filepath.Base(filePath)

	// Direct match
	if lang, ok := manifestFileTypes[base]; ok {
		return lang
	}

	// Special case: requirements-*.txt pattern
	if strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt") {
		return "python"
	}

	// Special case: *.gradle files
	if strings.HasSuffix(base, ".gradle") || strings.HasSuffix(base, ".gradle.kts") {
		return "java"
	}

	return ""
}

// isManifestFile returns true if the file path points to a known dependency manifest file.
func isManifestFile(filePath string) bool {
	return detectManifestType(filePath) != ""
}

// normalizeFilePath ensures file paths are valid for SonarQube's generic issue import.
// Dependency findings often arrive as "package:version (manifest)" which SonarQube rejects
// as unknown files. This normalizes them to "/manifest:package:version" format.
func normalizeFilePath(filePath, manifestPath string) string {
	// Already a proper absolute path - return as-is
	if strings.HasPrefix(filePath, "/") && !strings.Contains(filePath, "(") {
		return filePath
	}

	// Handle dependency format: "package:version (manifest_file)"
	// Pattern: package:version or package:version (requirements.txt)
	if strings.Contains(filePath, ":") {
		// Extract manifest name from parentheses if present
		manifestName := ""
		if idx := strings.Index(filePath, "("); idx != -1 {
			closeParen := strings.Index(filePath[idx:], ")")
			if closeParen != -1 {
				manifestName = filePath[idx+1 : idx+closeParen]
			}
		}

		// Extract package:version (remove parentheses suffix)
		pkgVersion := filePath
		if idx := strings.Index(pkgVersion, " ("); idx != -1 {
			pkgVersion = pkgVersion[:idx]
		}

		// Determine manifest path
		var manifest string
		if manifestPath != "" {
			manifest = manifestPath
		} else if manifestName != "" {
			manifest = "/" + manifestName
		} else {
			// Default manifest based on common patterns
			// This fallback handles cases where manifest isn't specified
			manifest = "/unknown_manifest"
		}

		return manifest + ":" + pkgVersion
	}

	// Default: return as-is (placeholder files, etc.)
	return filePath
}

// validateSonarQubeFilePath checks if a file path is valid for SonarQube's generic issue import.
// SonarQube rejects paths that don't match actual files in the project.
func validateSonarQubeFilePath(filePath string) error {
	if filePath == "" {
		return errors.New("empty file path")
	}

	// Must start with / (absolute path in project)
	if !strings.HasPrefix(filePath, "/") {
		return fmt.Errorf("path must start with '/': %q", filePath)
	}

	// Reject placeholder files
	if strings.Contains(filePath, "huskyCI_Placeholder_File") {
		return fmt.Errorf("placeholder file not valid for SonarQube: %q", filePath)
	}

	// Reject the raw "package:version (manifest)" format that SonarQube ignores
	// This format appears in external tool output when not properly normalized
	if strings.Contains(filePath, "(") && strings.Contains(filePath, ")") {
		// Allow composite paths like "/requirements.txt:package:version"
		// but reject "package:version (manifest)" format
		if !strings.HasPrefix(filePath, "/") || strings.HasPrefix(filePath, "(") {
			return fmt.Errorf("invalid package:version (manifest) format: %q", filePath)
		}
	}

	return nil
}

// sonarQubeExternalIssue represents a single external issue for SonarQube import.
type sonarQubeExternalIssue struct {
	EngineID       string `json:"engineId"`
	RuleID         string `json:"ruleId"`
	Severity       string `json:"severity,omitempty"`
	Type           string `json:"type,omitempty"`
	PrimaryLocation struct {
		Message  string `json:"message"`
		FilePath string `json:"filePath"`
		Line     int    `json:"line,omitempty"`
	} `json:"primaryLocation"`
}

// generateSonarQubeExternalIssue converts a HuskyCIVulnerability to SonarQube external issue format.
func generateSonarQubeExternalIssue(vuln types.HuskyCIVulnerability) sonarQubeExternalIssue {
	issue := sonarQubeExternalIssue{
		EngineID: vuln.SecurityTool,
		RuleID:   vuln.Title,
	}

	// Map severity from HuskyCI to SonarQube format
	switch strings.ToUpper(vuln.Severity) {
	case "CRITICAL":
		issue.Severity = "CRITICAL"
		issue.Type = "VULNERABILITY"
	case "HIGH":
		issue.Severity = "MAJOR"
		issue.Type = "VULNERABILITY"
	case "MEDIUM":
		issue.Severity = "MINOR"
		issue.Type = "VULNERABILITY"
	case "LOW":
		issue.Severity = "INFO"
		issue.Type = "VULNERABILITY"
	default:
		issue.Severity = "MAJOR"
		issue.Type = "VULNERABILITY"
	}

	// Set message (combine title and details)
	msg := vuln.Title
	if vuln.Details != "" {
		msg += " - " + vuln.Details
	}
	issue.PrimaryLocation.Message = msg

	// Normalize the file path for SonarQube
	filePath := vuln.File
	filePath = normalizeFilePath(filePath, "")
	issue.PrimaryLocation.FilePath = filePath

	// Parse line number
	if vuln.Line != "" {
		if lineNum, err := strconv.Atoi(vuln.Line); err == nil && lineNum > 0 {
			issue.PrimaryLocation.Line = lineNum
		}
	}

	return issue
}

// parseWizCLIJSON converts the JSON produced by `wizcli dir scan -f json`
// into HuskyCIVulnerability entries, covering CVEs (libraries, OS packages),
// secrets, data findings, and end-of-life technologies.
func parseWizCLIJSON(output string) ([]types.HuskyCIVulnerability, error) {
	var report wizCLIReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		return nil, err
	}

	var findings []types.HuskyCIVulnerability
	seen := make(map[string]bool)

	addFinding := func(title, severity, file, line, details string) {
		key := title + "::" + severity + "::" + file + "::" + line
		if seen[key] {
			return
		}
		seen[key] = true
		findings = append(findings, types.HuskyCIVulnerability{
			Language:     "Generic",
			SecurityTool: "WizCLI",
			Severity:     severity,
			Title:        title,
			File:         file,
			Line:         line,
			Details:      details,
		})
	}

	collectCVEs := func(pkgs []wizPackageWithVulns) {
		for _, pkg := range pkgs {
			// Use the manifest path directly if available - WizCLI provides the actual file
			location := pkg.Path
			if location == "" {
				// Fallback: construct from package name/version
				location = pkg.Name
				if pkg.Version != "" {
					location += ":" + pkg.Version
				}
			}
			line := ""
			if pkg.StartLine > 0 {
				line = strconv.Itoa(pkg.StartLine)
			}
			for _, v := range pkg.Vulnerabilities {
				if v.Name == "" {
					continue
				}
				details := v.Name
				if v.FixedVersion != "" {
					details += " (fixed: " + v.FixedVersion + ")"
				} else {
					details += " (fixed: n/a)"
				}
				if v.Description != "" {
					details += " — " + v.Description
				}
				// Normalize the location for SonarQube compatibility
				normalizedLocation := normalizeFilePath(location, pkg.Path)
				addFinding(v.Name, strings.ToUpper(v.Severity), normalizedLocation, line, details)
			}
		}
	}

	collectCVEs(report.Result.Libraries)
	collectCVEs(report.Result.OSPackages)

	for _, s := range report.Result.Secrets {
		title := s.Description
		if title == "" {
			title = s.Type
		}
		if title == "" {
			title = "Secret finding"
		}
		line := ""
		if s.LineNumber > 0 {
			line = strconv.Itoa(s.LineNumber)
		}
		severity := strings.ToUpper(s.Severity)
		if severity == "INFORMATIONAL" || severity == "INFO" || severity == "" {
			severity = "INFO"
		}
		addFinding(title, severity, s.Path, line, title)
	}

	for _, df := range report.Result.DataFindings {
		title := df.Classifier
		if title == "" {
			title = "Data finding"
		}
		if df.MatchCount > 0 {
			title += " (" + strconv.Itoa(df.MatchCount) + " matches)"
		}
		severity := strings.ToUpper(df.Severity)
		if severity == "INFORMATIONAL" || severity == "INFO" || severity == "" {
			severity = "INFO"
		}
		addFinding(title, severity, df.Path, "", title)
	}

	for _, eol := range report.Result.EndOfLifeTechnologies {
		if eol.Name == "" {
			continue
		}
		location := eol.Name
		if eol.Version != "" {
			location += ":" + eol.Version
		}
		addFinding("End of Life Technology", "MEDIUM", location, "", eol.Name+" is end of life")
	}

	return findings, nil
}
