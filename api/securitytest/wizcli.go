package securitytest

import (
	"encoding/json"
	"errors"
	"fmt"
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
			location := pkg.Name
			if pkg.Version != "" {
				location += ":" + pkg.Version
			}
			if pkg.Path != "" {
				location += " (" + strings.TrimLeft(pkg.Path, "/") + ")"
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
				addFinding(v.Name, strings.ToUpper(v.Severity), location, line, details)
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
