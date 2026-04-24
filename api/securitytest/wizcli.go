package securitytest

import (
	"bufio"
	"regexp"
	"strings"

	"github.com/githubanotaai/huskyci-api/api/types"
)

var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*m|\[[0-9;]*m`)
var cvePattern = regexp.MustCompile(`CVE-\d{4}-\d+`)

func stripAnsiWiz(s string) string {
	return ansiEscape.ReplaceAllString(s, "")
}

func analyzeWizCLI(scanInfo *SecTestScanInfo) error {
	output := scanInfo.Container.COutput

	if strings.Contains(output, "ERROR_AUTH_WIZCLI") {
		scanInfo.ErrorFound = nil
		return nil
	}

	vulns := parseWizCLIStdout(output)

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

// parseWizCLIStdout parses the textual stdout of `wizcli dir scan` into
// HuskyCIVulnerability entries. It mirrors the logic in console-parser.js,
// handling Secrets, Data Findings, and CVE sections.
func parseWizCLIStdout(output string) []types.HuskyCIVulnerability {
	var findings []types.HuskyCIVulnerability
	seen := make(map[string]bool)

	type secretState struct {
		description string
		severity    string
		filePath    string
		lineNumber  string
	}

	type dataFindingState struct {
		classifier string
		matchCount string
		severity   string
		filePath   string
	}

	type cveState struct {
		cve          string
		severity     string
		location     string
		fixedVersion string
	}

	type packageState struct {
		name    string
		version string
		path    string
	}

	addFinding := func(title, severity, file, line, details, tool string) {
		key := title + "::" + severity + "::" + file
		if seen[key] {
			return
		}
		seen[key] = true
		findings = append(findings, types.HuskyCIVulnerability{
			Language:     "Generic",
			SecurityTool: tool,
			Severity:     severity,
			Title:        title,
			File:         file,
			Line:         line,
			Details:      details,
		})
	}

	var (
		currentSection     string
		currentSecret      *secretState
		currentDataFinding *dataFindingState
		currentCVE         *cveState
		currentPackage     *packageState
	)

	flushCVE := func(cve *cveState) {
		if cve == nil {
			return
		}
		fv := cve.fixedVersion
		if fv == "" {
			fv = "n/a"
		}
		details := cve.cve
		if fv != "n/a" {
			details += " (fixed: " + fv + ")"
		}
		addFinding(cve.cve, cve.severity, cve.location, "", details, "WizCLI")
	}

	flushSecret := func(s *secretState) {
		if s == nil || s.filePath == "" {
			return
		}
		loc := s.filePath
		if s.lineNumber != "" {
			loc += ", Line " + s.lineNumber
		}
		sev := s.severity
		if sev == "" {
			sev = "INFO"
		}
		addFinding(s.description, sev, loc, s.lineNumber, s.description, "WizCLI")
	}

	scanner := bufio.NewScanner(strings.NewReader(output))
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	for i, rawLine := range lines {
		line := strings.TrimSpace(stripAnsiWiz(rawLine))

		// Section detection
		if strings.Contains(line, "Library vulnerabilities:") || strings.Contains(line, "OS Package vulnerabilities:") {
			flushCVE(currentCVE)
			currentCVE = nil
			currentSection = "vulnerabilities"
			currentPackage = nil
			continue
		}
		if strings.Contains(line, "Secrets:") {
			currentSection = "secrets"
			currentSecret = nil
			continue
		}
		if strings.Contains(line, "Data Findings:") || strings.Contains(line, "Data findings:") {
			currentSection = "dataFindings"
			currentDataFinding = nil
			continue
		}
		if strings.Contains(line, "End of life technologies:") {
			flushCVE(currentCVE)
			currentCVE = nil
			currentSection = "eol"
			currentPackage = nil
			continue
		}
		if strings.Contains(line, "Licenses:") {
			flushCVE(currentCVE)
			currentCVE = nil
			currentSection = "licenses"
			currentPackage = nil
			continue
		}

		switch currentSection {

		case "secrets":
			cleanLine := stripAnsiWiz(rawLine)

			if strings.Contains(line, "Secret description:") {
				flushSecret(currentSecret)
				re := regexp.MustCompile(`(?i)Secret description:\s*(.+?)(?:\s*\[0m|\s*\[[0-9;]*m|\s*$)`)
				if m := re.FindStringSubmatch(cleanLine); len(m) > 1 {
					desc := ansiEscape.ReplaceAllString(strings.TrimSpace(m[1]), "")
					currentSecret = &secretState{description: desc, severity: "INFO"}
				}
				continue
			}
			if currentSecret != nil && strings.Contains(line, "Severity:") {
				cleanedLine := ansiEscape.ReplaceAllString(cleanLine, "")
				if m := regexp.MustCompile(`(?i)Severity:\s*(\w+)`).FindStringSubmatch(cleanedLine); len(m) > 1 {
					currentSecret.severity = strings.ToUpper(strings.TrimSpace(m[1]))
				}
				if currentSecret.filePath != "" {
					flushSecret(currentSecret)
					currentSecret = nil
				}
				continue
			}
			if currentSecret != nil && strings.Contains(line, "Path:") {
				re := regexp.MustCompile(`(?i)Path:\s*([^,]+)(?:,\s*Line\s+(\d+))?`)
				if m := re.FindStringSubmatch(cleanLine); len(m) > 1 {
					fp := ansiEscape.ReplaceAllString(strings.TrimSpace(m[1]), "")
					currentSecret.filePath = fp
					if len(m) > 2 && m[2] != "" {
						currentSecret.lineNumber = strings.TrimSpace(m[2])
					} else if i+1 < len(lines) {
						nextLine := strings.TrimSpace(stripAnsiWiz(lines[i+1]))
						if lm := regexp.MustCompile(`(?i)Line\s+(\d+)`).FindStringSubmatch(nextLine); len(lm) > 1 {
							currentSecret.lineNumber = lm[1]
						}
					}
					if currentSecret.severity != "" && currentSecret.severity != "INFO" {
						flushSecret(currentSecret)
						currentSecret = nil
					}
				}
				continue
			}

		case "dataFindings":
			cleanLine := stripAnsiWiz(line)
			if strings.Contains(line, "Data finding for classifier:") {
				re := regexp.MustCompile(`(?i)Data finding for classifier:\s*(.+?)(?:\s*\[0m|\s*\[[0-9;]*m|\s*$)`)
				if m := re.FindStringSubmatch(cleanLine); len(m) > 1 {
					clf := ansiEscape.ReplaceAllString(strings.TrimSpace(m[1]), "")
					currentDataFinding = &dataFindingState{classifier: clf, severity: "INFO"}
				}
				continue
			}
			if currentDataFinding != nil && strings.Contains(line, "Match count:") {
				if m := regexp.MustCompile(`(?i)Match count:\s*(\d+)`).FindStringSubmatch(cleanLine); len(m) > 1 {
					currentDataFinding.matchCount = m[1]
				}
				continue
			}
			if currentDataFinding != nil && strings.Contains(line, "Severity:") {
				cleanedLine := ansiEscape.ReplaceAllString(cleanLine, "")
				if m := regexp.MustCompile(`(?i)Severity:\s*(\w+)`).FindStringSubmatch(cleanedLine); len(m) > 1 {
					currentDataFinding.severity = strings.ToUpper(strings.TrimSpace(m[1]))
				}
				continue
			}
			if currentDataFinding != nil && strings.Contains(line, "Path:") {
				if m := regexp.MustCompile(`(?i)Path:\s*(.+)`).FindStringSubmatch(cleanLine); len(m) > 1 {
					fp := strings.TrimSpace(m[1])
					if currentDataFinding.filePath == "" {
						currentDataFinding.filePath = fp
						name := currentDataFinding.classifier
						if currentDataFinding.matchCount != "" {
							name += " (" + currentDataFinding.matchCount + " matches)"
						}
						addFinding(name, currentDataFinding.severity, fp, "", name, "WizCLI")
					}
				}
				continue
			}

		case "vulnerabilities":
			cleanLine := stripAnsiWiz(rawLine)
			if strings.Contains(line, "Name:") {
				flushCVE(currentCVE)
				currentCVE = nil
				nameRe := regexp.MustCompile(`Name:\s*([^,]+)`)
				verRe := regexp.MustCompile(`Version:\s*([^,]+)`)
				pathRe := regexp.MustCompile(`Path:\s*(.+?)(?:\s*$)`)
				var pkg packageState
				if m := nameRe.FindStringSubmatch(cleanLine); len(m) > 1 {
					pkg.name = strings.TrimSpace(m[1])
				}
				if m := verRe.FindStringSubmatch(cleanLine); len(m) > 1 {
					pkg.version = strings.TrimSpace(m[1])
				}
				if m := pathRe.FindStringSubmatch(cleanLine); len(m) > 1 {
					p := strings.TrimSpace(m[1])
					if idx := strings.Index(p, " contains transitive"); idx != -1 {
						p = strings.TrimSpace(p[:idx])
					}
					pkg.path = p
				}
				if pkg.name != "" {
					currentPackage = &pkg
				}
				continue
			}
			if currentPackage != nil && cvePattern.MatchString(line) {
				flushCVE(currentCVE)
				cveM := cvePattern.FindString(stripAnsiWiz(rawLine))
				sevM := regexp.MustCompile(`(?i)Severity:\s*(\w+)`).FindStringSubmatch(stripAnsiWiz(rawLine))
				sev := "UNKNOWN"
				if len(sevM) > 1 {
					sev = strings.ToUpper(strings.TrimSpace(sevM[1]))
				}
				loc := currentPackage.name
				if currentPackage.version != "" {
					loc += ":" + currentPackage.version
				}
				if currentPackage.path != "" {
					loc += " (" + strings.TrimLeft(currentPackage.path, "/") + ")"
				}
				currentCVE = &cveState{cve: cveM, severity: sev, location: loc, fixedVersion: "n/a"}
				continue
			}
			if currentCVE != nil && strings.Contains(line, "Fixed version:") {
				if m := regexp.MustCompile(`(?i)Fixed version:\s*([^\s,]+)`).FindStringSubmatch(stripAnsiWiz(rawLine)); len(m) > 1 {
					currentCVE.fixedVersion = strings.TrimSpace(m[1])
				}
				continue
			}

		case "eol":
			cleanLine := stripAnsiWiz(rawLine)
			if strings.Contains(line, "Name:") {
				nameRe := regexp.MustCompile(`Name:\s*([^,]+)`)
				verRe := regexp.MustCompile(`Version:\s*([^,]+)`)
				name := ""
				version := ""
				if m := nameRe.FindStringSubmatch(cleanLine); len(m) > 1 {
					name = strings.TrimSpace(m[1])
				}
				if m := verRe.FindStringSubmatch(cleanLine); len(m) > 1 {
					version = strings.TrimSpace(m[1])
				}
				if name != "" {
					loc := name
					if version != "" {
						loc += ":" + version
					}
					addFinding("End of Life Technology", "MEDIUM", loc, "", name+" is end of life", "WizCLI")
				}
				continue
			}
		}
	}

	// Flush any pending state
	flushCVE(currentCVE)
	flushSecret(currentSecret)

	return findings
}
