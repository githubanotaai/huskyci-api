func GenerateOutputFile(analysis types.Analysis, outputPath, outputFileName string) error {
	fmt.Println("[DEBUG] Starting GenerateOutputFile...")
	fmt.Printf("[DEBUG] Output Path: %s, Output File Name: %s\n", outputPath, outputFileName)

	// Print the current working directory
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Printf("[DEBUG] Failed to get current working directory: %v\n", err)
	} else {
		fmt.Printf("[DEBUG] Current working directory: %s\n", cwd)
	}

	// Ensure the output directory exists
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		fmt.Printf("[DEBUG] Output directory does not exist. Creating: %s\n", outputPath)
		err := os.MkdirAll(outputPath, os.ModePerm)
		if err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	// Collect all vulnerabilities from different tools into a single slice
	allVulns := make([]types.HuskyCIVulnerability, 0)
	allVulns = append(allVulns, analysis.HuskyCIResults.GoResults.HuskyCIGosecOutput.LowVulns...)
	// ... (rest of the vulnerability aggregation code)

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
			err := util.CreateFile([]byte(placeholderFileText), outputPath, placeholderFileName)
			if err != nil {
				return err
			}
			issue.PrimaryLocation.FilePath = filepath.Join(outputPath, placeholderFileName)
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

	fmt.Printf("[DEBUG] Writing SonarQube JSON file to: %s/%s\n", outputPath, outputFileName)
	err = util.CreateFile(sonarOutputString, outputPath, outputFileName)
	if err != nil {
		return err
	}

	return nil
}