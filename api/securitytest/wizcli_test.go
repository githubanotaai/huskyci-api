package securitytest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/githubanotaai/huskyci-api/api/types"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func findVuln(vulns []types.HuskyCIVulnerability, predicate func(types.HuskyCIVulnerability) bool) *types.HuskyCIVulnerability {
	for i := range vulns {
		if predicate(vulns[i]) {
			return &vulns[i]
		}
	}
	return nil
}

func loadJSONFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join("testdata", "wizcli_v1_json_sample.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read fixture %s: %v", path, err)
	}
	return string(b)
}

// ── parser tests ─────────────────────────────────────────────────────────────

func TestParseWizCLIJSON_Empty(t *testing.T) {
	_, err := parseWizCLIJSON("")
	if err == nil {
		t.Error("expected error parsing empty JSON, got nil")
	}
}

func TestParseWizCLIJSON_InvalidJSON(t *testing.T) {
	_, err := parseWizCLIJSON("not json")
	if err == nil {
		t.Error("expected error parsing invalid JSON, got nil")
	}
}

func TestParseWizCLIJSON_NoFindings(t *testing.T) {
	out, err := parseWizCLIJSON(`{"status":{"state":"SUCCESS","verdict":"PASSED_BY_POLICY"},"result":{}}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected zero findings, got %d", len(out))
	}
}

func TestParseWizCLIJSON_LibraryCVEs(t *testing.T) {
	const input = `{"status":{"state":"SUCCESS","verdict":"PASSED_BY_POLICY"},"result":{"libraries":[
		{"name":"lodash","version":"4.17.4","path":"/package-lock.json","startLine":5,"endLine":5,
		 "vulnerabilities":[
		   {"name":"CVE-2021-23337","severity":"HIGH","fixedVersion":"4.17.21"},
		   {"name":"CVE-2018-3721","severity":"MEDIUM","fixedVersion":"4.17.5"}
		 ]}
	]}}`
	out, err := parseWizCLIJSON(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(out))
	}
	high := findVuln(out, func(v types.HuskyCIVulnerability) bool {
		return v.Title == "CVE-2021-23337"
	})
	if high == nil {
		t.Fatal("expected CVE-2021-23337 finding")
	}
	if high.Severity != "HIGH" {
		t.Errorf("expected severity HIGH, got %q", high.Severity)
	}
	// Updated: we now use the manifest path directly (without leading /)
	if high.File != "package-lock.json" {
		t.Errorf("expected file 'package-lock.json', got %q", high.File)
	}
	if high.Line != "5" {
		t.Errorf("expected line '5', got %q", high.Line)
	}
	if !strings.Contains(high.Details, "fixed: 4.17.21") {
		t.Errorf("expected details to mention fixed version, got %q", high.Details)
	}
	if high.SecurityTool != "WizCLI" {
		t.Errorf("expected tool WizCLI, got %q", high.SecurityTool)
	}
}

func TestParseWizCLIJSON_OSPackagesUseSamePath(t *testing.T) {
	const input = `{"result":{"osPackages":[
		{"name":"openssl","version":"1.1.1","path":"/usr/lib","vulnerabilities":[
			{"name":"CVE-2024-0001","severity":"CRITICAL"}
		]}
	]}}`
	out, err := parseWizCLIJSON(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 1 || out[0].Title != "CVE-2024-0001" {
		t.Fatalf("expected one CVE-2024-0001 finding, got %+v", out)
	}
	if out[0].Severity != "CRITICAL" {
		t.Errorf("expected CRITICAL severity, got %q", out[0].Severity)
	}
}

func TestParseWizCLIJSON_Secrets(t *testing.T) {
	const input = `{"result":{"secrets":[
		{"description":"GitHub Classic PAT","path":"/leaky.env","lineNumber":1,"severity":"HIGH","type":"SAAS_API_KEY"},
		{"description":"AWS access key","path":"/cfg.yaml","lineNumber":42,"severity":"INFORMATIONAL","type":"GENERIC"}
	]}}`
	out, err := parseWizCLIJSON(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 secret findings, got %d", len(out))
	}
	pat := findVuln(out, func(v types.HuskyCIVulnerability) bool {
		return v.Title == "GitHub Classic PAT"
	})
	if pat == nil || pat.Severity != "HIGH" || pat.Line != "1" {
		t.Errorf("unexpected PAT finding: %+v", pat)
	}
	info := findVuln(out, func(v types.HuskyCIVulnerability) bool {
		return v.Title == "AWS access key"
	})
	if info == nil || info.Severity != "INFO" {
		t.Errorf("expected INFORMATIONAL secret to bucket as INFO, got %+v", info)
	}
}

func TestParseWizCLIJSON_DataFindings(t *testing.T) {
	const input = `{"result":{"dataFindings":[
		{"classifier":"Email Address","matchCount":3,"severity":"LOW","path":"/users.csv"}
	]}}`
	out, err := parseWizCLIJSON(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 data finding, got %d", len(out))
	}
	if !strings.Contains(out[0].Title, "Email Address") || !strings.Contains(out[0].Title, "3 matches") {
		t.Errorf("expected title to mention classifier+count, got %q", out[0].Title)
	}
	if out[0].Severity != "LOW" {
		t.Errorf("expected LOW severity, got %q", out[0].Severity)
	}
}

func TestParseWizCLIJSON_EOLTechnologies(t *testing.T) {
	const input = `{"result":{"endOfLifeTechnologies":[{"name":"Python","version":"2.7"}]}}`
	out, err := parseWizCLIJSON(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 EOL finding, got %d", len(out))
	}
	if out[0].Title != "End of Life Technology" {
		t.Errorf("expected EOL title, got %q", out[0].Title)
	}
	if out[0].Severity != "MEDIUM" {
		t.Errorf("expected MEDIUM severity, got %q", out[0].Severity)
	}
	if !strings.Contains(out[0].File, "Python:2.7") {
		t.Errorf("expected location to contain 'Python:2.7', got %q", out[0].File)
	}
}

func TestParseWizCLIJSON_IacFindings(t *testing.T) {
	const input = `{"result":{"iac":[
		{"name":"S3 Bucket without versioning","description":"Bucket should have versioning","severity":"HIGH","file":"main.tf","line":42,"rule":"CKV_AWS_1"}
	]}}`
	out, err := parseWizCLIJSON(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 IaC finding, got %d", len(out))
	}
	v := out[0]
	if v.Title != "S3 Bucket without versioning" {
		t.Errorf("expected Title 'S3 Bucket without versioning', got %q", v.Title)
	}
	if v.Severity != "HIGH" {
		t.Errorf("expected Severity HIGH, got %q", v.Severity)
	}
	if v.File != "main.tf" {
		t.Errorf("expected File 'main.tf', got %q", v.File)
	}
	if v.Line != "42" {
		t.Errorf("expected Line '42', got %q", v.Line)
	}
	if v.Details != "Bucket should have versioning" {
		t.Errorf("expected Details 'Bucket should have versioning', got %q", v.Details)
	}
	if v.SecurityTool != "WizCLI" {
		t.Errorf("expected SecurityTool WizCLI, got %q", v.SecurityTool)
	}
}

func TestParseWizCLIJSON_SastFindings(t *testing.T) {
	const input = `{"result":{"sast":[
		{"name":"SQL Injection","description":"Unsanitized input in SQL query","severity":"CRITICAL","file":"handler.go","line":100,"rule":"SQL_INJECTION"}
	]}}`
	out, err := parseWizCLIJSON(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 SAST finding, got %d", len(out))
	}
	v := out[0]
	if v.Title != "SQL Injection" {
		t.Errorf("expected Title 'SQL Injection', got %q", v.Title)
	}
	if v.Severity != "CRITICAL" {
		t.Errorf("expected Severity CRITICAL, got %q", v.Severity)
	}
	if v.File != "handler.go" {
		t.Errorf("expected File 'handler.go', got %q", v.File)
	}
	if v.Line != "100" {
		t.Errorf("expected Line '100', got %q", v.Line)
	}
	if v.Details != "Unsanitized input in SQL query" {
		t.Errorf("expected Details 'Unsanitized input in SQL query', got %q", v.Details)
	}
}

func TestParseWizCLIJSON_MalwareFindings(t *testing.T) {
	const input = `{"result":{"malwares":[
		{"name":"Trojan.GenericKD","description":"Known malware detected","severity":"HIGH","path":"vendor/evil/lib.so"}
	]}}`
	out, err := parseWizCLIJSON(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 Malware finding, got %d", len(out))
	}
	v := out[0]
	if v.Title != "Trojan.GenericKD" {
		t.Errorf("expected Title 'Trojan.GenericKD', got %q", v.Title)
	}
	if v.Severity != "HIGH" {
		t.Errorf("expected Severity HIGH, got %q", v.Severity)
	}
	if v.File != "vendor/evil/lib.so" {
		t.Errorf("expected File (Code/Path) 'vendor/evil/lib.so', got %q", v.File)
	}
	if v.Line != "" {
		t.Errorf("expected Line '' (line=0 in JSON), got %q", v.Line)
	}
	if v.Details != "Known malware detected" {
		t.Errorf("expected Details 'Known malware detected', got %q", v.Details)
	}
}

func TestParseWizCLIJSON_AIModelFindings(t *testing.T) {
	const input = `{"result":{"aiModels":[
		{"name":"gpt-4","version":"2024-03","severity":"INFO","path":"requirements.txt"}
	]}}`
	out, err := parseWizCLIJSON(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 AIModel finding, got %d", len(out))
	}
	v := out[0]
	if v.Title != "gpt-4" {
		t.Errorf("expected Title 'gpt-4', got %q", v.Title)
	}
	if v.Severity != "INFO" {
		t.Errorf("expected Severity INFO, got %q", v.Severity)
	}
	if v.File != "requirements.txt" {
		t.Errorf("expected File (Path) 'requirements.txt', got %q", v.File)
	}
	if !strings.Contains(v.Details, "gpt-4:2024-03") {
		t.Errorf("expected Details to contain 'gpt-4:2024-03', got %q", v.Details)
	}
}

func TestParseWizCLIJSON_SoftwareSupplyChainFindings(t *testing.T) {
	const input = `{"result":{"softwareSupplyChain":[
		{"name":"lodash","version":"4.17.20","severity":"MEDIUM","license":"MIT","path":"package.json"}
	]}}`
	out, err := parseWizCLIJSON(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 Supply Chain finding, got %d", len(out))
	}
	v := out[0]
	if v.Title != "lodash" {
		t.Errorf("expected Title 'lodash', got %q", v.Title)
	}
	if v.Severity != "MEDIUM" {
		t.Errorf("expected Severity MEDIUM, got %q", v.Severity)
	}
	if v.File != "package.json" {
		t.Errorf("expected File (Path) 'package.json', got %q", v.File)
	}
	if !strings.Contains(v.Details, "lodash:4.17.20") {
		t.Errorf("expected Details to contain 'lodash:4.17.20', got %q", v.Details)
	}
	if !strings.Contains(v.Details, "license: MIT") {
		t.Errorf("expected Details to contain 'license: MIT', got %q", v.Details)
	}
}

func TestParseWizCLIJSON_NullNewFieldsIsNoError(t *testing.T) {
	const input = `{"result":{"iac":null,"sast":null,"malwares":null,"aiModels":null,"softwareSupplyChain":null}}`
	out, err := parseWizCLIJSON(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected 0 findings with null new fields, got %d", len(out))
	}
}

func TestParseWizCLIJSON_Deduplicates(t *testing.T) {
	const input = `{"result":{"libraries":[
		{"name":"lodash","version":"4.17.4","path":"/package-lock.json",
		 "vulnerabilities":[
		   {"name":"CVE-2021-23337","severity":"HIGH","fixedVersion":"4.17.21"},
		   {"name":"CVE-2021-23337","severity":"HIGH","fixedVersion":"4.17.21"}
		 ]}
	]}}`
	out, err := parseWizCLIJSON(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected dedup to 1 finding, got %d", len(out))
	}
}

// ── analyzeWizCLI tests ──────────────────────────────────────────────────────

func TestAnalyzeWizCLI_RealJSONFixture_BucketsAllSeverities(t *testing.T) {
	scanInfo := &SecTestScanInfo{}
	scanInfo.Container.COutput = loadJSONFixture(t)

	if err := analyzeWizCLI(scanInfo); err != nil {
		t.Fatalf("analyzeWizCLI returned unexpected error: %v", err)
	}

	high := len(scanInfo.Vulnerabilities.HighVulns)
	med := len(scanInfo.Vulnerabilities.MediumVulns)
	low := len(scanInfo.Vulnerabilities.LowVulns)
	info := len(scanInfo.Vulnerabilities.NoSecVulns)
	total := high + med + low + info

	if total < 12 {
		t.Errorf("expected at least 12 findings from fixture (12 lib CVEs + 1 secret), got %d (high=%d med=%d low=%d info=%d)",
			total, high, med, low, info)
	}
	if high == 0 {
		t.Error("expected HIGH-severity library CVEs from fixture")
	}
	if med == 0 {
		t.Error("expected MEDIUM-severity library CVEs from fixture")
	}

	// Ensure every finding is tagged WizCLI.
	for _, v := range scanInfo.Vulnerabilities.HighVulns {
		if v.SecurityTool != "WizCLI" {
			t.Errorf("expected SecurityTool=WizCLI, got %q", v.SecurityTool)
		}
	}
}

func TestAnalyzeWizCLI_ErrorAuth(t *testing.T) {
	scanInfo := &SecTestScanInfo{}
	scanInfo.Container.COutput = "ERROR_AUTH_WIZCLI: authentication failed"

	err := analyzeWizCLI(scanInfo)
	if err == nil {
		t.Fatal("expected non-nil error when ERROR_AUTH_WIZCLI is present, got nil")
	}
	if scanInfo.ErrorFound == nil {
		t.Error("expected scanInfo.ErrorFound to be set, got nil")
	}
}

func TestAnalyzeWizCLI_ScanError(t *testing.T) {
	scanInfo := &SecTestScanInfo{}
	scanInfo.Container.COutput = "some partial output\nERROR_RUNNING_WIZCLI_SCAN\n"

	err := analyzeWizCLI(scanInfo)
	if err == nil {
		t.Fatal("expected non-nil error when ERROR_RUNNING_WIZCLI_SCAN is present, got nil")
	}
	if scanInfo.ErrorFound == nil {
		t.Error("expected scanInfo.ErrorFound to be set, got nil")
	}
}

func TestAnalyzeWizCLI_InvalidJSONIsError(t *testing.T) {
	scanInfo := &SecTestScanInfo{}
	scanInfo.Container.COutput = "this is not json at all"

	err := analyzeWizCLI(scanInfo)
	if err == nil {
		t.Fatal("expected non-nil error for non-JSON output, got nil")
	}
	if scanInfo.ErrorFound == nil {
		t.Error("expected scanInfo.ErrorFound to be set, got nil")
	}
}

func TestAnalyzeWizCLI_EmptyOutputIsNoFindings(t *testing.T) {
	scanInfo := &SecTestScanInfo{}
	scanInfo.Container.COutput = ""

	err := analyzeWizCLI(scanInfo)
	if err != nil {
		t.Fatalf("expected nil error for empty output, got %v", err)
	}
	total := len(scanInfo.Vulnerabilities.HighVulns) +
		len(scanInfo.Vulnerabilities.MediumVulns) +
		len(scanInfo.Vulnerabilities.LowVulns) +
		len(scanInfo.Vulnerabilities.NoSecVulns)
	if total != 0 {
		t.Errorf("expected 0 findings for empty output, got %d", total)
	}
}

// ── file path normalization tests (TDD for dependency findings) ───────────────

func TestNormalizeFilePath_AlreadyValid(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		expected string
	}{
		{
			name:     "regular source file",
			filePath: "/src/main.py",
			expected: "src/main.py", // Leading / stripped for SonarQube relative paths
		},
		{
			name:     "file with line reference",
			filePath: "/app/handlers/user.py:42",
			expected: "app/handlers/user.py:42", // Leading / stripped
		},
		{
			name:     "manifest file",
			filePath: "/package-lock.json",
			expected: "package-lock.json", // Leading / stripped
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := normalizeFilePath(tc.filePath, "")
			if result != tc.expected {
				t.Errorf("normalizeFilePath(%q) = %q, want %q", tc.filePath, result, tc.expected)
			}
		})
	}
}

func TestNormalizeFilePath_DependencyPath(t *testing.T) {
	tests := []struct {
		name         string
		filePath     string
		manifestPath string
		expected     string
	}{
		{
			name:         "python package with requirements.txt",
			filePath:     "pytest:7.4.3 (requirements.txt)",
			manifestPath: "/requirements.txt",
			expected:     "requirements.txt:pytest:7.4.3", // No leading / for SonarQube
		},
		{
			name:         "fastapi dependency",
			filePath:     "fastapi:0.104.1 (requirements.txt)",
			manifestPath: "/requirements.txt",
			expected:     "requirements.txt:fastapi:0.104.1",
		},
		{
			name:         "gunicorn without manifest detected",
			filePath:     "gunicorn:21.2.0 (requirements.txt)",
			manifestPath: "",
			expected:     "requirements.txt:gunicorn:21.2.0", // Extracted from parentheses
		},
		{
			name:         "npm package with package-lock.json",
			filePath:     "lodash:4.17.4 (package-lock.json)",
			manifestPath: "/package-lock.json",
			expected:     "package-lock.json:lodash:4.17.4",
		},
		{
			name:         "package without parentheses",
			filePath:     "requests:2.28.0",
			manifestPath: "/requirements.txt",
			expected:     "requirements.txt:requests:2.28.0",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := normalizeFilePath(tc.filePath, tc.manifestPath)
			if result != tc.expected {
				t.Errorf("normalizeFilePath(%q, %q) = %q, want %q",
					tc.filePath, tc.manifestPath, result, tc.expected)
			}
		})
	}
}

func TestNormalizeFilePath_PlaceholderFile(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		expected string
	}{
		{
			name:     "huskyci placeholder",
			filePath: "huskyCI/huskyCI_Placeholder_File",
			expected: "huskyCI/huskyCI_Placeholder_File",
		},
		{
			name:     "generic placeholder without extension",
			filePath: "/placeholder",
			expected: "placeholder", // Leading / stripped for SonarQube
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := normalizeFilePath(tc.filePath, "")
			if result != tc.expected {
				t.Errorf("normalizeFilePath(%q) = %q, want %q", tc.filePath, result, tc.expected)
			}
		})
	}
}

func TestParseWizCLIJSON_LibraryCVEs_NormalizePaths(t *testing.T) {
	const input = `{"result":{"libraries":[
		{"name":"pytest","version":"7.4.3","path":"/requirements.txt",
		 "vulnerabilities":[{"name":"CVE-2023-XXXX","severity":"HIGH","fixedVersion":"7.4.4"}]},
		{"name":"lodash","version":"4.17.4","path":"/package-lock.json",
		 "vulnerabilities":[{"name":"CVE-2021-23337","severity":"HIGH","fixedVersion":"4.17.21"}]}
	]}}`
	out, err := parseWizCLIJSON(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(out))
	}

	// Verify paths are normalized (no leading /) for SonarQube compatibility
	for _, v := range out {
		if strings.HasPrefix(v.File, "/") {
			t.Errorf("expected file path without leading '/', got %q", v.File)
		}
		if strings.Contains(v.File, "(") && strings.Contains(v.File, ")") {
			t.Errorf("expected normalized path without parentheses, got %q", v.File)
		}
	}
}

// ── manifest file detection tests ──────────────────────────────────────────────

func TestDetectManifestType(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		expected string
	}{
		{
			name:     "python requirements.txt",
			filePath: "/requirements.txt",
			expected: "python",
		},
		{
			name:     "python requirements-dev.txt",
			filePath: "/requirements-dev.txt",
			expected: "python",
		},
		{
			name:     "python pyproject.toml",
			filePath: "/pyproject.toml",
			expected: "python",
		},
		{
			name:     "python setup.py",
			filePath: "/setup.py",
			expected: "python",
		},
		{
			name:     "node package-lock.json",
			filePath: "/package-lock.json",
			expected: "node",
		},
		{
			name:     "node yarn.lock",
			filePath: "/yarn.lock",
			expected: "node",
		},
		{
			name:     "node package.json",
			filePath: "/package.json",
			expected: "node",
		},
		{
			name:     "go go.mod",
			filePath: "/go.mod",
			expected: "go",
		},
		{
			name:     "go go.sum",
			filePath: "/go.sum",
			expected: "go",
		},
		{
			name:     "java pom.xml",
			filePath: "/pom.xml",
			expected: "java",
		},
		{
			name:     "ruby gemfile",
			filePath: "/Gemfile",
			expected: "ruby",
		},
		{
			name:     "ruby gemfile.lock",
			filePath: "/Gemfile.lock",
			expected: "ruby",
		},
		{
			name:     "php composer.json",
			filePath: "/composer.json",
			expected: "php",
		},
		{
			name:     "php composer.lock",
			filePath: "/composer.lock",
			expected: "php",
		},
		{
			name:     "unknown manifest",
			filePath: "/some-random.lock",
			expected: "",
		},
		{
			name:     "regular source file",
			filePath: "/src/main.py",
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := detectManifestType(tc.filePath)
			if result != tc.expected {
				t.Errorf("detectManifestType(%q) = %q, want %q", tc.filePath, result, tc.expected)
			}
		})
	}
}

func TestIsManifestFile(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		expected bool
	}{
		{
			name:     "requirements.txt is manifest",
			filePath: "/requirements.txt",
			expected: true,
		},
		{
			name:     "package-lock.json is manifest",
			filePath: "/package-lock.json",
			expected: true,
		},
		{
			name:     "go.mod is manifest",
			filePath: "/go.mod",
			expected: true,
		},
		{
			name:     "regular python file is not manifest",
			filePath: "/src/app.py",
			expected: false,
		},
		{
			name:     "regular js file is not manifest",
			filePath: "/index.js",
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := isManifestFile(tc.filePath)
			if result != tc.expected {
				t.Errorf("isManifestFile(%q) = %v, want %v", tc.filePath, result, tc.expected)
			}
		})
	}
}

// ── SonarQube output validation tests ───────────────────────────────────────────

func TestValidateSonarQubeFilePath(t *testing.T) {
	tests := []struct {
		name        string
		filePath    string
		shouldError bool
		description string
	}{
		{
			name:        "valid_source_file",
			filePath:    "src/main.py",
			shouldError: false,
			description: "Regular source files should pass validation",
		},
		{
			name:        "valid_manifest_file",
			filePath:    "requirements.txt",
			shouldError: false,
			description: "Manifest files like requirements.txt should pass",
		},
		{
			name:        "valid_composite_path",
			filePath:    "requirements.txt:pytest:7.4.3",
			shouldError: false,
			description: "Composite manifest:package:version paths should pass",
		},
		{
			name:        "invalid_package_version_only",
			filePath:    "pytest:7.4.3 (requirements.txt)",
			shouldError: true,
			description: "Raw package:version (requirements.txt) format should fail - SonarQube rejects it",
		},
		{
			name:        "invalid_leading_slash",
			filePath:    "/src/main.py",
			shouldError: true,
			description: "Paths with leading slash should fail - SonarQube expects relative paths",
		},
		{
			name:        "invalid_leading_dot_slash",
			filePath:    "./src/main.py",
			shouldError: true,
			description: "Paths with ./ prefix should fail - SonarQube expects relative paths",
		},
		{
			name:        "invalid_placeholder",
			filePath:    "huskyCI/huskyCI_Placeholder_File",
			shouldError: true,
			description: "Placeholder files should fail - not real files in project",
		},
		{
			name:        "empty_path",
			filePath:    "",
			shouldError: true,
			description: "Empty paths should fail validation",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSonarQubeFilePath(tc.filePath)
			if tc.shouldError && err == nil {
				t.Errorf("%s: expected error for %q, got nil", tc.description, tc.filePath)
			}
			if !tc.shouldError && err != nil {
				t.Errorf("%s: expected no error for %q, got %v", tc.description, tc.filePath, err)
			}
		})
	}
}

func TestGenerateSonarQubeExternalIssue(t *testing.T) {
	tests := []struct {
		name string
		vuln types.HuskyCIVulnerability
	}{
		{
			name: "dependency vulnerability in manifest",
			vuln: types.HuskyCIVulnerability{
				Title:        "CVE-2023-XXXX",
				Severity:     "HIGH",
				File:         "requirements.txt:pytest:7.4.3",
				Line:         "5",
				Details:       "CVE-2023-XXXX (fixed: 7.4.4)",
				SecurityTool: "WizCLI",
			},
		},
		{
			name: "source code vulnerability",
			vuln: types.HuskyCIVulnerability{
				Title:        "SQL Injection",
				Severity:     "CRITICAL",
				File:         "app/db/queries.py",
				Line:         "42",
				Details:       "Potential SQL injection in user input",
				SecurityTool: "WizCLI",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			issue := generateSonarQubeExternalIssue(tc.vuln)

			// Verify the issue has required fields
			if issue.EngineID == "" {
				t.Error("expected EngineID to be set")
			}
			if issue.RuleID == "" {
				t.Error("expected RuleID to be set")
			}
			if issue.PrimaryLocation.Message == "" {
				t.Error("expected Message to be set")
			}
			if issue.PrimaryLocation.FilePath == "" {
				t.Error("expected FilePath to be set")
			}

			// Verify file path is normalized (doesn't contain parentheses)
			if strings.Contains(issue.PrimaryLocation.FilePath, "(") {
				t.Errorf("file path should not contain parentheses: %q", issue.PrimaryLocation.FilePath)
			}
			// Verify file path does NOT start with / (SonarQube expects relative paths)
			if strings.HasPrefix(issue.PrimaryLocation.FilePath, "/") {
				t.Errorf("file path should not start with '/': %q", issue.PrimaryLocation.FilePath)
			}
		})
	}
}
