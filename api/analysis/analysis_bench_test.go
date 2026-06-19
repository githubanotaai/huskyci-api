// Copyright 2026 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package analysis

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/githubanotaai/huskyci-api/api/types"
	"go.mongodb.org/mongo-driver/bson"
)

const (
	// Threshold constants for BSON encoding benchmarks.
	warningBSONSizeBytes = 14 * 1024 * 1024 // 14 MiB
	allocMultiplier      = 3
)

// cOutputVariants returns the COutput strings used across sub-benchmarks.
// Empty, 1 MiB placeholder, and an errorFound-prefixed large string.
func cOutputVariants() map[string]string {
	return map[string]string{
		"empty":      "",
		"1MB":        strings.Repeat("x", 1024*1024),
		"errorFound": "errorFound: " + strings.Repeat("y", 1024*1024),
	}
}

// vulnCounts returns the vulnerability counts used across sub-benchmarks.
func vulnCounts() []int {
	return []int{1000, 10000, 50000}
}

// buildVulnerability creates a realistic HuskyCIVulnerability with all fields
// populated to maximise document size and represent a worst-case payload.
func buildVulnerability(language, tool, severity, file string, line int) types.HuskyCIVulnerability {
	return types.HuskyCIVulnerability{
		Language:       language,
		SecurityTool:   tool,
		Severity:       severity,
		Confidence:     "high",
		File:           file,
		Line:           fmt.Sprintf("%d", line),
		Code:           fmt.Sprintf("vulnerable_call_%d()", line),
		Details:        fmt.Sprintf("Vulnerability found at %s:%d by %s - detailed description of the security issue including remediation steps and CWE references", file, line, tool),
		Type:           "CWE-79",
		Title:          fmt.Sprintf("XSS vulnerability in %s at %s line %d", tool, file, line),
		VunerableBelow: "1.2.3",
		Version:        "1.0.0",
		Occurrences:    1,
	}
}

// buildSecurityTestOutput returns a HuskyCISecurityTestOutput filled with the
// given number of vulnerabilities, balanced across severity levels.
func buildSecurityTestOutput(language, tool, filename string, count int) types.HuskyCISecurityTestOutput {
	out := types.HuskyCISecurityTestOutput{
		NoSecVulns:  make([]types.HuskyCIVulnerability, 0, count),
		LowVulns:    make([]types.HuskyCIVulnerability, 0, count),
		MediumVulns: make([]types.HuskyCIVulnerability, 0, count),
		HighVulns:   make([]types.HuskyCIVulnerability, 0, count),
	}
	for i := 0; i < count; i++ {
		severity := []string{"info", "low", "medium", "high"}[i%4]
		v := buildVulnerability(language, tool, severity, filename, i+1)
		switch severity {
		case "info":
			out.NoSecVulns = append(out.NoSecVulns, v)
		case "low":
			out.LowVulns = append(out.LowVulns, v)
		case "medium":
			out.MediumVulns = append(out.MediumVulns, v)
		case "high":
			out.HighVulns = append(out.HighVulns, v)
		}
	}
	return out
}

// buildWorstCaseAnalysis constructs a worst-case types.Analysis document with
// totalVulns HuskyCIVulnerabilities distributed across all language-specific
// result types, realistic Container instances, and Code entries. COutput
// controls the Container.COutput field size.
func buildWorstCaseAnalysis(totalVulns int, containerOutput string) types.Analysis {
	// Distribute vulns across the 8 result types (Go, Python×2, JS×3, Java,
	// Ruby, HCL, C#, Generic×5 = ~16 slots).
	allLanguages := []struct {
		language string
		tool     string
		filename string
	}{
		{"Go", "gosec", "main.go"},
		{"Python", "bandit", "app.py"},
		{"Python", "safety", "requirements.txt"},
		{"JavaScript", "npmaudit", "package.json"},
		{"JavaScript", "yarnaudit", "yarn.lock"},
		{"JavaScript", "pnpm-audit", "pnpm-lock.yaml"},
		{"Java", "spotbugs", "Main.java"},
		{"Ruby", "brakeman", "app/controllers/users_controller.rb"},
		{"HCL", "tfsec", "main.tf"},
		{"C#", "securitycodescan", "Program.cs"},
		{"Generic", "gitleaks", ".git/config"},
		{"Generic", "wizcli-secrets", "config.yaml"},
		{"Generic", "iac", "terraform.tf"},
		{"Generic", "wizcli-sast", "src/app.js"},
		{"Generic", "wizcli-vulns", "Dockerfile"},
	}

	numSlots := len(allLanguages)
	basePerSlot := totalVulns / numSlots
	remainder := totalVulns % numSlots

	goVulns := 0
	pyBandit := 0
	pySafety := 0
	jsNpm := 0
	jsYarn := 0
	jsPnpm := 0
	javaVulns := 0
	rubyVulns := 0
	hclVulns := 0
	csharpVulns := 0
	genGitleaks := 0
	genWizSecrets := 0
	genIac := 0
	genWizSast := 0
	genWizVulns := 0

	// Assign vulns per slot; distribute remainder to early slots.
	for i := 0; i < numSlots; i++ {
		count := basePerSlot
		if remainder > 0 {
			count++
			remainder--
		}
		switch i {
		case 0:
			goVulns = count
		case 1:
			pyBandit = count
		case 2:
			pySafety = count
		case 3:
			jsNpm = count
		case 4:
			jsYarn = count
		case 5:
			jsPnpm = count
		case 6:
			javaVulns = count
		case 7:
			rubyVulns = count
		case 8:
			hclVulns = count
		case 9:
			csharpVulns = count
		case 10:
			genGitleaks = count
		case 11:
			genWizSecrets = count
		case 12:
			genIac = count
		case 13:
			genWizSast = count
		case 14:
			genWizVulns = count
		}
	}

	now := time.Now()

	a := types.Analysis{
		RID:    "benchmark-rid-000000000000000000000001",
		URL:    "https://github.com/example/very-large-monorepo.git",
		Branch: "main",
		CommitAuthors: []string{
			"author-one@example.com",
			"author-two@example.com",
		},
		Status: "finished",
		Result: "passed",
		Containers: []types.Container{
			{
				CID: "container-bench-0000000000000000000001",
				SecurityTest: types.SecurityTest{
					Name:             "gosec",
					Image:            "huskyci/gosec:latest",
					ImageTag:         "latest",
					Cmd:              "gosec ./...",
					Type:             "Go",
					Language:         "Go",
					Default:          true,
					TimeOutInSeconds: 600,
				},
				CStatus:    "finished",
				COutput:    containerOutput,
				CResult:    "passed",
				CInfo:      "scanned 500 files",
				StartedAt:  now.Add(-5 * time.Minute),
				FinishedAt: now,
			},
			{
				CID: "container-bench-0000000000000000000002",
				SecurityTest: types.SecurityTest{
					Name:             "bandit",
					Image:            "huskyci/bandit:latest",
					ImageTag:         "latest",
					Cmd:              "bandit -r .",
					Type:             "Python",
					Language:         "Python",
					Default:          true,
					TimeOutInSeconds: 600,
				},
				CStatus:    "finished",
				COutput:    containerOutput,
				CResult:    "passed",
				CInfo:      "scanned 200 Python files",
				StartedAt:  now.Add(-4 * time.Minute),
				FinishedAt: now,
			},
			{
				CID: "container-bench-0000000000000000000003",
				SecurityTest: types.SecurityTest{
					Name:             "npmaudit",
					Image:            "huskyci/npmaudit:latest",
					ImageTag:         "latest",
					Cmd:              "npm audit --json",
					Type:             "JavaScript",
					Language:         "JavaScript",
					Default:          true,
					TimeOutInSeconds: 600,
				},
				CStatus:    "finished",
				COutput:    containerOutput,
				CResult:    "failed",
				CInfo:      "found 42 vulnerabilities",
				StartedAt:  now.Add(-3 * time.Minute),
				FinishedAt: now,
			},
		},
		Codes: []types.Code{
			{Language: "Go", Files: []string{"main.go", "handlers/auth.go", "db/query.go", "middleware/logging.go", "config/config.go"}},
			{Language: "Python", Files: []string{"app.py", "utils/security.py", "models/user.py", "views/dashboard.py"}},
			{Language: "JavaScript", Files: []string{"src/index.js", "src/components/Login.jsx", "src/api/client.js", "src/utils/validators.js"}},
			{Language: "Java", Files: []string{"src/main/java/com/example/Main.java", "src/main/java/com/example/SecurityConfig.java"}},
			{Language: "Ruby", Files: []string{"app/controllers/application_controller.rb", "app/models/user.rb"}},
			{Language: "HCL", Files: []string{"main.tf", "variables.tf", "outputs.tf"}},
			{Language: "C#", Files: []string{"Program.cs", "Startup.cs", "SecurityMiddleware.cs"}},
		},
		StartedAt:  now.Add(-10 * time.Minute),
		FinishedAt: now,
		ErrorFound: "",
		HuskyCIResults: types.HuskyCIResults{
			GoResults: types.GoResults{
				HuskyCIGosecOutput: buildSecurityTestOutput("Go", "gosec", "main.go", goVulns),
			},
			PythonResults: types.PythonResults{
				HuskyCIBanditOutput: buildSecurityTestOutput("Python", "bandit", "app.py", pyBandit),
				HuskyCISafetyOutput: buildSecurityTestOutput("Python", "safety", "requirements.txt", pySafety),
			},
			JavaScriptResults: types.JavaScriptResults{
				HuskyCINpmAuditOutput:  buildSecurityTestOutput("JavaScript", "npmaudit", "package.json", jsNpm),
				HuskyCIYarnAuditOutput: buildSecurityTestOutput("JavaScript", "yarnaudit", "yarn.lock", jsYarn),
				HuskyCIPnpmAuditOutput: buildSecurityTestOutput("JavaScript", "pnpm-audit", "pnpm-lock.yaml", jsPnpm),
			},
			JavaResults: types.JavaResults{
				HuskyCISpotBugsOutput: buildSecurityTestOutput("Java", "spotbugs", "Main.java", javaVulns),
			},
			RubyResults: types.RubyResults{
				HuskyCIBrakemanOutput: buildSecurityTestOutput("Ruby", "brakeman", "app/controllers/users_controller.rb", rubyVulns),
			},
			HclResults: types.HclResults{
				HuskyCITFSecOutput: buildSecurityTestOutput("HCL", "tfsec", "main.tf", hclVulns),
			},
			CSharpResults: types.CsharpResults{
				HuskyCISecurityCodeScanOutput: buildSecurityTestOutput("C#", "securitycodescan", "Program.cs", csharpVulns),
			},
			GenericResults: types.GenericResults{
				HuskyCIGitleaksOutput:      buildSecurityTestOutput("Generic", "gitleaks", ".git/config", genGitleaks),
				HuskyCIWizCLISecretsOutput: buildSecurityTestOutput("Generic", "wizcli-secrets", "config.yaml", genWizSecrets),
				HuskyCIIacOutput:           buildSecurityTestOutput("Generic", "iac", "terraform.tf", genIac),
				HuskyCIWizCLISastOutput:    buildSecurityTestOutput("Generic", "wizcli-sast", "src/app.js", genWizSast),
				HuskyCIWizCLIVulnsOutput:   buildSecurityTestOutput("Generic", "wizcli-vulns", "Dockerfile", genWizVulns),
			},
		},
	}

	return a
}

// BenchmarkAnalysisBSONEncodingWorstCase measures BSON encoding time and
// allocation size for worst-case Analysis documents across varying
// vulnerability counts and Container.COutput sizes.
//
// Input range: vulns={1k,10k,50k} × cOutput={empty,1MB,errorFound}.
// Reference: docs/assessments/performance-gap-assessment-01.md Phase 6,
// BSON encoding spec; gap analysis finding #11 (document size).
func BenchmarkAnalysisBSONEncodingWorstCase(b *testing.B) {
	vulns := vulnCounts()
	outputs := cOutputVariants()

	for _, vc := range vulns {
		for outName, outValue := range outputs {
			name := fmt.Sprintf("vulns=%d/cOutput=%s", vc, outName)
			b.Run(name, func(b *testing.B) {
				b.ReportAllocs()

				// Build once outside the loop — Marshal is the measured operation.
				analysis := buildWorstCaseAnalysis(vc, outValue)

				// Pre-compute allocs for threshold check using testing.AllocsPerRun.
				allocsPerOp := int64(testing.AllocsPerRun(1, func() {
					_, _ = bson.Marshal(analysis)
				}))

				var encodedSize int64
				b.ResetTimer()

				for b.Loop() {
					data, err := bson.Marshal(analysis)
					if err != nil {
						b.Fatalf("bson.Marshal failed: %v", err)
					}
					encodedSize = int64(len(data))
				}

				// Report the encoded BSON document size as a custom metric.
				b.ReportMetric(float64(encodedSize), "bson-bytes/op")

				// Threshold checks.
				if encodedSize > warningBSONSizeBytes {
					b.Logf("WARNING: BSON size %d bytes exceeds %d MiB threshold (%.2f MiB)",
						encodedSize, warningBSONSizeBytes/(1024*1024),
						float64(encodedSize)/(1024*1024))
				}
				if allocsPerOp > encodedSize*allocMultiplier {
					b.Logf("WARNING: allocs/op %d exceeds BSON_size×%d = %d",
						allocsPerOp, allocMultiplier, encodedSize*allocMultiplier)
				}
			})
		}
	}
}
