package securitytest

import (
	"context"
	"os"
	"strings"
	"sync"

	apiContext "github.com/githubanotaai/huskyci-api/api/context"
	"github.com/githubanotaai/huskyci-api/api/log"
	"github.com/githubanotaai/huskyci-api/api/types"
	"golang.org/x/sync/errgroup"
)

// RunAllInfo store all scans results of an Analysis
type RunAllInfo struct {
	runner         scanRunner        `json:"-" bson:"-"`
	mu             sync.Mutex        `json:"-" bson:"-"`
	RID            string
	Status         string
	Containers     []types.Container
	CommitAuthors  []string
	Codes          []types.Code
	FinalResult    string
	ErrorFound     error
	HuskyCIResults types.HuskyCIResults

	// Lockfile-not-found tracking for coalescing into a single HIGH vuln
	// when no JS package manager lockfile exists in the repo.
	NpmLockNotFound  bool
	YarnLockNotFound bool
	PnpmLockNotFound bool
}

const bandit = "bandit"
const brakeman = "brakeman"
const safety = "safety"
const gosec = "gosec"
const npmaudit = "npmaudit"
const yarnaudit = "yarnaudit"
const pnpmaudit = "pnpmaudit"
const spotbugs = "spotbugs"
const gitleaks = "gitleaks"
const tfsec = "tfsec"
const securitycodescan = "securitycodescan"
const (
	wizcliSecrets = "wizcli_secrets"
	wizcliIacSast  = "wizcli_iac_sast"
	wizcliVulns    = "wizcli_vulns"
)

// isTestDisabled checks if a security test is disabled via environment variable.
// The env var pattern is: HUSKYCI_DISABLE_<TESTNAME> (e.g., HUSKYCI_DISABLE_GITAUTHORS=true)
// Returns true if the test should be skipped.
func isTestDisabled(testName string) bool {
	envVarName := "HUSKYCI_DISABLE_" + strings.ToUpper(testName)
	value := os.Getenv(envVarName)
	return strings.ToLower(value) == "true" || value == "1"
}

// Start runs both generic and language security
func (results *RunAllInfo) Start(enryScan SecTestScanInfo) error {
	results.Codes = enryScan.Codes
	defer results.setToAnalysis()

	g, ctx := errgroup.WithContext(context.Background())

	g.Go(func() error {
		return results.runGenericScans(ctx, enryScan)
	})
	g.Go(func() error {
		return results.runLanguageScans(ctx, enryScan)
	})

	if err := g.Wait(); err != nil {
		results.ErrorFound = err
		return err
	}

	results.setFinalResult()
	return nil
}

func (results *RunAllInfo) runGenericScans(ctx context.Context, enryScan SecTestScanInfo) error {
	g, ctx := errgroup.WithContext(ctx)
	runner := results.getRunner()

	genericTests, err := runner.listGenericTests()
	if err != nil {
		return err
	}

	for i := range genericTests {
		testName := genericTests[i].Name
		if isTestDisabled(testName) {
			log.Info("runGenericScans", "SECURITYTEST", 0, "Skipping disabled test: "+testName)
			continue
		}
		g.Go(func() error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			scan, err := runner.newScan(enryScan.RID, enryScan.URL, enryScan.Branch, testName, nil, enryScan.DockerHost)
			if err != nil {
				return err
			}
			if err := runner.startScan(scan); err != nil {
				return err
			}
			results.mu.Lock()
			results.Containers = append(results.Containers, scan.Container)
			switch testName {
			case "gitauthors":
				results.CommitAuthors = scan.CommitAuthors.Authors
			case "gitleaks", "wizcli_secrets", "wizcli_iac_sast", "wizcli_vulns":
				results.setVulns(*scan)
			}
			results.mu.Unlock()
			return nil
		})
	}

	return g.Wait()
}

func (results *RunAllInfo) runLanguageScans(ctx context.Context, enryScan SecTestScanInfo) error {
	g, ctx := errgroup.WithContext(ctx)
	runner := results.getRunner()

	languageTests := []types.SecurityTest{}
	for _, code := range enryScan.Codes {
		codeTests, err := runner.listLanguageTests(code.Language)
		if err != nil {
			return err
		}
		languageTests = append(languageTests, codeTests...)
	}

	for i := range languageTests {
		testName := languageTests[i].Name
		if isTestDisabled(testName) {
			log.Info("runLanguageScans", "SECURITYTEST", 0, "Skipping disabled test: "+testName)
			continue
		}
		g.Go(func() error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			scan, err := runner.newScan(enryScan.RID, enryScan.URL, enryScan.Branch, testName, nil, enryScan.DockerHost)
			if err != nil {
				return err
			}
			if err := runner.startScan(scan); err != nil {
				results.mu.Lock()
				results.Containers = append(results.Containers, scan.Container)
				results.mu.Unlock()
				return err
			}
			results.mu.Lock()
			results.Containers = append(results.Containers, scan.Container)
			results.setVulns(*scan)
			// Propagate lockfile-not-found flags for coalescing
			if scan.PackageNotFound {
				results.NpmLockNotFound = true
			}
			if scan.YarnLockNotFound {
				results.YarnLockNotFound = true
			}
			if scan.PnpmLockNotFound {
				results.PnpmLockNotFound = true
			}
			results.mu.Unlock()
			return nil
		})
	}

	return g.Wait()
}

// vulnOutput maps a security test name to its corresponding HuskyCISecurityTestOutput pointer.
func (results *RunAllInfo) vulnOutput(securityTestName string) *types.HuskyCISecurityTestOutput {
	switch securityTestName {
	case bandit:
		return &results.HuskyCIResults.PythonResults.HuskyCIBanditOutput
	case brakeman:
		return &results.HuskyCIResults.RubyResults.HuskyCIBrakemanOutput
	case safety:
		return &results.HuskyCIResults.PythonResults.HuskyCISafetyOutput
	case gosec:
		return &results.HuskyCIResults.GoResults.HuskyCIGosecOutput
	case npmaudit:
		return &results.HuskyCIResults.JavaScriptResults.HuskyCINpmAuditOutput
	case yarnaudit:
		return &results.HuskyCIResults.JavaScriptResults.HuskyCIYarnAuditOutput
	case pnpmaudit:
		return &results.HuskyCIResults.JavaScriptResults.HuskyCIPnpmAuditOutput
	case spotbugs:
		return &results.HuskyCIResults.JavaResults.HuskyCISpotBugsOutput
	case gitleaks:
		return &results.HuskyCIResults.GenericResults.HuskyCIGitleaksOutput
	case wizcliSecrets, "wizcli": // "wizcli" migration safeguard — routes to secrets output
		return &results.HuskyCIResults.GenericResults.HuskyCIWizCLISecretsOutput
	case wizcliIacSast:
		return &results.HuskyCIResults.GenericResults.HuskyCIIacSastOutput
	case wizcliVulns:
		return &results.HuskyCIResults.GenericResults.HuskyCIWizCLIVulnsOutput
	case tfsec:
		return &results.HuskyCIResults.HclResults.HuskyCITFSecOutput
	case securitycodescan:
		return &results.HuskyCIResults.CSharpResults.HuskyCISecurityCodeScanOutput
	default:
		return nil
	}
}

func (results *RunAllInfo) setVulns(securityTestScan SecTestScanInfo) {
	output := results.vulnOutput(securityTestScan.SecurityTestName)
	if output == nil {
		return
	}
	output.HighVulns = append(output.HighVulns, securityTestScan.Vulnerabilities.HighVulns...)
	output.MediumVulns = append(output.MediumVulns, securityTestScan.Vulnerabilities.MediumVulns...)
	output.LowVulns = append(output.LowVulns, securityTestScan.Vulnerabilities.LowVulns...)
	output.NoSecVulns = append(output.NoSecVulns, securityTestScan.Vulnerabilities.NoSecVulns...)
}

// SetAnalysisError sets error on an analysis that did not got to the setToAnalysis phase
func (results *RunAllInfo) SetAnalysisError(err error) {
	results.ErrorFound = err
	results.Status = "error running"
	results.FinalResult = "error"
}

func (results *RunAllInfo) setToAnalysis() {

	results.Status = "finished"
	results.FinalResult = "passed"

	if results.ErrorFound != nil {
		results.Status = "error running"
		results.FinalResult = "error"
		return
	}

	// Coalesce: when all three JS package manager lockfiles are missing,
	// replace the three individual LOW vulns with a single HIGH vuln.
	results.coalesceJsLockfileErrors()

	jsWarningFlag := false

	for _, container := range results.Containers {
		switch container.CResult {
		case "warning":
			if container.SecurityTest.Language == "JavaScript" {
				if jsWarningFlag {
					results.FinalResult = "warning"
				} else {
					jsWarningFlag = true
				}
			} else {
				results.FinalResult = "warning"
			}
		case "failed":
			results.FinalResult = "failed"
			return
		}
	}
}

func getAllDefaultSecurityTests(typeOf, language string) ([]types.SecurityTest, error) {
	securityTestQuery := map[string]interface{}{"type": typeOf, "default": true}
	if language != "" {
		securityTestQuery = map[string]interface{}{"language": language, "default": true}
	}
	securityTests, err := apiContext.APIConfiguration.DBInstance.FindAllDBSecurityTest(securityTestQuery)
	if err != nil {
		if err.Error() == "no data found" {
			return securityTests, nil
		}
		log.Error("getAllDefaultSecurityTests", "SECURITYTEST", 2009, err)
		return securityTests, err
	}
	return securityTests, nil
}

// coalesceJsLockfileErrors checks if all three JS package manager lockfiles
// are missing from the repo. When all three scanners report lockfile-not-found,
// the three individual LOW vulns are replaced with a single HIGH vuln on the
// PnpmAudit output. This prevents noise and surfaces the real problem: no
// lockfile means HuskyCI cannot audit the repo's dependencies at all.
func (results *RunAllInfo) coalesceJsLockfileErrors() {
	if !results.NpmLockNotFound || !results.YarnLockNotFound || !results.PnpmLockNotFound {
		return
	}

	// Clear the individual LOW vulns from all three outputs.
	results.HuskyCIResults.JavaScriptResults.HuskyCINpmAuditOutput.LowVulns = nil
	results.HuskyCIResults.JavaScriptResults.HuskyCIYarnAuditOutput.LowVulns = nil
	results.HuskyCIResults.JavaScriptResults.HuskyCIPnpmAuditOutput.LowVulns = nil

	// Emit a single HIGH vuln on the PnpmAudit output.
	highVuln := types.HuskyCIVulnerability{
		Language:     "JavaScript",
		SecurityTool: "PnpmAudit",
		Severity:     "high",
		Title:        "No lockfile found in the repository.",
		Details:      "It looks like your project doesn't have a package-lock.json, yarn.lock, or pnpm-lock.yaml file. huskyCI needs a lockfile to audit your dependencies for vulnerabilities. Please commit the lockfile of the package manager you use (npm, yarn, or pnpm).",
	}
	results.HuskyCIResults.JavaScriptResults.HuskyCIPnpmAuditOutput.HighVulns = append(
		results.HuskyCIResults.JavaScriptResults.HuskyCIPnpmAuditOutput.HighVulns,
		highVuln,
	)
}

func (results *RunAllInfo) setFinalResult() {
	// Logic to determine the final result based on scan results.
	// For example, if all scans passed, set FinalResult to "passed".
	// If any critical scan failed, set FinalResult to "failed".
	passed := true
	for _, container := range results.Containers {
		if container.CResult == "failed" {
			passed = false
			break
		}
	}
	if passed {
		results.FinalResult = "passed"
	} else {
		results.FinalResult = "failed"
	}
}

func (results *RunAllInfo) getRunner() scanRunner {
	if results.runner != nil {
		return results.runner
	}
	return realRunner{}
}
