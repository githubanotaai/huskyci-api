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
}

const bandit = "bandit"
const brakeman = "brakeman"
const safety = "safety"
const gosec = "gosec"
const npmaudit = "npmaudit"
const yarnaudit = "yarnaudit"
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
			results.mu.Unlock()
			return nil
		})
	}

	return g.Wait()
}

func (results *RunAllInfo) setVulns(securityTestScan SecTestScanInfo) {

	for _, highVuln := range securityTestScan.Vulnerabilities.HighVulns {
		switch securityTestScan.SecurityTestName {
		case bandit:
			results.HuskyCIResults.PythonResults.HuskyCIBanditOutput.HighVulns = append(results.HuskyCIResults.PythonResults.HuskyCIBanditOutput.HighVulns, highVuln)
		case brakeman:
			results.HuskyCIResults.RubyResults.HuskyCIBrakemanOutput.HighVulns = append(results.HuskyCIResults.RubyResults.HuskyCIBrakemanOutput.HighVulns, highVuln)
		case safety:
			results.HuskyCIResults.PythonResults.HuskyCISafetyOutput.HighVulns = append(results.HuskyCIResults.PythonResults.HuskyCISafetyOutput.HighVulns, highVuln)
		case gosec:
			results.HuskyCIResults.GoResults.HuskyCIGosecOutput.HighVulns = append(results.HuskyCIResults.GoResults.HuskyCIGosecOutput.HighVulns, highVuln)
		case npmaudit:
			results.HuskyCIResults.JavaScriptResults.HuskyCINpmAuditOutput.HighVulns = append(results.HuskyCIResults.JavaScriptResults.HuskyCINpmAuditOutput.HighVulns, highVuln)
		case yarnaudit:
			results.HuskyCIResults.JavaScriptResults.HuskyCIYarnAuditOutput.HighVulns = append(results.HuskyCIResults.JavaScriptResults.HuskyCIYarnAuditOutput.HighVulns, highVuln)
		case spotbugs:
			results.HuskyCIResults.JavaResults.HuskyCISpotBugsOutput.HighVulns = append(results.HuskyCIResults.JavaResults.HuskyCISpotBugsOutput.HighVulns, highVuln)
		case gitleaks:
			results.HuskyCIResults.GenericResults.HuskyCIGitleaksOutput.HighVulns = append(results.HuskyCIResults.GenericResults.HuskyCIGitleaksOutput.HighVulns, highVuln)
		case wizcliSecrets:
			results.HuskyCIResults.GenericResults.HuskyCIWizCLISecretsOutput.HighVulns = append(results.HuskyCIResults.GenericResults.HuskyCIWizCLISecretsOutput.HighVulns, highVuln)
		case wizcliIacSast:
			results.HuskyCIResults.GenericResults.HuskyCIIacSastOutput.HighVulns = append(results.HuskyCIResults.GenericResults.HuskyCIIacSastOutput.HighVulns, highVuln)
		case wizcliVulns:
			results.HuskyCIResults.GenericResults.HuskyCIWizCLIVulnsOutput.HighVulns = append(results.HuskyCIResults.GenericResults.HuskyCIWizCLIVulnsOutput.HighVulns, highVuln)
		case tfsec:
			results.HuskyCIResults.HclResults.HuskyCITFSecOutput.HighVulns = append(results.HuskyCIResults.HclResults.HuskyCITFSecOutput.HighVulns, highVuln)
		case securitycodescan:
			results.HuskyCIResults.CSharpResults.HuskyCISecurityCodeScanOutput.HighVulns = append(results.HuskyCIResults.CSharpResults.HuskyCISecurityCodeScanOutput.HighVulns, highVuln)
		}
	}

	for _, mediumVuln := range securityTestScan.Vulnerabilities.MediumVulns {
		switch securityTestScan.SecurityTestName {
		case bandit:
			results.HuskyCIResults.PythonResults.HuskyCIBanditOutput.MediumVulns = append(results.HuskyCIResults.PythonResults.HuskyCIBanditOutput.MediumVulns, mediumVuln)
		case brakeman:
			results.HuskyCIResults.RubyResults.HuskyCIBrakemanOutput.MediumVulns = append(results.HuskyCIResults.RubyResults.HuskyCIBrakemanOutput.MediumVulns, mediumVuln)
		case safety:
			results.HuskyCIResults.PythonResults.HuskyCISafetyOutput.MediumVulns = append(results.HuskyCIResults.PythonResults.HuskyCISafetyOutput.MediumVulns, mediumVuln)
		case gosec:
			results.HuskyCIResults.GoResults.HuskyCIGosecOutput.MediumVulns = append(results.HuskyCIResults.GoResults.HuskyCIGosecOutput.MediumVulns, mediumVuln)
		case npmaudit:
			results.HuskyCIResults.JavaScriptResults.HuskyCINpmAuditOutput.MediumVulns = append(results.HuskyCIResults.JavaScriptResults.HuskyCINpmAuditOutput.MediumVulns, mediumVuln)
		case yarnaudit:
			results.HuskyCIResults.JavaScriptResults.HuskyCIYarnAuditOutput.MediumVulns = append(results.HuskyCIResults.JavaScriptResults.HuskyCIYarnAuditOutput.MediumVulns, mediumVuln)
		case spotbugs:
			results.HuskyCIResults.JavaResults.HuskyCISpotBugsOutput.MediumVulns = append(results.HuskyCIResults.JavaResults.HuskyCISpotBugsOutput.MediumVulns, mediumVuln)
		case gitleaks:
			results.HuskyCIResults.GenericResults.HuskyCIGitleaksOutput.MediumVulns = append(results.HuskyCIResults.GenericResults.HuskyCIGitleaksOutput.MediumVulns, mediumVuln)
		case wizcliSecrets:
			results.HuskyCIResults.GenericResults.HuskyCIWizCLISecretsOutput.MediumVulns = append(results.HuskyCIResults.GenericResults.HuskyCIWizCLISecretsOutput.MediumVulns, mediumVuln)
		case wizcliIacSast:
			results.HuskyCIResults.GenericResults.HuskyCIIacSastOutput.MediumVulns = append(results.HuskyCIResults.GenericResults.HuskyCIIacSastOutput.MediumVulns, mediumVuln)
		case wizcliVulns:
			results.HuskyCIResults.GenericResults.HuskyCIWizCLIVulnsOutput.MediumVulns = append(results.HuskyCIResults.GenericResults.HuskyCIWizCLIVulnsOutput.MediumVulns, mediumVuln)
		case tfsec:
			results.HuskyCIResults.HclResults.HuskyCITFSecOutput.MediumVulns = append(results.HuskyCIResults.HclResults.HuskyCITFSecOutput.MediumVulns, mediumVuln)
		case securitycodescan:
			results.HuskyCIResults.CSharpResults.HuskyCISecurityCodeScanOutput.MediumVulns = append(results.HuskyCIResults.CSharpResults.HuskyCISecurityCodeScanOutput.MediumVulns, mediumVuln)
		}
	}

	for _, lowVuln := range securityTestScan.Vulnerabilities.LowVulns {
		switch securityTestScan.SecurityTestName {
		case bandit:
			results.HuskyCIResults.PythonResults.HuskyCIBanditOutput.LowVulns = append(results.HuskyCIResults.PythonResults.HuskyCIBanditOutput.LowVulns, lowVuln)
		case brakeman:
			results.HuskyCIResults.RubyResults.HuskyCIBrakemanOutput.LowVulns = append(results.HuskyCIResults.RubyResults.HuskyCIBrakemanOutput.LowVulns, lowVuln)
		case safety:
			results.HuskyCIResults.PythonResults.HuskyCISafetyOutput.LowVulns = append(results.HuskyCIResults.PythonResults.HuskyCISafetyOutput.LowVulns, lowVuln)
		case gosec:
			results.HuskyCIResults.GoResults.HuskyCIGosecOutput.LowVulns = append(results.HuskyCIResults.GoResults.HuskyCIGosecOutput.LowVulns, lowVuln)
		case npmaudit:
			results.HuskyCIResults.JavaScriptResults.HuskyCINpmAuditOutput.LowVulns = append(results.HuskyCIResults.JavaScriptResults.HuskyCINpmAuditOutput.LowVulns, lowVuln)
		case yarnaudit:
			results.HuskyCIResults.JavaScriptResults.HuskyCIYarnAuditOutput.LowVulns = append(results.HuskyCIResults.JavaScriptResults.HuskyCIYarnAuditOutput.LowVulns, lowVuln)
		case spotbugs:
			results.HuskyCIResults.JavaResults.HuskyCISpotBugsOutput.LowVulns = append(results.HuskyCIResults.JavaResults.HuskyCISpotBugsOutput.LowVulns, lowVuln)
		case gitleaks:
			results.HuskyCIResults.GenericResults.HuskyCIGitleaksOutput.LowVulns = append(results.HuskyCIResults.GenericResults.HuskyCIGitleaksOutput.LowVulns, lowVuln)
		case wizcliSecrets:
			results.HuskyCIResults.GenericResults.HuskyCIWizCLISecretsOutput.LowVulns = append(results.HuskyCIResults.GenericResults.HuskyCIWizCLISecretsOutput.LowVulns, lowVuln)
		case wizcliIacSast:
			results.HuskyCIResults.GenericResults.HuskyCIIacSastOutput.LowVulns = append(results.HuskyCIResults.GenericResults.HuskyCIIacSastOutput.LowVulns, lowVuln)
		case wizcliVulns:
			results.HuskyCIResults.GenericResults.HuskyCIWizCLIVulnsOutput.LowVulns = append(results.HuskyCIResults.GenericResults.HuskyCIWizCLIVulnsOutput.LowVulns, lowVuln)
		case tfsec:
			results.HuskyCIResults.HclResults.HuskyCITFSecOutput.LowVulns = append(results.HuskyCIResults.HclResults.HuskyCITFSecOutput.LowVulns, lowVuln)
		case securitycodescan:
			results.HuskyCIResults.CSharpResults.HuskyCISecurityCodeScanOutput.LowVulns = append(results.HuskyCIResults.CSharpResults.HuskyCISecurityCodeScanOutput.LowVulns, lowVuln)
		}
	}

	for _, noSec := range securityTestScan.Vulnerabilities.NoSecVulns {
		switch securityTestScan.SecurityTestName {
		case bandit:
			results.HuskyCIResults.PythonResults.HuskyCIBanditOutput.NoSecVulns = append(results.HuskyCIResults.PythonResults.HuskyCIBanditOutput.NoSecVulns, noSec)
		case brakeman:
			results.HuskyCIResults.RubyResults.HuskyCIBrakemanOutput.NoSecVulns = append(results.HuskyCIResults.RubyResults.HuskyCIBrakemanOutput.NoSecVulns, noSec)
		case safety:
			results.HuskyCIResults.PythonResults.HuskyCISafetyOutput.NoSecVulns = append(results.HuskyCIResults.PythonResults.HuskyCISafetyOutput.NoSecVulns, noSec)
		case gosec:
			results.HuskyCIResults.GoResults.HuskyCIGosecOutput.NoSecVulns = append(results.HuskyCIResults.GoResults.HuskyCIGosecOutput.NoSecVulns, noSec)
		case npmaudit:
			results.HuskyCIResults.JavaScriptResults.HuskyCINpmAuditOutput.NoSecVulns = append(results.HuskyCIResults.JavaScriptResults.HuskyCINpmAuditOutput.NoSecVulns, noSec)
		case yarnaudit:
			results.HuskyCIResults.JavaScriptResults.HuskyCIYarnAuditOutput.NoSecVulns = append(results.HuskyCIResults.JavaScriptResults.HuskyCIYarnAuditOutput.NoSecVulns, noSec)
		case spotbugs:
			results.HuskyCIResults.JavaResults.HuskyCISpotBugsOutput.NoSecVulns = append(results.HuskyCIResults.JavaResults.HuskyCISpotBugsOutput.NoSecVulns, noSec)
		case gitleaks:
			results.HuskyCIResults.GenericResults.HuskyCIGitleaksOutput.NoSecVulns = append(results.HuskyCIResults.GenericResults.HuskyCIGitleaksOutput.NoSecVulns, noSec)
		case wizcliSecrets:
			results.HuskyCIResults.GenericResults.HuskyCIWizCLISecretsOutput.NoSecVulns = append(results.HuskyCIResults.GenericResults.HuskyCIWizCLISecretsOutput.NoSecVulns, noSec)
		case wizcliIacSast:
			results.HuskyCIResults.GenericResults.HuskyCIIacSastOutput.NoSecVulns = append(results.HuskyCIResults.GenericResults.HuskyCIIacSastOutput.NoSecVulns, noSec)
		case wizcliVulns:
			results.HuskyCIResults.GenericResults.HuskyCIWizCLIVulnsOutput.NoSecVulns = append(results.HuskyCIResults.GenericResults.HuskyCIWizCLIVulnsOutput.NoSecVulns, noSec)
		case tfsec:
			results.HuskyCIResults.HclResults.HuskyCITFSecOutput.NoSecVulns = append(results.HuskyCIResults.HclResults.HuskyCITFSecOutput.NoSecVulns, noSec)
		case securitycodescan:
			results.HuskyCIResults.CSharpResults.HuskyCISecurityCodeScanOutput.NoSecVulns = append(results.HuskyCIResults.CSharpResults.HuskyCISecurityCodeScanOutput.NoSecVulns, noSec)
		}
	}
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
