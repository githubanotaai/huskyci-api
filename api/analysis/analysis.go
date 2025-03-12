package analysis

import (
	"errors"
	"os"
	"time"

	apiContext "github.com/githubanotaai/huskyci-api/api/context"
	"github.com/githubanotaai/huskyci-api/api/log"
	"github.com/githubanotaai/huskyci-api/api/securitytest"
	"github.com/githubanotaai/huskyci-api/api/types"
	apiUtil "github.com/githubanotaai/huskyci-api/api/util/api"
	"go.mongodb.org/mongo-driver/bson"
)

const logActionStart = "StartAnalysis"
const logInfoAnalysis = "ANALYSIS"

// StartAnalysis starts the analysis given a RID and a repository.
func StartAnalysis(RID string, repository types.Repository) {

	// step 1: create a new analysis into MongoDB based on repository received
	if err := registerNewAnalysis(RID, repository); err != nil {
		return
	}
	log.Info(logActionStart, logInfoAnalysis, 101, RID)

	// step 2: run enry as huskyCI initial step
	enryScan := securitytest.SecTestScanInfo{}
	enryScan.SecurityTestName = "enry"
	allScansResults := securitytest.RunAllInfo{}

	defer func() {
		err := registerFinishedAnalysis(RID, &allScansResults)
		if err != nil {
			log.Error(logActionStart, logInfoAnalysis, 2011, err)
		}
	}()

	infrastructureSelected, hasSelected := os.LookupEnv("HUSKYCI_INFRASTRUCTURE_USE")
	if !hasSelected {
		err := errors.New("HUSKYCI_INFRASTRUCTURE_USE environment variable not set")
		log.Error(logActionStart, logInfoAnalysis, 2011, err)
		return
	}

	var apiHost string

	if infrastructureSelected == "docker" {
		dockerAPIHost, err := apiContext.APIConfiguration.DBInstance.FindAndModifyDockerAPIAddresses()
		if err != nil {
			log.Error(logActionStart, logInfoAnalysis, 2011, err)
			return
		}

		configAPI, err := apiContext.DefaultConf.GetAPIConfig()
		if err != nil {
			log.Error(logActionStart, logInfoAnalysis, 2011, err)
			return
		}

		apiHost, err = apiUtil.FormatDockerHostAddress(dockerAPIHost, configAPI)
		if err != nil {
			log.Error(logActionStart, logInfoAnalysis, 2011, err)
			return
		}
	} else if infrastructureSelected == "kubernetes" {
		// Assume that the Kubernetes host is set properly in the configuration or environment variables
		apiHost = "kubernetes.default.svc" // Example host, replace with actual logic if needed
	} else {
		err := errors.New("Invalid HUSKYCI_INFRASTRUCTURE_USE value")
		log.Error(logActionStart, logInfoAnalysis, 2011, err)
		return
	}

	log.Info("StartAnalysisTest", apiHost, 2012, RID)

	if err := enryScan.New(RID, repository.URL, repository.Branch, enryScan.SecurityTestName, repository.LanguageExclusions, apiHost); err != nil {
		log.Error(logActionStart, logInfoAnalysis, 2011, err)
		return
	}
	if err := enryScan.Start(); err != nil {
		allScansResults.SetAnalysisError(err)
		return
	}

	// step 3: run generic and languages security tests based on enryScan result in parallel
	if err := allScansResults.Start(enryScan); err != nil {
		allScansResults.SetAnalysisError(err)
		return
	}

	log.Info("StartAnalysis", logInfoAnalysis, 102, RID)
}

func registerNewAnalysis(RID string, repository types.Repository) error {

	newAnalysis := types.Analysis{
		RID:       RID,
		URL:       repository.URL,
		Branch:    repository.Branch,
		Status:    "running",
		StartedAt: time.Now(),
	}

	if err := apiContext.APIConfiguration.DBInstance.InsertDBAnalysis(newAnalysis); err != nil {
		log.Error("registerNewAnalysis", logInfoAnalysis, 2011, err)
		return err
	}

	return nil
}

func registerFinishedAnalysis(RID string, allScanResults *securitytest.RunAllInfo) error {
	analysisQuery := map[string]interface{}{"RID": RID}
	var errorString string
	if _, ok := allScanResults.ErrorFound.(error); ok {
		errorString = allScanResults.ErrorFound.Error()
	} else {
		errorString = ""
	}

	// Determine the final status based on scan results
	finalStatus := "completed"
	if allScanResults.ErrorFound != nil {
		finalStatus = "failed"
	} else if hasCriticalVulnerabilities(allScanResults.HuskyCIResults) {
		finalStatus = "failed"
	}

	updateAnalysisQuery := bson.M{
		"status":         finalStatus,
		"commitAuthors":  allScanResults.CommitAuthors,
		"result":         allScanResults.FinalResult,
		"containers":     allScanResults.Containers,
		"huskyciresults": allScanResults.HuskyCIResults,
		"codes":          allScanResults.Codes,
		"errorFound":     errorString,
		"finishedAt":     time.Now(),
	}

	if err := apiContext.APIConfiguration.DBInstance.UpdateOneDBAnalysisContainer(analysisQuery, updateAnalysisQuery); err != nil {
		log.Error("registerFinishedAnalysis", logInfoAnalysis, 2011, err)
		return err
	}
	return nil
}

func hasCriticalVulnerabilities(results types.HuskyCIResults) bool {
	return hasCriticalVulnerabilitiesInOutput(results.GoResults.HuskyCIGosecOutput) ||
		hasCriticalVulnerabilitiesInOutput(results.PythonResults.HuskyCIBanditOutput) ||
		hasCriticalVulnerabilitiesInOutput(results.PythonResults.HuskyCISafetyOutput) ||
		hasCriticalVulnerabilitiesInOutput(results.JavaScriptResults.HuskyCINpmAuditOutput) ||
		hasCriticalVulnerabilitiesInOutput(results.JavaScriptResults.HuskyCIYarnAuditOutput) ||
		hasCriticalVulnerabilitiesInOutput(results.JavaResults.HuskyCISpotBugsOutput) ||
		hasCriticalVulnerabilitiesInOutput(results.RubyResults.HuskyCIBrakemanOutput) ||
		hasCriticalVulnerabilitiesInOutput(results.HclResults.HuskyCITFSecOutput) ||
		hasCriticalVulnerabilitiesInOutput(results.CSharpResults.HuskyCISecurityCodeScanOutput) ||
		hasCriticalVulnerabilitiesInOutput(results.GenericResults.HuskyCIGitleaksOutput)
}

func hasCriticalVulnerabilitiesInOutput(output types.HuskyCISecurityTestOutput) bool {
	return len(output.HighVulns) > 0 || len(output.MediumVulns) > 0
}
