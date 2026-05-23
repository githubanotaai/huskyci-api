package securitytest

import "github.com/githubanotaai/huskyci-api/api/types"

// scanRunner abstracts scan lifecycle so tests can mock
// DB queries and scan execution without MongoDB or K8s.
type scanRunner interface {
	listGenericTests() ([]types.SecurityTest, error)
	listLanguageTests(language string) ([]types.SecurityTest, error)
	newScan(RID, URL, branch, securityTestName string, languageExclusions map[string]bool, dockerHost string) (*SecTestScanInfo, error)
	startScan(scan *SecTestScanInfo) error
}

// realRunner delegates to actual SecTestScanInfo + DB methods.
type realRunner struct{}

func (realRunner) listGenericTests() ([]types.SecurityTest, error) {
	return getAllDefaultSecurityTests("Generic", "")
}

func (realRunner) listLanguageTests(language string) ([]types.SecurityTest, error) {
	return getAllDefaultSecurityTests("Language", language)
}

func (realRunner) newScan(RID, URL, branch, securityTestName string, languageExclusions map[string]bool, dockerHost string) (*SecTestScanInfo, error) {
	scan := &SecTestScanInfo{}
	return scan, scan.New(RID, URL, branch, securityTestName, languageExclusions, dockerHost)
}

func (realRunner) startScan(scan *SecTestScanInfo) error {
	return scan.Start()
}

// mockRunner returns preconfigured results for testing.
type mockRunner struct {
	genericTests  []types.SecurityTest
	languageTests []types.SecurityTest
	newScanFunc   func(RID, URL, branch, securityTestName string, languageExclusions map[string]bool, dockerHost string) (*SecTestScanInfo, error)
	startScanFunc func(scan *SecTestScanInfo) error
}

func (m *mockRunner) listGenericTests() ([]types.SecurityTest, error) {
	return m.genericTests, nil
}

func (m *mockRunner) listLanguageTests(language string) ([]types.SecurityTest, error) {
	return m.languageTests, nil
}

func (m *mockRunner) newScan(RID, URL, branch, securityTestName string, languageExclusions map[string]bool, dockerHost string) (*SecTestScanInfo, error) {
	if m.newScanFunc != nil {
		return m.newScanFunc(RID, URL, branch, securityTestName, languageExclusions, dockerHost)
	}
	return &SecTestScanInfo{}, nil
}

func (m *mockRunner) startScan(scan *SecTestScanInfo) error {
	if m.startScanFunc != nil {
		return m.startScanFunc(scan)
	}
	return nil
}