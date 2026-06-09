package kubernetes

import (
	"os"
	"testing"
)

func TestGetScannerConfig(t *testing.T) {
	t.Setenv("HUSKYCI_SCANNER_GITLEAKS_DELTA_SCAN", "true")
	t.Setenv("HUSKYCI_SCANNER_TFSEC_TIMEOUT", "300")

	result := getScannerConfig("gitleaks", "DELTA_SCAN")
	if result != "true" {
		t.Errorf("expected 'true', got '%s'", result)
	}

	result = getScannerConfig("tfsec", "TIMEOUT")
	if result != "300" {
		t.Errorf("expected '300', got '%s'", result)
	}
}

func TestGetScannerConfig_Missing(t *testing.T) {
	os.Unsetenv("HUSKYCI_SCANNER_NONEXISTENT_DELTA_SCAN")

	result := getScannerConfig("nonexistent", "DELTA_SCAN")
	if result != "" {
		t.Errorf("expected empty string for missing env var, got '%s'", result)
	}
}

func TestIsDeltaScanEnabled_True(t *testing.T) {
	t.Setenv("HUSKYCI_SCANNER_GITLEAKS_DELTA_SCAN", "true")

	if !isDeltaScanEnabled("gitleaks") {
		t.Error("expected isDeltaScanEnabled to return true when env var is 'true'")
	}
}

func TestIsDeltaScanEnabled_TrueCaseInsensitive(t *testing.T) {
	t.Setenv("HUSKYCI_SCANNER_GITLEAKS_DELTA_SCAN", "TRUE")

	if !isDeltaScanEnabled("gitleaks") {
		t.Error("expected isDeltaScanEnabled to return true when env var is 'TRUE' (case-insensitive)")
	}
}

func TestIsDeltaScanEnabled_TrueMixedCase(t *testing.T) {
	t.Setenv("HUSKYCI_SCANNER_GITLEAKS_DELTA_SCAN", "True")

	if !isDeltaScanEnabled("gitleaks") {
		t.Error("expected isDeltaScanEnabled to return true when env var is 'True'")
	}
}

func TestIsDeltaScanEnabled_False(t *testing.T) {
	t.Setenv("HUSKYCI_SCANNER_GITLEAKS_DELTA_SCAN", "false")

	if isDeltaScanEnabled("gitleaks") {
		t.Error("expected isDeltaScanEnabled to return false when env var is 'false'")
	}
}

func TestIsDeltaScanEnabled_Unset(t *testing.T) {
	os.Unsetenv("HUSKYCI_SCANNER_GITLEAKS_DELTA_SCAN")

	if isDeltaScanEnabled("gitleaks") {
		t.Error("expected isDeltaScanEnabled to return false when env var is unset")
	}
}

func TestIsDeltaScanEnabled_Empty(t *testing.T) {
	t.Setenv("HUSKYCI_SCANNER_GITLEAKS_DELTA_SCAN", "")

	if isDeltaScanEnabled("gitleaks") {
		t.Error("expected isDeltaScanEnabled to return false when env var is empty")
	}
}

func TestIsDeltaScanEnabled_WrongValue(t *testing.T) {
	t.Setenv("HUSKYCI_SCANNER_GITLEAKS_DELTA_SCAN", "1")

	if isDeltaScanEnabled("gitleaks") {
		t.Error("expected isDeltaScanEnabled to return false when env var is '1' (not 'true')")
	}
}
