package util

import (
	"strings"
	"testing"
)

// TestHandleCmd_WizClientIDSubstitution verifies %WIZ_CLIENT_ID% is replaced
// with the value from HUSKYCI_API_WIZ_CLIENT_ID.
func TestHandleCmd_WizClientIDSubstitution(t *testing.T) {
	t.Setenv("HUSKYCI_API_WIZ_CLIENT_ID", "testid")
	t.Setenv("HUSKYCI_API_WIZ_CLIENT_SECRET", "")

	cmd := "wizcli auth --client-id %WIZ_CLIENT_ID%"
	result := HandleCmd("https://github.com/org/repo.git", "main", cmd)

	if !strings.Contains(result, "testid") {
		t.Errorf("expected result to contain 'testid', got: %s", result)
	}
	if strings.Contains(result, "%WIZ_CLIENT_ID%") {
		t.Errorf("placeholder %%WIZ_CLIENT_ID%% was not replaced, got: %s", result)
	}
}

// TestHandleCmd_WizClientSecretSubstitution verifies %WIZ_CLIENT_SECRET% is
// replaced with the value from HUSKYCI_API_WIZ_CLIENT_SECRET.
func TestHandleCmd_WizClientSecretSubstitution(t *testing.T) {
	t.Setenv("HUSKYCI_API_WIZ_CLIENT_ID", "")
	t.Setenv("HUSKYCI_API_WIZ_CLIENT_SECRET", "testsecret")

	cmd := "wizcli auth --client-secret %WIZ_CLIENT_SECRET%"
	result := HandleCmd("https://github.com/org/repo.git", "main", cmd)

	if !strings.Contains(result, "testsecret") {
		t.Errorf("expected result to contain 'testsecret', got: %s", result)
	}
	if strings.Contains(result, "%WIZ_CLIENT_SECRET%") {
		t.Errorf("placeholder %%WIZ_CLIENT_SECRET%% was not replaced, got: %s", result)
	}
}

// TestHandleCmd_WizPlaceholders_BothPresent verifies that both Wiz placeholders
// are replaced in the same command string.
func TestHandleCmd_WizPlaceholders_BothPresent(t *testing.T) {
	t.Setenv("HUSKYCI_API_WIZ_CLIENT_ID", "myClientID")
	t.Setenv("HUSKYCI_API_WIZ_CLIENT_SECRET", "myClientSecret")

	cmd := "wizcli auth --client-id %WIZ_CLIENT_ID% --client-secret %WIZ_CLIENT_SECRET%"
	result := HandleCmd("https://github.com/org/repo.git", "main", cmd)

	if !strings.Contains(result, "myClientID") {
		t.Errorf("expected result to contain 'myClientID', got: %s", result)
	}
	if !strings.Contains(result, "myClientSecret") {
		t.Errorf("expected result to contain 'myClientSecret', got: %s", result)
	}
	if strings.Contains(result, "%WIZ_CLIENT_ID%") || strings.Contains(result, "%WIZ_CLIENT_SECRET%") {
		t.Errorf("one or more Wiz placeholders were not replaced, got: %s", result)
	}
}

// TestHandleCmd_WizPlaceholders_EmptyEnv verifies that when the env vars are
// not set, the placeholders are replaced with empty strings (not left as-is).
func TestHandleCmd_WizPlaceholders_EmptyEnv(t *testing.T) {
	t.Setenv("HUSKYCI_API_WIZ_CLIENT_ID", "")
	t.Setenv("HUSKYCI_API_WIZ_CLIENT_SECRET", "")

	cmd := "wizcli auth --client-id %WIZ_CLIENT_ID% --client-secret %WIZ_CLIENT_SECRET%"
	result := HandleCmd("https://github.com/org/repo.git", "main", cmd)

	if strings.Contains(result, "%WIZ_CLIENT_ID%") {
		t.Errorf("placeholder %%WIZ_CLIENT_ID%% was not replaced with empty string, got: %s", result)
	}
	if strings.Contains(result, "%WIZ_CLIENT_SECRET%") {
		t.Errorf("placeholder %%WIZ_CLIENT_SECRET%% was not replaced with empty string, got: %s", result)
	}
}

// TestHandleCmd_WizPlaceholders_NotAffectedByOtherCmds verifies that a command
// without Wiz placeholders is not altered (beyond standard git substitutions).
func TestHandleCmd_WizPlaceholders_NotAffectedByOtherCmds(t *testing.T) {
	t.Setenv("HUSKYCI_API_WIZ_CLIENT_ID", "shouldNotAppear")
	t.Setenv("HUSKYCI_API_WIZ_CLIENT_SECRET", "shouldNotAppear")

	cmd := "git clone -b %GIT_BRANCH% --single-branch %GIT_REPO% code"
	result := HandleCmd("https://github.com/org/repo.git", "main", cmd)

	if strings.Contains(result, "shouldNotAppear") {
		t.Errorf("Wiz env values unexpectedly appeared in non-Wiz command: %s", result)
	}
	if strings.Contains(result, "%GIT_REPO%") || strings.Contains(result, "%GIT_BRANCH%") {
		t.Errorf("git placeholders were not replaced, got: %s", result)
	}
	if !strings.Contains(result, "https://github.com/org/repo.git") {
		t.Errorf("expected repo URL in result, got: %s", result)
	}
}
