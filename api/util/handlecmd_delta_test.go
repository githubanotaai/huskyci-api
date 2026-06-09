package util

import (
	"strings"
	"testing"
)

// TestHandleCmd_ChangedFiles_Replacement verifies %CHANGED_FILES% is replaced
// with the provided changedFiles string.
func TestHandleCmd_ChangedFiles_Replacement(t *testing.T) {
	changedFiles := "src/main.go\nsrc/utils.go\nREADME.md"
	cmd := "echo '%CHANGED_FILES%' > /tmp/delta.txt"
	result := HandleCmd("https://github.com/org/repo.git", "main", cmd, changedFiles)

	if !strings.Contains(result, "src/main.go") {
		t.Errorf("expected result to contain 'src/main.go', got: %s", result)
	}
	if !strings.Contains(result, "src/utils.go") {
		t.Errorf("expected result to contain 'src/utils.go', got: %s", result)
	}
	if strings.Contains(result, "%CHANGED_FILES%") {
		t.Errorf("placeholder %%CHANGED_FILES%% was not replaced, got: %s", result)
	}
}

// TestHandleCmd_ChangedFiles_Empty verifies that an empty changedFiles results
// in the placeholder being replaced with an empty string.
func TestHandleCmd_ChangedFiles_Empty(t *testing.T) {
	cmd := "echo '%CHANGED_FILES%' > /tmp/delta.txt"
	result := HandleCmd("https://github.com/org/repo.git", "main", cmd, "")

	if strings.Contains(result, "%CHANGED_FILES%") {
		t.Errorf("placeholder %%CHANGED_FILES%% was not replaced with empty string, got: %s", result)
	}
}

// TestHandleCmd_ChangedFiles_UnchangedPlaceholders verifies that existing
// placeholders (%GIT_REPO%, %GIT_BRANCH%) still work when changedFiles is provided.
func TestHandleCmd_ChangedFiles_UnchangedPlaceholders(t *testing.T) {
	changedFiles := "src/main.go\nREADME.md"
	cmd := "git clone -b %GIT_BRANCH% --single-branch %GIT_REPO% code && echo '%CHANGED_FILES%' > delta.txt"
	result := HandleCmd("https://github.com/org/repo.git", "main", cmd, changedFiles)

	if strings.Contains(result, "%GIT_REPO%") {
		t.Errorf("placeholder %%GIT_REPO%% was not replaced, got: %s", result)
	}
	if strings.Contains(result, "%GIT_BRANCH%") {
		t.Errorf("placeholder %%GIT_BRANCH%% was not replaced, got: %s", result)
	}
	if strings.Contains(result, "%CHANGED_FILES%") {
		t.Errorf("placeholder %%CHANGED_FILES%% was not replaced, got: %s", result)
	}
	if !strings.Contains(result, "https://github.com/org/repo.git") {
		t.Errorf("expected result to contain repo URL, got: %s", result)
	}
	if !strings.Contains(result, "src/main.go") {
		t.Errorf("expected result to contain 'src/main.go', got: %s", result)
	}
}

// TestHandleCmd_ChangedFiles_NoPlaceholder verifies that a command without
// %CHANGED_FILES% is not altered when changedFiles is provided.
func TestHandleCmd_ChangedFiles_NoPlaceholder(t *testing.T) {
	cmd := "git clone -b %GIT_BRANCH% --single-branch %GIT_REPO% code"
	result := HandleCmd("https://github.com/org/repo.git", "main", cmd, "shouldNotAppear")

	if strings.Contains(result, "shouldNotAppear") {
		t.Errorf("changedFiles content unexpectedly appeared in result: %s", result)
	}
	if strings.Contains(result, "%GIT_REPO%") || strings.Contains(result, "%GIT_BRANCH%") {
		t.Errorf("git placeholders were not replaced, got: %s", result)
	}
}
