package analysis

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/githubanotaai/huskyci-api/client/config"
	"github.com/githubanotaai/huskyci-api/client/types"
)

func TestChangedFilesInPayload(t *testing.T) {
	// Set the env var
	os.Setenv("HUSKYCI_CLIENT_CHANGED_FILES", "src/main.go\nsrc/utils.go")
	defer os.Unsetenv("HUSKYCI_CLIENT_CHANGED_FILES")

	config.SetConfigs()

	payload := types.JSONPayload{
		RepositoryURL:      config.RepositoryURL,
		RepositoryBranch:   config.RepositoryBranch,
		LanguageExclusions: config.LanguageExclusions,
		ChangedFiles:       config.ChangedFiles,
	}

	marshalled, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	var result map[string]interface{}
	err = json.Unmarshal(marshalled, &result)
	if err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}

	changedFiles, ok := result["changedFiles"].(string)
	if !ok {
		t.Fatal("changedFiles not found in payload")
	}

	if changedFiles != "src/main.go\nsrc/utils.go" {
		t.Fatalf("expected changedFiles to be 'src/main.go\\nsrc/utils.go', got '%s'", changedFiles)
	}
}

func TestChangedFilesEmpty(t *testing.T) {
	// Ensure env var is not set
	os.Unsetenv("HUSKYCI_CLIENT_CHANGED_FILES")

	config.SetConfigs()

	payload := types.JSONPayload{
		RepositoryURL:      config.RepositoryURL,
		RepositoryBranch:   config.RepositoryBranch,
		LanguageExclusions: config.LanguageExclusions,
		ChangedFiles:       config.ChangedFiles,
	}

	marshalled, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	var result map[string]interface{}
	err = json.Unmarshal(marshalled, &result)
	if err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}

	changedFiles, ok := result["changedFiles"].(string)
	if !ok {
		t.Fatal("changedFiles not found in payload")
	}

	if changedFiles != "" {
		t.Fatalf("expected changedFiles to be empty, got '%s'", changedFiles)
	}
}
