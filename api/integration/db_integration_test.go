//go:build integration

package integration

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/githubanotaai/huskyci-api/api/db"
	mongoHuskyCI "github.com/githubanotaai/huskyci-api/api/db/mongo"
	"github.com/githubanotaai/huskyci-api/api/integration/testhelper"
	"github.com/githubanotaai/huskyci-api/api/types"
)

var mongoRequests db.Requests

func TestMain(m *testing.M) {
	if !testhelper.IsDockerAvailable() {
		fmt.Println("Docker unavailable — skipping integration tests")
		os.Exit(0)
	}

	ctx := context.Background()
	mc, err := testhelper.StartMongoContainer(ctx)
	if err != nil {
		fmt.Println("Docker unavailable — skipping integration tests:", err)
		os.Exit(0)
	}

	connURI, err := url.Parse(mc.ConnectionString)
	if err != nil {
		fmt.Println("Failed to parse MongoDB connection string:", err)
		mc.Terminate(ctx)
		os.Exit(1)
	}
	host := connURI.Hostname()
	port := 27017
	if p := connURI.Port(); p != "" {
		port, _ = strconv.Atoi(p)
	}

	err = mongoHuskyCI.Connect(host, "huskyci_test", "", "", 100, port, 60*time.Second)
	if err != nil {
		fmt.Println("Failed to connect to MongoDB:", err)
		mc.Terminate(ctx)
		os.Exit(1)
	}

	mongoRequests = &db.MongoRequests{}

	code := m.Run()

	if err := mc.Terminate(ctx); err != nil {
		fmt.Println("Failed to terminate MongoDB container:", err)
	}

	os.Exit(code)
}

func TestInsertAndFindAnalysis(t *testing.T) {
	if mongoRequests == nil {
		t.Skip("Docker unavailable — skipping integration test")
	}

	now := time.Now().UTC()
	analysis := types.Analysis{
		RID:       "test-rid-001",
		URL:       "https://github.com/example/repo.git",
		Branch:    "main",
		Status:    "running",
		Containers: []types.Container{},
		StartedAt: now,
	}

	err := mongoRequests.InsertDBAnalysis(analysis)
	if err != nil {
		t.Fatalf("InsertDBAnalysis failed: %v", err)
	}

	result, err := mongoRequests.FindOneDBAnalysis(map[string]interface{}{
		"RID": "test-rid-001",
	})
	if err != nil {
		t.Fatalf("FindOneDBAnalysis failed: %v", err)
	}

	if result.RID != analysis.RID {
		t.Errorf("RID mismatch: got %q, want %q", result.RID, analysis.RID)
	}
	if result.URL != analysis.URL {
		t.Errorf("URL mismatch: got %q, want %q", result.URL, analysis.URL)
	}
	if result.Branch != analysis.Branch {
		t.Errorf("Branch mismatch: got %q, want %q", result.Branch, analysis.Branch)
	}
	if result.Status != analysis.Status {
		t.Errorf("Status mismatch: got %q, want %q", result.Status, analysis.Status)
	}
}

func TestUpdateAnalysis(t *testing.T) {
	if mongoRequests == nil {
		t.Skip("Docker unavailable — skipping integration test")
	}

	now := time.Now().UTC()
	analysis := types.Analysis{
		RID:        "test-rid-002",
		URL:        "https://github.com/example/repo.git",
		Branch:     "develop",
		Status:     "running",
		Containers: []types.Container{},
		StartedAt:  now,
	}

	err := mongoRequests.InsertDBAnalysis(analysis)
	if err != nil {
		t.Fatalf("InsertDBAnalysis failed: %v", err)
	}

	err = mongoRequests.UpdateOneDBAnalysis(
		map[string]interface{}{"RID": "test-rid-002"},
		map[string]interface{}{"status": "finished"},
	)
	if err != nil {
		t.Fatalf("UpdateOneDBAnalysis failed: %v", err)
	}

	result, err := mongoRequests.FindOneDBAnalysis(map[string]interface{}{
		"RID": "test-rid-002",
	})
	if err != nil {
		t.Fatalf("FindOneDBAnalysis after update failed: %v", err)
	}

	if result.Status != "finished" {
		t.Errorf("Status not updated: got %q, want %q", result.Status, "finished")
	}
	if result.RID != analysis.RID {
		t.Errorf("RID mismatch after update: got %q, want %q", result.RID, analysis.RID)
	}
	if result.URL != analysis.URL {
		t.Errorf("URL changed after status-only update: got %q, want %q", result.URL, analysis.URL)
	}
}

func TestInsertAndFindRepository(t *testing.T) {
	if mongoRequests == nil {
		t.Skip("Docker unavailable — skipping integration test")
	}

	now := time.Now().UTC()
	repo := types.Repository{
		URL:       "https://github.com/example/test-repo.git",
		CreatedAt: now,
	}

	err := mongoRequests.InsertDBRepository(repo)
	if err != nil {
		t.Fatalf("InsertDBRepository failed: %v", err)
	}

	result, err := mongoRequests.FindOneDBRepository(map[string]interface{}{
		"repositoryURL": "https://github.com/example/test-repo.git",
	})
	if err != nil {
		t.Fatalf("FindOneDBRepository failed: %v", err)
	}

	if result.URL != repo.URL {
		t.Errorf("URL mismatch: got %q, want %q", result.URL, repo.URL)
	}
}

func TestInsertSecurityTest(t *testing.T) {
	if mongoRequests == nil {
		t.Skip("Docker unavailable — skipping integration test")
	}

	st := types.SecurityTest{
		Name:             "gitleaks",
		Image:            "huskyci/gitleaks",
		ImageTag:         "latest",
		Cmd:              "run",
		Language:         "generic",
		Type:             "static",
		Default:          true,
		TimeOutInSeconds: 600,
	}

	err := mongoRequests.InsertDBSecurityTest(st)
	if err != nil {
		t.Fatalf("InsertDBSecurityTest failed: %v", err)
	}

	result, err := mongoRequests.FindOneDBSecurityTest(map[string]interface{}{
		"name": "gitleaks",
	})
	if err != nil {
		t.Fatalf("FindOneDBSecurityTest failed: %v", err)
	}

	if result.Name != st.Name {
		t.Errorf("Name mismatch: got %q, want %q", result.Name, st.Name)
	}
	if result.Image != st.Image {
		t.Errorf("Image mismatch: got %q, want %q", result.Image, st.Image)
	}
	if result.Cmd != st.Cmd {
		t.Errorf("Cmd mismatch: got %q, want %q", result.Cmd, st.Cmd)
	}
	if result.Language != st.Language {
		t.Errorf("Language mismatch: got %q, want %q", result.Language, st.Language)
	}
	if result.Default != st.Default {
		t.Errorf("Default mismatch: got %v, want %v", result.Default, st.Default)
	}
	if result.TimeOutInSeconds != st.TimeOutInSeconds {
		t.Errorf("TimeOutInSeconds mismatch: got %d, want %d", result.TimeOutInSeconds, st.TimeOutInSeconds)
	}
}
