//go:build integration

// Package integration contains route-to-DB integration tests backed by a real
// MongoDB container.
//
// Full Docker scanner runtime is deferred from this file. Scanner containers
// (gitleaks, enry, gosec, bandit, etc.) require pre-built Docker images, a
// Docker socket, and SSH keys for private repositories. Exercising the complete
// scanner pipeline is covered by the gitleaks-contract CI job and the
// deployments/docker-compose.yml stack. This file focuses on the route → DB
// persistence layer with real MongoDB, which is the highest-leverage integration
// surface not covered by existing unit tests.

package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo"

	apiContext "github.com/githubanotaai/huskyci-api/api/context"
	huskyRoutes "github.com/githubanotaai/huskyci-api/api/routes"
	"github.com/githubanotaai/huskyci-api/api/token"
	"github.com/githubanotaai/huskyci-api/api/types"
)

// mockVerifier implements token.TInterface and always authorizes requests.
// Used to bypass real token validation during route integration tests.
type mockVerifier struct{}

func (m *mockVerifier) GenerateAccessToken(repo types.TokenRequest) (string, error) {
	return "mock-token", nil
}

func (m *mockVerifier) ValidateToken(token, repositoryURL string) error {
	return nil
}

func (m *mockVerifier) VerifyRepo(repositoryURL string) error {
	return nil
}

// newTestEcho creates an Echo instance with the analysis routes registered
// and a permissive token validator. No BasicAuth middleware is applied —
// the handlers themselves use the overridden tokenValidator.
func newTestEcho() *echo.Echo {
	huskyRoutes.SetTokenValidator(token.TValidator{
		TokenVerifier: &mockVerifier{},
	})

	e := echo.New()
	e.POST("/analysis", huskyRoutes.ReceiveRequest)
	e.GET("/analysis/:id", huskyRoutes.GetAnalysis)
	return e
}

// ensureDBInstance ensures the global APIConfiguration has a DBInstance
// pointing at the test MongoDB. idempotent across tests.
func ensureDBInstance() {
	if apiContext.APIConfiguration == nil || apiContext.APIConfiguration.DBInstance == nil {
		apiContext.APIConfiguration = &apiContext.APIConfig{
			DBInstance: mongoRequests,
		}
	} else if apiContext.APIConfiguration.DBInstance == nil {
		apiContext.APIConfiguration.DBInstance = mongoRequests
	}
}

func TestPostAnalysisInsertsRecord(t *testing.T) {
	if mongoRequests == nil {
		t.Skip("Docker unavailable — skipping integration test")
	}
	ensureDBInstance()

	e := newTestEcho()
	body := `{"repositoryURL":"https://github.com/test/insert-test.git","repositoryBranch":"main"}`
	req := httptest.NewRequest(http.MethodPost, "/analysis", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()

	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify the analysis record was inserted via MongoDB.
	query := map[string]interface{}{"repositoryURL": "https://github.com/test/insert-test.git"}
	analysisResult, err := mongoRequests.FindOneDBAnalysis(query)
	if err != nil {
		t.Fatalf("failed to find analysis record in MongoDB: %v", err)
	}
	if analysisResult.URL != "https://github.com/test/insert-test.git" {
		t.Errorf("URL mismatch: got %q, want %q", analysisResult.URL, "https://github.com/test/insert-test.git")
	}
	if analysisResult.Branch != "main" {
		t.Errorf("Branch mismatch: got %q, want %q", analysisResult.Branch, "main")
	}
	if analysisResult.Status == "" {
		t.Error("expected non-empty status field in analysis record")
	}
}

func TestGetAnalysisReturnsRecord(t *testing.T) {
	if mongoRequests == nil {
		t.Skip("Docker unavailable — skipping integration test")
	}
	ensureDBInstance()

	// Seed an analysis record directly in MongoDB.
	now := time.Now().UTC()
	seedAnalysis := types.Analysis{
		RID:        "test-rid-get-001",
		URL:        "https://github.com/test/get-test.git",
		Branch:     "develop",
		Status:     "finished",
		Containers: []types.Container{},
		StartedAt:  now,
	}
	if err := mongoRequests.InsertDBAnalysis(seedAnalysis); err != nil {
		t.Fatalf("failed to seed analysis record: %v", err)
	}

	e := newTestEcho()
	req := httptest.NewRequest(http.MethodGet, "/analysis/test-rid-get-001", nil)
	rec := httptest.NewRecorder()

	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var result types.Analysis
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if result.RID != seedAnalysis.RID {
		t.Errorf("RID mismatch: got %q, want %q", result.RID, seedAnalysis.RID)
	}
	if result.URL != seedAnalysis.URL {
		t.Errorf("URL mismatch: got %q, want %q", result.URL, seedAnalysis.URL)
	}
	if result.Branch != seedAnalysis.Branch {
		t.Errorf("Branch mismatch: got %q, want %q", result.Branch, seedAnalysis.Branch)
	}
	if result.Status != seedAnalysis.Status {
		t.Errorf("Status mismatch: got %q, want %q", result.Status, seedAnalysis.Status)
	}
}

func TestPostDuplicateAnalysisWhileRunning(t *testing.T) {
	if mongoRequests == nil {
		t.Skip("Docker unavailable — skipping integration test")
	}
	ensureDBInstance()

	// Seed a running analysis to trigger the duplicate check.
	now := time.Now().UTC()
	seedAnalysis := types.Analysis{
		RID:        "test-rid-dup-001",
		URL:        "https://github.com/test/dup-test.git",
		Branch:     "main",
		Status:     "running",
		Containers: []types.Container{},
		StartedAt:  now,
	}
	if err := mongoRequests.InsertDBAnalysis(seedAnalysis); err != nil {
		t.Fatalf("failed to seed running analysis: %v", err)
	}

	e := newTestEcho()
	body := `{"repositoryURL":"https://github.com/test/dup-test.git","repositoryBranch":"main"}`
	req := httptest.NewRequest(http.MethodPost, "/analysis", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()

	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict for duplicate analysis, got %d: %s", rec.Code, rec.Body.String())
	}

	var reply map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	success, _ := reply["success"].(bool)
	if success {
		t.Error("expected success=false in duplicate response")
	}
	errMsg, _ := reply["error"].(string)
	if !strings.Contains(strings.ToLower(errMsg), "already") {
		t.Errorf("expected 'already' in error message, got: %q", errMsg)
	}
}

func TestPostInvalidJSON(t *testing.T) {
	if mongoRequests == nil {
		t.Skip("Docker unavailable — skipping integration test")
	}
	ensureDBInstance()

	e := newTestEcho()
	body := `{"repositoryURL": invalid-json`
	req := httptest.NewRequest(http.MethodPost, "/analysis", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()

	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for invalid JSON, got %d: %s", rec.Code, rec.Body.String())
	}

	var reply map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	success, _ := reply["success"].(bool)
	if success {
		t.Error("expected success=false in error response")
	}
}

func TestGetNonexistentAnalysis(t *testing.T) {
	if mongoRequests == nil {
		t.Skip("Docker unavailable — skipping integration test")
	}
	ensureDBInstance()

	e := newTestEcho()
	req := httptest.NewRequest(http.MethodGet, "/analysis/nonexistent-rid-99999", nil)
	rec := httptest.NewRecorder()

	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 Not Found for nonexistent analysis, got %d: %s", rec.Code, rec.Body.String())
	}

	var reply map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	success, _ := reply["success"].(bool)
	if success {
		t.Error("expected success=false in not-found response")
	}
}
