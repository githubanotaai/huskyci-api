//go:build integration

package testhelper

import (
	"context"
	"testing"
)

func TestIsDockerAvailable_NoPanic(t *testing.T) {
	// This test verifies IsDockerAvailable returns a bool without crashing.
	// When Docker is unavailable it just returns false — no panic, no error.
	available := IsDockerAvailable()
	if !available {
		t.Skip("Docker unavailable — skipping integration test helper tests")
	}
}

func TestStartMongoContainer(t *testing.T) {
	if !IsDockerAvailable() {
		t.Skip("Docker unavailable — skipping integration test helper tests")
	}

	ctx := context.Background()
	mc, err := StartMongoContainer(ctx)
	if err != nil {
		t.Fatalf("StartMongoContainer failed: %v", err)
	}

	if mc.ConnectionString == "" {
		mc.Terminate(ctx)
		t.Fatal("expected non-empty connection string")
	}
	t.Logf("MongoDB connection string: %s", mc.ConnectionString)

	// Verify Terminate cleanly stops the container.
	if err := mc.Terminate(ctx); err != nil {
		t.Errorf("Terminate failed: %v", err)
	}
}

func TestStartMongoContainer_TerminateCleansUp(t *testing.T) {
	if !IsDockerAvailable() {
		t.Skip("Docker unavailable — skipping integration test helper tests")
	}

	ctx := context.Background()
	mc, err := StartMongoContainer(ctx)
	if err != nil {
		t.Fatalf("StartMongoContainer failed: %v", err)
	}

	// Terminate must succeed.
	if err := mc.Terminate(ctx); err != nil {
		t.Errorf("Terminate should succeed on first call, got: %v", err)
	}
}
