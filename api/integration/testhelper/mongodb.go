//go:build integration

package testhelper

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/testcontainers/testcontainers-go/modules/mongodb"
)

// MongoContainer holds a running MongoDB test container
// started via testcontainers-go.
type MongoContainer struct {
	// ConnectionString is the MongoDB URI (e.g. "mongodb://localhost:12345")
	ConnectionString string

	// Terminate stops and removes the container.
	Terminate func(ctx context.Context) error
}

// IsDockerAvailable checks whether Docker is available on the host
// by running "docker info". Returns false with a log message when
// Docker is not reachable.
func IsDockerAvailable() bool {
	cmd := exec.Command("docker", "info")
	if err := cmd.Run(); err != nil {
		fmt.Println("testhelper: Docker unavailable — docker info failed:", err)
		return false
	}
	return true
}

// StartMongoContainer starts a mongo:4.2 container via testcontainers-go
// and returns a MongoContainer with the connection string and a terminate
// function. Callers must call Terminate to clean up the container.
// Returns an error if Docker is unavailable or the container fails to start.
func StartMongoContainer(ctx context.Context) (*MongoContainer, error) {
	if !IsDockerAvailable() {
		return nil, fmt.Errorf("docker unavailable - cannot start MongoDB container")
	}

	mongoCtr, err := mongodb.Run(ctx, "mongo:4.2")
	if err != nil {
		return nil, fmt.Errorf("failed to start MongoDB container: %w", err)
	}

	connStr, err := mongoCtr.ConnectionString(ctx)
	if err != nil {
		mongoCtr.Terminate(ctx)
		return nil, fmt.Errorf("failed to get MongoDB connection string: %w", err)
	}

	return &MongoContainer{
		ConnectionString: connStr,
		Terminate: func(ctx context.Context) error {
			return mongoCtr.Terminate(ctx)
		},
	}, nil
}
