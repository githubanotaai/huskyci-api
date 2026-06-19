// Copyright 2026 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build integration

package dockers

import (
	"context"
	"os"
	"testing"
	"time"

	dockerClient "github.com/docker/docker/client"
)

// dockerAvailable checks whether a local Docker daemon is reachable and the
// busybox:stable image is loaded (or can be pulled). It returns a shared
// Docker client on success or calls t.Skipf when Docker is unavailable, which
// causes the calling test to be cleanly skipped.
//
// This helper creates a Docker client directly rather than via NewDocker to
// avoid the Viper config + GELF logger dependency that NewDocker has.
// Docker host detection follows the same pattern used in api_bench_test.go.
func dockerAvailable(t *testing.T) *Docker {
	t.Helper()

	dockerHost := os.Getenv("DOCKER_HOST")
	if dockerHost == "" {
		dockerHost = "unix:///var/run/docker.sock"
	}

	cli, err := dockerClient.NewClientWithOpts(
		dockerClient.FromEnv,
		dockerClient.WithHost(dockerHost),
		dockerClient.WithAPIVersionNegotiation(),
	)
	if err != nil {
		t.Skipf("Docker unavailable (NewClientWithOpts): %v", err)
	}

	ctx := context.Background()
	if _, err := cli.Ping(ctx); err != nil {
		t.Skipf("Docker daemon unreachable (ping): %v", err)
	}

	d := &Docker{client: cli}

	const image = "busybox:stable"
	if !d.ImageIsLoaded(image) {
		if err := d.PullImage(image); err != nil {
			t.Skipf("failed to pull image %s: %v", image, err)
		}
	}

	return d
}

// createAndStart is a helper that creates a container with the given command,
// starts it, and registers cleanup. It returns the Docker handle with CID set.
func createAndStart(t *testing.T, d *Docker, cmd string) *Docker {
	t.Helper()

	docker := &Docker{client: d.client}
	cid, err := docker.CreateContainer("busybox:stable", cmd)
	if err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}
	docker.CID = cid

	t.Cleanup(func() {
		_ = docker.RemoveContainer()
	})

	if err := docker.StartContainer(); err != nil {
		t.Fatalf("StartContainer: %v", err)
	}

	return docker
}

// TestDocker_WaitContainer_Timeout verifies that WaitContainer enforces its
// timeout parameter via context.WithTimeout (the fix for bug #2 documented in
// CLAUDE.md). It runs three sub-tests:
//
//  1. "timeout enforced on stuck container" — a container that sleeps 30s
//     must return context.DeadlineExceeded when WaitContainer is called
//     with a 1-second timeout.
//
//  2. "no timeout when parameter is zero" — a container that sleeps 2s must
//     complete normally when WaitContainer is called with timeout=0
//     (background context, no deadline).
//
//  3. "container exits cleanly before timeout" — a container running "echo ok"
//     must complete without error when WaitContainer is called with a
//     30-second timeout.
func TestDocker_WaitContainer_Timeout(t *testing.T) {
	t.Parallel()

	d := dockerAvailable(t)

	t.Run("timeout enforced on stuck container", func(t *testing.T) {
		t.Parallel()

		docker := createAndStart(t, d, "sleep 30")

		start := time.Now()
		err := docker.WaitContainer(1)
		elapsed := time.Since(start)

		if err == nil {
			t.Fatal("expected context.DeadlineExceeded, got nil")
		}
		if err != context.DeadlineExceeded {
			t.Errorf("expected context.DeadlineExceeded, got %v", err)
		}
		if elapsed > 5*time.Second {
			t.Errorf("timeout took too long: %v (expected ~1s)", elapsed)
		}
	})

	t.Run("no timeout when parameter is zero", func(t *testing.T) {
		t.Parallel()

		docker := createAndStart(t, d, "sleep 2")

		err := docker.WaitContainer(0)
		if err != nil {
			t.Errorf("expected no error with zero timeout, got %v", err)
		}
	})

	t.Run("container exits cleanly before timeout", func(t *testing.T) {
		t.Parallel()

		docker := createAndStart(t, d, "echo ok")

		err := docker.WaitContainer(30)
		if err != nil {
			t.Errorf("expected no error when container exits quickly, got %v", err)
		}
	})
}
