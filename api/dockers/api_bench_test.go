// Copyright 2026 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build integration

package dockers

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/sync/errgroup"
)

// BenchmarkDockerContainerStartBurst measures Docker ContainerCreate +
// ContainerStart latency under increasing parallel scanner starts. It fans out
// goroutines that each create a uniquely-named container, start it, wait for
// completion, read output, and then remove the container via defer.
//
// Setup requires a local Docker daemon (DOCKER_HOST env var or default Unix
// socket) and the busybox:stable image pre-pulled. If Docker is unavailable,
// the benchmark calls b.Skip() rather than failing.
//
// Input range: parallelism=1,5,10,20,50.
// Reference: docs/assessments/performance-gap-assessment-01.md Phase 6,
// Docker burst spec; gap analysis finding #3 (unbounded scan admission).
func BenchmarkDockerContainerStartBurst(b *testing.B) {
	dockerHost := os.Getenv("DOCKER_HOST")
	if dockerHost == "" {
		dockerHost = "unix:///var/run/docker.sock"
	}

	// Verify Docker daemon is reachable before running any benchmarks.
	d, err := NewDocker(dockerHost)
	if err != nil {
		b.Skipf("Docker unavailable (NewDocker): %v", err)
	}
	ctx := context.Background()
	if _, err := d.client.Ping(ctx); err != nil {
		b.Skipf("Docker daemon unreachable (ping): %v", err)
	}

	const image = "busybox:stable"
	const containerCmd = "echo ok"
	const containerTimeout = 30 // seconds per container

	// Pre-pull the no-op image if it is not already present.
	if !d.ImageIsLoaded(image) {
		if err := d.PullImage(image); err != nil {
			b.Fatalf("failed to pull image %s: %v", image, err)
		}
	}

	parallelismLevels := []int{1, 5, 10, 20, 50}

	for _, p := range parallelismLevels {
		b.Run(fmt.Sprintf("parallelism=%d", p), func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				g, gctx := errgroup.WithContext(context.Background())
				// No SetLimit — let all p goroutines fan out unrestrained
				// to measure the raw Docker daemon throughput ceiling.

				for i := 0; i < p; i++ {
					idx := i // capture for goroutine
					g.Go(func() error {
						// Share the single Docker client to avoid
						// re-creating client state per goroutine (gap
						// assessment § "Docker clients per host").
						docker := Docker{client: d.client}

						cid, err := docker.CreateContainer(image, containerCmd)
						if err != nil {
							return fmt.Errorf("goroutine %d CreateContainer: %w", idx, err)
						}
						docker.CID = cid

						// Always clean up, even on error.
						defer func() {
							_ = docker.RemoveContainer()
						}()

						if err := docker.StartContainer(); err != nil {
							return fmt.Errorf("goroutine %d StartContainer: %w", idx, err)
						}
						if err := docker.WaitContainer(containerTimeout); err != nil {
							return fmt.Errorf("goroutine %d WaitContainer: %w", idx, err)
						}
						if _, err := docker.ReadOutput(); err != nil {
							return fmt.Errorf("goroutine %d ReadOutput: %w", idx, err)
						}

						return nil
					})

					// Check if context was cancelled (another goroutine failed).
					select {
					case <-gctx.Done():
						break
					default:
					}
				}

				if err := g.Wait(); err != nil {
					b.Errorf("errgroup failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkDockerContainerStartBurstSerial is a single-container benchmark
// that measures the minimum latency for one container create+start+wait
// cycle. It runs without the integration build tag so it can be used as a
// fast serial baseline when Docker is available on a developer machine (run
// with -tags=integration). The benchmark uses b.Skip when Docker is
// unavailable.
func BenchmarkDockerContainerStartBurstSerial(b *testing.B) {
	dockerHost := os.Getenv("DOCKER_HOST")
	if dockerHost == "" {
		dockerHost = "unix:///var/run/docker.sock"
	}

	d, err := NewDocker(dockerHost)
	if err != nil {
		b.Skipf("Docker unavailable (NewDocker): %v", err)
	}
	ctx := context.Background()
	if _, err := d.client.Ping(ctx); err != nil {
		b.Skipf("Docker daemon unreachable (ping): %v", err)
	}

	const image = "busybox:stable"
	const containerCmd = "echo ok"
	const containerTimeout = 30

	if !d.ImageIsLoaded(image) {
		if err := d.PullImage(image); err != nil {
			b.Fatalf("failed to pull image %s: %v", image, err)
		}
	}

	docker := Docker{client: d.client}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		cid, err := docker.CreateContainer(image, containerCmd)
		if err != nil {
			b.Fatalf("CreateContainer: %v", err)
		}
		docker.CID = cid

		deferFuncRan := false
		cleanup := func() {
			if !deferFuncRan {
				_ = docker.RemoveContainer()
				deferFuncRan = true
			}
		}

		if err := docker.StartContainer(); err != nil {
			cleanup()
			b.Fatalf("StartContainer: %v", err)
		}
		if err := docker.WaitContainer(containerTimeout); err != nil {
			cleanup()
			b.Fatalf("WaitContainer: %v", err)
		}
		if _, err := docker.ReadOutput(); err != nil {
			cleanup()
			b.Fatalf("ReadOutput: %v", err)
		}
		cleanup()

		// Remove the container — required to avoid name/id conflicts
		// across b.Loop() iterations.
		time.Sleep(10 * time.Millisecond)
	}
}
