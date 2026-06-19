// Copyright 2026 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build integration

package kubernetes

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sync/errgroup"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// BenchmarkKubernetesPodCreateBurst measures Kubernetes pod create + watch
// setup latency and throttle errors under parallel fan-out. Each parallel
// goroutine creates a uniquely-named pod via CreatePod, waits for it to reach
// Running then complete via WaitPod, and removes it via RemovePod.
//
// Setup requires:
//   - A Kubernetes cluster reachable via kubeconfig (KUBECONFIG env var or
//     default ~/.kube/config).
//   - The no-op image busybox:stable pre-pulled in the cluster.
//   - A test namespace (HUSKYCI_K8S_BENCH_NAMESPACE env var, otherwise
//     "default").
//
// Input range: parallelism=1,5,10,20,50.
// Reference: docs/assessments/performance-gap-assessment-01.md Phase 6,
// K8s burst spec; gap analysis finding #3 (unbounded scan admission).
func BenchmarkKubernetesPodCreateBurst(b *testing.B) {
	kubeconfig := os.Getenv("KUBECONFIG")
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		b.Skipf("Kubernetes unavailable (kubeconfig): %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		b.Skipf("Kubernetes unavailable (clientset): %v", err)
	}

	// Verify cluster connectivity before running any benchmarks.
	ctx := context.Background()
	_, err = clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil {
		b.Skipf("Kubernetes cluster unreachable: %v", err)
	}

	namespace := os.Getenv("HUSKYCI_K8S_BENCH_NAMESPACE")
	if namespace == "" {
		namespace = "default"
	}

	const image = "busybox:stable"
	const podCmd = "echo ok"
	const podSchedulingTimeout = 60 // seconds
	const podTestTimeout = 30       // seconds

	parallelismLevels := []int{1, 5, 10, 20, 50}

	for _, p := range parallelismLevels {
		b.Run(fmt.Sprintf("parallelism=%d", p), func(b *testing.B) {
			b.ReportAllocs()
			var throttleCount atomic.Int64

			for b.Loop() {
				g, gctx := errgroup.WithContext(context.Background())

				for i := 0; i < p; i++ {
					idx := i // capture for goroutine
					g.Go(func() error {
						podName := fmt.Sprintf("bench-burst-p%d-i%d-%d", p, idx, time.Now().UnixNano())

						k := Kubernetes{
							client:    clientset,
							Namespace: namespace,
						}

						_, err := k.CreatePod(image, podCmd, podName, "bench-burst")
						if err != nil {
							if isThrottleError(err) {
								throttleCount.Add(1)
							}
							return fmt.Errorf("goroutine %d CreatePod: %w", idx, err)
						}

						// Always clean up, even on error.
						defer func() {
							_ = removePodGracefully(clientset, namespace, podName)
						}()

						// Check if context was cancelled before proceeding.
						select {
						case <-gctx.Done():
							return gctx.Err()
						default:
						}

						_, err = k.WaitPod(podName, podSchedulingTimeout, podTestTimeout)
						if err != nil {
							if isThrottleError(err) {
								throttleCount.Add(1)
							}
							return fmt.Errorf("goroutine %d WaitPod: %w", idx, err)
						}

						return nil
					})
				}

				if err := g.Wait(); err != nil {
					b.Errorf("errgroup failed: %v", err)
				}
			}

			if tc := throttleCount.Load(); tc > 0 {
				b.ReportMetric(float64(tc), "throttle-errors")
			}
		})
	}
}

// removePodGracefully deletes a pod by name and swallows errors on
// already-deleted pods so that defer-based cleanup is safe regardless of
// whether the pod still exists.
func removePodGracefully(clientset kubernetes.Interface, namespace, podName string) error {
	err := clientset.CoreV1().Pods(namespace).Delete(
		context.Background(), podName, metav1.DeleteOptions{})
	if err != nil && !isNotFoundError(err) {
		return err
	}
	return nil
}

// isThrottleError returns true if err indicates server-side throttling (HTTP
// 429) or client-side rate-limiting delay. It uses a best-effort substring
// check that covers the common client-go and API server throttle messages.
func isThrottleError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "429") ||
		strings.Contains(msg, "TooManyRequests") ||
		strings.Contains(msg, "throttl")
}

// isNotFoundError returns true if err indicates the Kubernetes resource was
// not found (HTTP 404). Used by removePodGracefully to avoid failing cleanup
// on already-deleted pods.
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "not found")
}
