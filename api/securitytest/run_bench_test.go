// Copyright 2026 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securitytest

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/githubanotaai/huskyci-api/api/types"
)

// BenchmarkScanGoroutineFanout measures goroutine fan-out behavior during scan
// orchestration. It runs N concurrent scans with M scanners each, samples
// runtime.NumGoroutine to capture the peak goroutine count during fan-out, and
// reports allocations.
//
// The benchmark uses mockRunner — no Docker, Kubernetes, or MongoDB
// dependencies. Each scanner goroutine sleeps briefly (1ms) to allow
// goroutine accumulation for measurement.
//
// Input range: concurrent_scans=1/10/50, scanners_per_scan=1/6/16.
// Reference: docs/assessments/performance-gap-assessment-01.md Phase 6.
func BenchmarkScanGoroutineFanout(b *testing.B) {
	concurrentScans := []int{1, 10, 50}
	scannersPerScan := []int{1, 6, 16}

	for _, concScans := range concurrentScans {
		for _, numScanners := range scannersPerScan {
			name := fmt.Sprintf("concurrent=%d/scanners=%d", concScans, numScanners)
			b.Run(name, func(b *testing.B) {
				b.ReportAllocs()

				for b.Loop() {
					// Build the scanner list shared by all concurrent scans.
					tests := make([]types.SecurityTest, 0, numScanners)
					for i := 0; i < numScanners; i++ {
						tests = append(tests, types.SecurityTest{
							Name: fmt.Sprintf("scanner_%d", i),
						})
					}

					baseline := runtime.NumGoroutine()

					var peak atomic.Int64
					var wg sync.WaitGroup
					stopSample := make(chan struct{})

					// High-frequency goroutine sampler runs during fan-out.
					wg.Add(1)
					go func() {
						defer wg.Done()
						ticker := time.NewTicker(50 * time.Microsecond)
						defer ticker.Stop()
						for {
							select {
							case <-stopSample:
								return
							case <-ticker.C:
								current := int64(runtime.NumGoroutine())
								for {
									old := peak.Load()
									if current <= old {
										break
									}
									if peak.CompareAndSwap(old, current) {
										break
									}
								}
							}
						}
					}()

					b.ResetTimer()

					// Launch concurrent scans, each with its own RunAllInfo.
					var runWG sync.WaitGroup
					for j := 0; j < concScans; j++ {
						runWG.Add(1)
						go func(idx int) {
							defer runWG.Done()

							runner := &mockRunner{
								genericTests: tests,
								newScanFunc: func(RID, URL, branch, name string, le map[string]bool, cf, dh string) (*SecTestScanInfo, error) {
									return &SecTestScanInfo{
										RID:              RID,
										SecurityTestName: name,
										Container: types.Container{
											CID:     "cid-" + name,
											CResult: "passed",
											CStatus: "finished",
										},
									}, nil
								},
								startScanFunc: func(scan *SecTestScanInfo) error {
									// Brief sleep so goroutines accumulate for measurement.
									time.Sleep(1 * time.Millisecond)
									return nil
								},
							}

							run := &RunAllInfo{runner: runner}
							enryScan := SecTestScanInfo{
								RID:    fmt.Sprintf("rid-%d", idx),
								URL:    "https://example.com/repo",
								Branch: "main",
							}
							_ = run.Start(enryScan)
						}(j)
					}

					runWG.Wait()
					b.StopTimer()
					close(stopSample)
					wg.Wait()

					// Report goroutine metrics (includes sampler goroutine).
					b.ReportMetric(float64(baseline), "baseline-goroutines")
					b.ReportMetric(float64(peak.Load()), "peak-goroutines")
					b.ReportMetric(float64(runtime.NumGoroutine()), "final-goroutines")

					b.StartTimer()
				}
			})
		}
	}
}
