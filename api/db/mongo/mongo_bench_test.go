// Copyright 2026 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build integration

package db

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/githubanotaai/huskyci-api/api/types"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

const (
	benchDB        = "huskyci_bench_analysis"
	benchColl      = "analysis"
	p99ThresholdNs = 50 * 1e6 // 50 ms in nanoseconds
)

// buildBenchAnalysis creates a realistic but lightweight types.Analysis
// document for benchmark seeding. Varies URL, branch, and status so that
// different query patterns (RID lookup, URL+branch filter, URL+branch+status
// filter) exercise distinct document subsets.
func buildBenchAnalysis(idx int) types.Analysis {
	now := time.Now()
	repoOrg := idx % 10
	repoNumber := idx % 1000
	branch := []string{"main", "develop", "feature/foo", "release/v1.0", "hotfix/bar"}[idx%5]
	docStatus := []string{"running", "finished", "error"}[idx%3]
	result := []string{"passed", "failed"}[idx%2]

	return types.Analysis{
		RID:           fmt.Sprintf("bench-rid-%024d", idx),
		URL:           fmt.Sprintf("https://github.com/org%d/repo%d.git", repoOrg, repoNumber),
		Branch:        branch,
		CommitAuthors: []string{fmt.Sprintf("author%d@example.com", idx%5)},
		Status:        docStatus,
		Result:        result,
		Containers: []types.Container{
			{
				CID: fmt.Sprintf("container-bench-%024d-1", idx),
				SecurityTest: types.SecurityTest{
					Name:             "gosec",
					Image:            "huskyci/gosec:latest",
					ImageTag:         "latest",
					Cmd:              "gosec ./...",
					Type:             "Go",
					Language:         "Go",
					Default:          true,
					TimeOutInSeconds: 600,
				},
				CStatus:    docStatus,
				COutput:    "scanned files",
				CResult:    result,
				CInfo:      fmt.Sprintf("container %d output", idx),
				StartedAt:  now.Add(-5 * time.Minute),
				FinishedAt: now,
			},
		},
		Codes: []types.Code{
			{Language: "Go", Files: []string{fmt.Sprintf("file%d.go", idx)}},
		},
		StartedAt:  now.Add(-10 * time.Minute),
		FinishedAt: now,
		HuskyCIResults: types.HuskyCIResults{
			GoResults: types.GoResults{
				HuskyCIGosecOutput: types.HuskyCISecurityTestOutput{
					LowVulns: []types.HuskyCIVulnerability{
						{
							Language:     "Go",
							SecurityTool: "gosec",
							Severity:     "low",
							Confidence:   "high",
							File:         fmt.Sprintf("file%d.go", idx),
							Line:         fmt.Sprintf("%d", idx%100),
							Code:         fmt.Sprintf("call_%d()", idx),
							Details:      "Sample vulnerability for benchmarking",
							Type:         "CWE-79",
							Title:        fmt.Sprintf("Vuln %d", idx),
						},
					},
				},
			},
		},
	}
}

// seedAnalysisCollection inserts numDocs synthetic Analysis documents into
// the given collection using bulk unordered inserts for efficiency.
func seedAnalysisCollection(b *testing.B, coll *mongo.Collection, numDocs int) {
	b.Helper()

	const bulkSize = 500
	var models []mongo.WriteModel

	for i := 0; i < numDocs; i++ {
		doc := buildBenchAnalysis(i)
		models = append(models, mongo.NewInsertOneModel().SetDocument(doc))

		if len(models) >= bulkSize || i == numDocs-1 {
			_, err := coll.BulkWrite(context.TODO(), models, options.BulkWrite().SetOrdered(false))
			if err != nil {
				b.Fatalf("failed to seed analysis documents (batch at offset %d): %v", i-len(models)+1, err)
			}
			models = models[:0]
		}
	}
	b.Logf("Seeded %d analysis documents", numDocs)
}

// createBenchIndexes creates the proposed indexes on the analysis collection:
//   - {RID: 1} unique
//   - {repositoryURL: 1, repositoryBranch: 1, status: 1}
func createBenchIndexes(b *testing.B, coll *mongo.Collection) {
	b.Helper()

	indexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "RID", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys: bson.D{
				{Key: "repositoryURL", Value: 1},
				{Key: "repositoryBranch", Value: 1},
				{Key: "status", Value: 1},
			},
		},
	}

	ctx := context.TODO()
	for _, idx := range indexes {
		_, err := coll.Indexes().CreateOne(ctx, idx)
		if err != nil {
			b.Fatalf("failed to create index on %v: %v", idx.Keys, err)
		}
	}
	b.Logf("Created indexes on %s", coll.Name())
}

// runQueryBenchmarks registers sub-benchmarks for the four query types
// (RID, url_branch, url_branch_status, update_RID) using the provided
// collection and reference document values. indexed controls whether
// the "with_indexes" or "no_indexes" suffix is used in benchmark names
// and whether the P99 threshold check is applied.
func runQueryBenchmarks(
	b *testing.B,
	numDocs int,
	indexed bool,
	coll *mongo.Collection,
	refRID, refURL, refBranch, refStatus, updateRID string,
) {
	idxLabel := "no_indexes"
	if indexed {
		idxLabel = "with_indexes"
	}

	// ── RID lookup ──
	b.Run(fmt.Sprintf("docs=%d/query=RID/%s", numDocs, idxLabel), func(b *testing.B) {
		b.ReportAllocs()
		query := bson.M{"RID": refRID}
		var result types.Analysis
		var elapsed time.Duration

		for b.Loop() {
			start := time.Now()
			err := coll.FindOne(context.TODO(), query).Decode(&result)
			elapsed = time.Since(start)
			if err != nil {
				b.Fatalf("RID lookup failed: %v", err)
			}
		}

		b.ReportMetric(float64(elapsed.Nanoseconds()), "ns/op")
		checkLatencyThreshold(b, indexed, elapsed)
	})

	// ── URL + branch lookup ──
	b.Run(fmt.Sprintf("docs=%d/query=url_branch/%s", numDocs, idxLabel), func(b *testing.B) {
		b.ReportAllocs()
		query := bson.M{"repositoryURL": refURL, "repositoryBranch": refBranch}
		var result types.Analysis
		var elapsed time.Duration

		for b.Loop() {
			start := time.Now()
			err := coll.FindOne(context.TODO(), query).Decode(&result)
			elapsed = time.Since(start)
			if err != nil {
				b.Fatalf("url_branch lookup failed: %v", err)
			}
		}

		b.ReportMetric(float64(elapsed.Nanoseconds()), "ns/op")
		checkLatencyThreshold(b, indexed, elapsed)
	})

	// ── URL + branch + status lookup ──
	b.Run(fmt.Sprintf("docs=%d/query=url_branch_status/%s", numDocs, idxLabel), func(b *testing.B) {
		b.ReportAllocs()
		query := bson.M{
			"repositoryURL":    refURL,
			"repositoryBranch": refBranch,
			"status":           refStatus,
		}
		var result types.Analysis
		var elapsed time.Duration

		for b.Loop() {
			start := time.Now()
			err := coll.FindOne(context.TODO(), query).Decode(&result)
			elapsed = time.Since(start)
			if err != nil {
				b.Fatalf("url_branch_status lookup failed: %v", err)
			}
		}

		b.ReportMetric(float64(elapsed.Nanoseconds()), "ns/op")
		checkLatencyThreshold(b, indexed, elapsed)
	})

	// ── Update by RID ──
	b.Run(fmt.Sprintf("docs=%d/query=update_RID/%s", numDocs, idxLabel), func(b *testing.B) {
		b.ReportAllocs()
		filter := bson.M{"RID": updateRID}
		update := bson.M{"$set": bson.M{"status": "finished"}}
		var elapsed time.Duration

		for b.Loop() {
			start := time.Now()
			_, err := coll.UpdateOne(context.TODO(), filter, update)
			elapsed = time.Since(start)
			if err != nil {
				b.Fatalf("update_RID failed: %v", err)
			}
		}

		b.ReportMetric(float64(elapsed.Nanoseconds()), "ns/op")
		checkLatencyThreshold(b, indexed, elapsed)
	})
}

// checkLatencyThreshold logs a warning if this is an indexed benchmark run
// and the operation latency exceeds 50 ms.
func checkLatencyThreshold(b *testing.B, indexed bool, elapsed time.Duration) {
	if indexed && elapsed > time.Duration(p99ThresholdNs) {
		b.Logf("WARNING: indexed operation took %v (> %.0f ms)", elapsed, float64(p99ThresholdNs)/1e6)
	}
}

// BenchmarkMongoAnalysisQueries measures FindOne and UpdateOne latency
// as the analysis collection grows (1k, 10k, 100k documents), with and
// without MongoDB indexes.
//
// Setup: connects to MongoDB via HUSKYCI_BENCH_MONGO_URI; skips if not set
// or connection fails. Uses a dedicated test database that is dropped on
// cleanup (b.Cleanup).
//
// Input range: docs={1k,10k,100k} × query={RID,url_branch,url_branch_status,update_RID} × {no_indexes,with_indexes}
//
// Reference: docs/assessments/performance-gap-assessment-01.md Phase 6,
// MongoDB query benchmark spec; gap analysis finding #11.
func BenchmarkMongoAnalysisQueries(b *testing.B) {
	uri := os.Getenv("HUSKYCI_BENCH_MONGO_URI")
	if uri == "" {
		b.Skip("HUSKYCI_BENCH_MONGO_URI not set")
	}

	// Connect to MongoDB using the same pattern as mongo.go.
	clientOptions := options.Client().ApplyURI(uri).SetConnectTimeout(5 * time.Second)
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		b.Skipf("MongoDB connection failed: %v", err)
	}

	if err := client.Ping(context.TODO(), readpref.Primary()); err != nil {
		_ = client.Disconnect(context.TODO())
		b.Skipf("MongoDB ping failed: %v", err)
	}

	// Use a dedicated test database to avoid contaminating real data.
	testDB := client.Database(benchDB)
	coll := testDB.Collection(benchColl)

	b.Cleanup(func() {
		_ = testDB.Drop(context.TODO())
		_ = client.Disconnect(context.TODO())
	})

	docCounts := []int{1000, 10000, 100000}

	for _, numDocs := range docCounts {
		// Start fresh for each doc-count tier.
		_ = coll.Drop(context.TODO())

		// Seed documents.
		seedAnalysisCollection(b, coll, numDocs)

		// Reference document values for queries (pick the middle document).
		refIdx := numDocs / 2
		ref := buildBenchAnalysis(refIdx)
		refRID := ref.RID
		refURL := ref.URL
		refBranch := ref.Branch
		refStatus := ref.Status

		// Use a different RID for the update benchmark so the update
		// side-effect doesn't interfere with lookup benchmarks.
		upd := buildBenchAnalysis(numDocs - 1)
		updateRID := upd.RID

		// ── Run queries WITHOUT indexes ──
		runQueryBenchmarks(b, numDocs, false, coll,
			refRID, refURL, refBranch, refStatus, updateRID)

		// ── Create indexes ──
		createBenchIndexes(b, coll)

		// ── Run queries WITH indexes ──
		runQueryBenchmarks(b, numDocs, true, coll,
			refRID, refURL, refBranch, refStatus, updateRID)

		// Drop collection (and thus indexes) for the next doc-count tier.
		_ = coll.Drop(context.TODO())
	}
}

// BenchmarkMongoReconnectDuringScan measures MongoDB operation latency and
// error behavior while the MongoDB connection is interrupted during active
// scan-like DB operations (FindOne/Update). Goroutines issue concurrent
// operations against a seeded collection while the client connection is
// deliberately disrupted and then restored, simulating the auto-reconnect
// loop in autoReconnect (mongo.go:77-94).
//
// Setup: connects to MongoDB via HUSKYCI_BENCH_MONGO_URI; skips if not set
// or connection/ping fails. Uses a dedicated test database that is dropped on
// cleanup (b.Cleanup).
//
// Input range: concurrent_operations={1,10,50} × interruption_duration={1s,5s}
//
// Reference: docs/assessments/performance-gap-assessment-01.md Phase 6,
// reconnect latency spec; gap analysis finding #11.
func BenchmarkMongoReconnectDuringScan(b *testing.B) {
	uri := os.Getenv("HUSKYCI_BENCH_MONGO_URI")
	if uri == "" {
		b.Skip("HUSKYCI_BENCH_MONGO_URI not set")
	}

	// Connect to MongoDB using the same pattern as mongo.go.
	clientOptions := options.Client().ApplyURI(uri).SetConnectTimeout(5 * time.Second)
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		b.Skipf("MongoDB connection failed: %v", err)
	}

	if err := client.Ping(context.TODO(), readpref.Primary()); err != nil {
		_ = client.Disconnect(context.TODO())
		b.Skipf("MongoDB ping failed: %v", err)
	}

	// Use a dedicated test database to avoid contaminating real data.
	testDB := client.Database("huskyci_bench_reconnect")
	coll := testDB.Collection("analysis_reconnect")

	b.Cleanup(func() {
		_ = testDB.Drop(context.TODO())
		_ = client.Disconnect(context.TODO())
	})

	// Drop and seed the collection with enough documents for read operations.
	_ = coll.Drop(context.TODO())
	seedAnalysisCollection(b, coll, 1000)

	concurrencyLevels := []int{1, 10, 50}
	interruptionDurations := []time.Duration{1 * time.Second, 5 * time.Second}

	// Reference server selection timeout for blocked-operation detection.
	referenceTimeout := 10 * time.Second

	for _, concurrent := range concurrencyLevels {
		for _, intrDuration := range interruptionDurations {
			name := fmt.Sprintf("concurrent=%d/interruption=%s", concurrent, intrDuration)
			b.Run(name, func(b *testing.B) {
				b.ReportAllocs()

				for b.Loop() {
					initialGoroutines := runtime.NumGoroutine()

					var (
						successCount   atomic.Int64
						errorCount     atomic.Int64
						totalLatencyNs atomic.Int64
						maxLatencyNs   atomic.Int64
						blockedOps     atomic.Int64
					)

					var wg sync.WaitGroup
					startCh := make(chan struct{})

					for i := 0; i < concurrent; i++ {
						wg.Add(1)
						go func(goroutineID int) {
							defer wg.Done()
							<-startCh

							var opErr error
							start := time.Now()

							if goroutineID%2 == 0 {
								// FindOne operation
								query := bson.M{"RID": fmt.Sprintf("bench-rid-%024d", goroutineID%1000)}
								var result types.Analysis
								opErr = coll.FindOne(context.TODO(), query).Decode(&result)
							} else {
								// UpdateOne operation
								filter := bson.M{"RID": fmt.Sprintf("bench-rid-%024d", goroutineID%1000)}
								update := bson.M{"$set": bson.M{"status": "finished"}}
								_, opErr = coll.UpdateOne(context.TODO(), filter, update)
							}

							elapsed := time.Since(start)
							elapsedNs := elapsed.Nanoseconds()

							if opErr != nil {
								errorCount.Add(1)
							} else {
								successCount.Add(1)
							}
							totalLatencyNs.Add(elapsedNs)

							for {
								old := maxLatencyNs.Load()
								if elapsedNs <= old || maxLatencyNs.CompareAndSwap(old, elapsedNs) {
									break
								}
							}

							if elapsed > referenceTimeout {
								blockedOps.Add(1)
							}
						}(i)
					}

					// Signal all goroutines to start.
					close(startCh)

					// Brief warm-up before interruption.
					time.Sleep(100 * time.Millisecond)

					// Trigger connection interruption (simulate network failure).
					_ = client.Disconnect(context.TODO())

					// Wait for the interruption duration.
					time.Sleep(intrDuration)

					// Reconnect (mimic autoReconnect reconnect cycle).
					reconnectErr := client.Connect(context.TODO())
					if reconnectErr != nil {
						b.Logf("WARNING: reconnect failed: %v", reconnectErr)
					}

					// Wait for all operations to complete.
					wg.Wait()

					// Collect final goroutine count for leak detection.
					finalGoroutines := runtime.NumGoroutine()

					// Compute and report metrics.
					successes := successCount.Load()
					errors := errorCount.Load()
					totalOps := successes + errors
					avgLatencyNs := int64(0)
					if totalOps > 0 {
						avgLatencyNs = totalLatencyNs.Load() / totalOps
					}

					b.ReportMetric(float64(avgLatencyNs), "ns/op")
					b.ReportMetric(float64(errors), "errors")
					b.ReportMetric(float64(successes), "successes")
					if totalOps > 0 {
						errPct := float64(errors) / float64(totalOps) * 100
						b.ReportMetric(errPct, "error_pct")
					}
					b.ReportMetric(float64(maxLatencyNs.Load()), "max_latency_ns")

					// Goroutine leak detection.
					expectedMax := initialGoroutines + concurrent
					if finalGoroutines > expectedMax {
						b.Logf("WARNING: goroutine leak detected: initial=%d final=%d expected_max=%d",
							initialGoroutines, finalGoroutines, expectedMax)
					}

					// Blocked operation detection.
					if blocked := blockedOps.Load(); blocked > 0 {
						b.Logf("WARNING: %d operation(s) blocked beyond reference timeout (%v)",
							blocked, referenceTimeout)
					}
				}
			})
		}
	}
}
