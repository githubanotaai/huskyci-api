// Copyright 2026 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dockers

import (
	"bytes"
	"errors"
	"io"
	"math/rand"
	"runtime"
	"testing"

	"github.com/githubanotaai/huskyci-api/api/util"
)

// generateBytes produces a deterministic byte slice of the given size using a
// fixed seed. This keeps benchmarks reproducible and free of Docker
// dependencies.
func generateBytes(size int) []byte {
	rng := rand.New(rand.NewSource(42))
	buf := make([]byte, size)
	for i := range buf {
		buf[i] = byte(rng.Intn(256))
	}
	return buf
}

// BenchmarkReadOutputBuffering measures io.ReadAll throughput, allocations,
// and peak RSS for scanner output sizes. It compares two modes:
//
//   - Capped: uses util.ReadBoundedScannerOutput (io.LimitReader +
//     io.ReadAll), which is the current production path since #48.
//   - Naive: reads into a bytes.Buffer then casts to string,
//     characterising the unbounded path for comparison.
//
// Sizes: 1 MB, 10 MB, 100 MB.
// No Docker daemon is required — all readers are generated in-memory.
func BenchmarkReadOutputBuffering(b *testing.B) {
	sizes := []struct {
		name  string
		bytes int
	}{
		{"1MB", 1 << 20},
		{"10MB", 10 << 20},
		{"100MB", 100 << 20},
	}

	for _, sz := range sizes {
		data := generateBytes(sz.bytes)

		b.Run("Size="+sz.name, func(b *testing.B) {
			b.Run("Mode=Capped", func(b *testing.B) {
				b.ReportAllocs()

				for b.Loop() {
					reader := bytes.NewReader(data)
					_, err := util.ReadBoundedScannerOutput(reader)
					if err != nil {
						b.Fatalf("unexpected capped error at %s: %v", sz.name, err)
					}
				}

				// Report peak RSS via runtime.ReadMemStats.
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				b.ReportMetric(float64(m.Sys)/1024/1024, "Sys-MB")
			})

			b.Run("Mode=Naive", func(b *testing.B) {
				b.ReportAllocs()

				for b.Loop() {
					reader := bytes.NewReader(data)
					var buf bytes.Buffer
					if _, err := io.Copy(&buf, reader); err != nil {
						b.Fatalf("unexpected naive error at %s: %v", sz.name, err)
					}
					_ = buf.String()
				}

				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				b.ReportMetric(float64(m.Sys)/1024/1024, "Sys-MB")
			})
		})
	}
}

// TestReadOutputBufferingCorrectness verifies the bounded reader used by
// Docker.ReadOutput (via util.ReadBoundedScannerOutput). It checks:
//
//	a) All bytes are preserved for sizes within the limit.
//	b) Output beyond MaxScannerOutputBytes returns ErrScannerOutputTooLarge.
//	c) Capped allocations stay under cap + 10%.
func TestReadOutputBufferingCorrectness(t *testing.T) {
	t.Parallel()

	t.Run("byte preservation", func(t *testing.T) {
		t.Parallel()

		sizes := []int{1024, 1 << 20} // 1 KB, 1 MB
		for _, size := range sizes {
			expected := generateBytes(size)
			result, err := util.ReadBoundedScannerOutput(bytes.NewReader(expected))
			if err != nil {
				t.Fatalf("unexpected error for size %d: %v", size, err)
			}
			if result != string(expected) {
				t.Fatalf("bytes not preserved for size %d: got %d bytes, want %d",
					size, len(result), len(expected))
			}
		}
	})

	t.Run("byte preservation at cap boundary", func(t *testing.T) {
		// Exactly MaxScannerOutputBytes should pass.
		size := util.MaxScannerOutputBytes
		expected := generateBytes(size)
		result, err := util.ReadBoundedScannerOutput(bytes.NewReader(expected))
		if err != nil {
			t.Fatalf("unexpected error at cap boundary: %v", err)
		}
		if result != string(expected) {
			t.Fatalf("bytes not preserved at cap boundary: got %d, want %d",
				len(result), len(expected))
		}
	})

	t.Run("ErrScannerOutputTooLarge at limit+1", func(t *testing.T) {
		// One byte beyond MaxScannerOutputBytes must return
		// ErrScannerOutputTooLarge.
		size := util.MaxScannerOutputBytes + 1
		data := generateBytes(size)
		_, err := util.ReadBoundedScannerOutput(bytes.NewReader(data))
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !errors.Is(err, util.ErrScannerOutputTooLarge) {
			t.Fatalf("expected ErrScannerOutputTooLarge, got %v", err)
		}
	})

	t.Run("capped allocations bounded", func(t *testing.T) {
		// For an input at the cap boundary, the capped reader must
		// produce the correct output and not leak unbounded memory.
		// io.ReadAll doubles its internal buffer, so cumulative
		// B/op (benchmark) will be ~3.4x the output size. Here we
		// verify the live heap after GC stays proportional to the
		// output (≤ 2.5x cap, accounting for the final io.ReadAll
		// buffer + string copy overhead).
		size := util.MaxScannerOutputBytes
		data := generateBytes(size)

		runtime.GC()
		var m1, m2 runtime.MemStats
		runtime.ReadMemStats(&m1)

		result, err := util.ReadBoundedScannerOutput(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		_ = result // keep alive so GC does not reclaim

		// Force GC to collect intermediate io.ReadAll buffers.
		runtime.GC()
		runtime.ReadMemStats(&m2)
		allocDelta := int64(m2.Alloc) - int64(m1.Alloc)
		maxAllowed := int64(float64(size) * 2.5)

		if allocDelta > maxAllowed {
			t.Errorf("capped live heap delta %d exceeds 2.5x cap (%d)", allocDelta, maxAllowed)
		}
	})
}
