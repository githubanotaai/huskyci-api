// Copyright 2019 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package auth_test

import (
	"crypto/rand"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/githubanotaai/huskyci-api/api/auth"
)

// fakeTimingClient implements auth.UserCredsHandler for timing tests.
type fakeTimingClient struct {
	passDB     string
	hashedPass string
	err        error
}

func (f *fakeTimingClient) GetPassFromDB(username string) (string, error) {
	return f.passDB, f.err
}

func (f *fakeTimingClient) GetHashedPass(password string) (string, error) {
	return f.hashedPass, f.err
}

func TestPasswordComparison_RejectsWrongPassword(t *testing.T) {
	fc := &fakeTimingClient{
		passDB:     "passFromDB",
		hashedPass: "differentHashedValue",
	}
	mc := auth.MongoBasic{ClientHandler: fc}

	valid, err := mc.IsValidUser("user", "password")
	if valid {
		t.Error("expected false when passDB and hashedPass differ")
	}
	if err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}
}

func TestPasswordComparison_AcceptsCorrectPassword(t *testing.T) {
	fc := &fakeTimingClient{
		passDB:     "sameValue",
		hashedPass: "sameValue",
	}
	mc := auth.MongoBasic{ClientHandler: fc}

	valid, err := mc.IsValidUser("user", "password")
	if !valid {
		t.Error("expected true when passDB and hashedPass match")
	}
	if err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}
}

func TestPasswordComparison_TimingConstantTime(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing test in short mode")
	}
	// macOS clock resolution is too coarse for reliable timing measurements;
	// kernel timer coalescing and power management introduce excessive noise.
	if runtime.GOOS == "darwin" {
		t.Skip("skipping timing test on macOS: clock noise makes measurements unreliable")
	}

	sizes := []int{64, 128, 256, 512, 1024}
	iterations := 2000

	for _, size := range sizes {
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			earlyMean := measureEarlyDiff(t, size, iterations)
			lateMean := measureLateDiff(t, size, iterations)

			if lateMean == 0 {
				t.Fatal("late-diff timing is zero; cannot compute ratio")
			}

			ratio := float64(earlyMean) / float64(lateMean)
			if ratio >= 2.0 {
				t.Errorf("timing ratio too high for size %d: early=%v, late=%v, ratio=%.2f",
					size, earlyMean, lateMean, ratio)
			}
		})
	}
}

// measureEarlyDiff returns the mean IsValidUser duration when passDB and
// hashedPass differ at the first byte (position 0).
func measureEarlyDiff(t *testing.T, size, iterations int) time.Duration {
	t.Helper()
	passDB, hashedPass := generateDifferingStrings(t, size, 0)
	return measureTiming(t, passDB, hashedPass, iterations)
}

// measureLateDiff returns the mean IsValidUser duration when passDB and
// hashedPass differ at the last byte.
func measureLateDiff(t *testing.T, size, iterations int) time.Duration {
	t.Helper()
	passDB, hashedPass := generateDifferingStrings(t, size, size-1)
	return measureTiming(t, passDB, hashedPass, iterations)
}

// generateDifferingStrings creates two byte slices of the given size filled
// with crypto/rand data. The slices are identical except at diffPos where the
// second slice has its byte flipped (XOR 0xFF).
func generateDifferingStrings(t *testing.T, size, diffPos int) (string, string) {
	t.Helper()
	a := make([]byte, size)
	if _, err := rand.Read(a); err != nil {
		t.Fatalf("failed to generate random data: %v", err)
	}
	b := make([]byte, size)
	copy(b, a)
	b[diffPos] ^= 0xFF
	return string(a), string(b)
}

// measureTiming runs IsValidUser the given number of times with the supplied
// passDB and hashedPass values and returns the mean duration per call.
func measureTiming(t *testing.T, passDB, hashedPass string, iterations int) time.Duration {
	t.Helper()
	fc := &fakeTimingClient{
		passDB:     passDB,
		hashedPass: hashedPass,
	}
	mc := auth.MongoBasic{ClientHandler: fc}

	var total time.Duration
	for i := 0; i < iterations; i++ {
		start := time.Now()
		valid, err := mc.IsValidUser("user", "password")
		_ = valid
		_ = err
		total += time.Since(start)
	}
	return total / time.Duration(iterations)
}
