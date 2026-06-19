// Copyright 2019 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package token_test

import (
	"crypto/rand"
	"fmt"
	"hash"
	"runtime"
	"testing"
	"time"

	"github.com/githubanotaai/huskyci-api/api/token"
	"github.com/githubanotaai/huskyci-api/api/types"
)

// fakePbkdf2Generator implements auth.Pbkdf2Generator for timing tests.
// GenHashValue returns a fixed, controlled string to allow testing of
// the constant-time comparison in ValidateRandomData.
type fakePbkdf2Generator struct {
	hashValue  string
	hashName   string
	iterations int
	keyLength  int
	decodeSalt func(string) ([]byte, error)
}

func (f *fakePbkdf2Generator) GetCredsFromDB(username string) (types.User, error) {
	return types.User{}, nil
}

func (f *fakePbkdf2Generator) DecodeSaltValue(salt string) ([]byte, error) {
	if f.decodeSalt != nil {
		return f.decodeSalt(salt)
	}
	return []byte(salt), nil
}

func (f *fakePbkdf2Generator) GenHashValue(value, salt []byte, iter, keyLen int, h hash.Hash) string {
	return f.hashValue
}

func (f *fakePbkdf2Generator) GenerateSalt() (string, error) {
	return "", nil
}

func (f *fakePbkdf2Generator) GetHashName() string {
	if f.hashName == "" {
		return "SHA256"
	}
	return f.hashName
}

func (f *fakePbkdf2Generator) GetIterations() int {
	if f.iterations == 0 {
		return 1
	}
	return f.iterations
}

func (f *fakePbkdf2Generator) GetKeyLength() int {
	if f.keyLength == 0 {
		return 32
	}
	return f.keyLength
}

func TestTokenRandomData_RejectsWrongHash(t *testing.T) {
	fake := &fakePbkdf2Generator{
		hashValue: "theGeneratedHashValue",
	}
	th := &token.THandler{HashGen: fake}

	err := th.ValidateRandomData("randomdata", "differentHashValue", "salt123")
	if err == nil {
		t.Error("expected error when hashes differ")
		return
	}
	if err.Error() != "Hash value from random data is different" {
		t.Errorf("expected specific error message, got: %v", err)
	}
}

func TestTokenRandomData_AcceptsCorrectHash(t *testing.T) {
	fake := &fakePbkdf2Generator{
		hashValue: "matchingHashValue",
	}
	th := &token.THandler{HashGen: fake}

	err := th.ValidateRandomData("randomdata", "matchingHashValue", "salt123")
	if err != nil {
		t.Errorf("expected nil error, got: %v", err)
	}
}

func TestTokenRandomData_TimingConstantTime(t *testing.T) {
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
			earlyMean := measureTokenEarlyDiff(t, size, iterations)
			lateMean := measureTokenLateDiff(t, size, iterations)

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

// measureTokenEarlyDiff returns the mean ValidateRandomData duration when
// the fake hash value and hashdata differ at the first byte (position 0).
func measureTokenEarlyDiff(t *testing.T, size, iterations int) time.Duration {
	t.Helper()
	fakeHashVal, hashdata := generateDifferingTokenStrings(t, size, 0)
	return measureTokenTiming(t, fakeHashVal, hashdata, iterations)
}

// measureTokenLateDiff returns the mean ValidateRandomData duration when
// the fake hash value and hashdata differ at the last byte.
func measureTokenLateDiff(t *testing.T, size, iterations int) time.Duration {
	t.Helper()
	fakeHashVal, hashdata := generateDifferingTokenStrings(t, size, size-1)
	return measureTokenTiming(t, fakeHashVal, hashdata, iterations)
}

// generateDifferingTokenStrings creates two byte slices of the given size
// filled with crypto/rand data. The slices are identical except at diffPos
// where the second slice has its byte flipped (XOR 0xFF).
func generateDifferingTokenStrings(t *testing.T, size, diffPos int) (string, string) {
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

// measureTokenTiming runs ValidateRandomData the given number of times with
// the supplied fake hash value and hashdata and returns the mean duration.
func measureTokenTiming(t *testing.T, fakeHashValue, hashdata string, iterations int) time.Duration {
	t.Helper()
	fake := &fakePbkdf2Generator{
		hashValue: fakeHashValue,
	}
	th := &token.THandler{HashGen: fake}

	var total time.Duration
	for i := 0; i < iterations; i++ {
		start := time.Now()
		err := th.ValidateRandomData("randomdata", hashdata, "salt")
		_ = err
		total += time.Since(start)
	}
	return total / time.Duration(iterations)
}
