// Copyright 2026 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package db

import (
	"testing"
	"time"

	"github.com/githubanotaai/huskyci-api/api/log"
)

// stubLogger is a no-op logger that satisfies the log.logger interface.
type stubLogger struct{}

func (s *stubLogger) SendLog(extra map[string]interface{}, loglevel string, messages ...interface{}) error {
	return nil
}

func init() {
	// Install a stub logger so that Connect's log calls don't panic on nil Logger.
	log.Logger = &stubLogger{}
}

// TestConnectNegativePoolLimit verifies that Connect returns an error
// immediately when poolLimit < 0, without attempting any MongoDB operations.
func TestConnectNegativePoolLimit(t *testing.T) {
	t.Parallel()

	err := Connect("localhost", "testdb", "user", "pass", -1, 27017, 10*time.Second)
	if err == nil {
		t.Fatal("expected error for negative poolLimit, got nil")
	}
	if err.Error() != "pool limit cannot be negative" {
		t.Fatalf("unexpected error message: %q", err.Error())
	}
}

// TestConnectZeroPoolLimit verifies that Connect does NOT return a validation
// error when poolLimit is zero (the validation guard only rejects negative values).
func TestConnectZeroPoolLimit(t *testing.T) {
	t.Parallel()

	err := Connect("localhost", "testdb", "user", "pass", 0, 27017, 10*time.Second)
	if err != nil && err.Error() == "pool limit cannot be negative" {
		t.Fatalf("unexpected validation error for zero poolLimit: %v", err)
	}
	// Connection failure (e.g., no MongoDB running) is expected and irrelevant
	// to the validation behavior under test.
}

// TestConnectPositivePoolLimit verifies that Connect does NOT return a validation
// error when poolLimit is positive.
func TestConnectPositivePoolLimit(t *testing.T) {
	t.Parallel()

	err := Connect("localhost", "testdb", "user", "pass", 100, 27017, 10*time.Second)
	if err != nil && err.Error() == "pool limit cannot be negative" {
		t.Fatalf("unexpected validation error for positive poolLimit: %v", err)
	}
	// Connection failure (e.g., no MongoDB running) is expected and irrelevant
	// to the validation behavior under test.
}
