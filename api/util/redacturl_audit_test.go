// Copyright 2019 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package util_test

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRedactURLAudit is a static guardrail that scans api/routes/ and
// api/analysis/ for log statements (log.Info, log.Warning, log.Error) that
// reference a .URL field without wrapping it in RedactURL.  When it finds a
// violation it reports file:line so the offender can be fixed.
func TestRedactURLAudit(t *testing.T) {
	violations := scanForRedactURLViolations(t)
	if len(violations) > 0 {
		t.Errorf(
			"found %d log statement(s) with .URL but without RedactURL:\n%s",
			len(violations),
			strings.Join(violations, "\n"),
		)
	}
}

func scanForRedactURLViolations(t *testing.T) []string {
	t.Helper()

	dirs := []string{"../routes", "../analysis"}
	var violations []string

	for _, dir := range dirs {
		pattern := filepath.Join(dir, "*.go")
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("failed to glob %s: %v", pattern, err)
		}
		for _, path := range matches {
			v := checkFileForRedactURL(t, path)
			violations = append(violations, v...)
		}
	}

	return violations
}

func checkFileForRedactURL(t *testing.T, path string) []string {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("failed to open %s: %v", path, err)
	}
	defer f.Close()

	var violations []string
	scanner := bufio.NewScanner(f)
	lineNo := 0

	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		if lineHasLogWithDotURLWithoutRedact(line) {
			violations = append(violations, fmt.Sprintf("%s:%d", path, lineNo))
		}
	}

	if err := scanner.Err(); err != nil {
		t.Fatalf("error reading %s: %v", path, err)
	}

	return violations
}

// lineHasLogWithDotURLWithoutRedact returns true when a single source line
// contains a log.Info / log.Warning / log.Error call together with a .URL
// field access but does NOT contain a RedactURL wrapper on the same line.
//
// This is deliberately a line-by-line heuristic — it does NOT parse the Go
// AST.  False positives are possible (e.g. a comment containing ".URL" on the
// same line as a log call) but unlikely in practice, and the trade-off is
// worth the simplicity and zero-dependency nature of the guardrail.
func lineHasLogWithDotURLWithoutRedact(line string) bool {
	trimmed := strings.TrimSpace(line)

	// Quick bail-out: the line must contain a log call.
	hasLog := strings.Contains(trimmed, "log.Info(") ||
		strings.Contains(trimmed, "log.Warning(") ||
		strings.Contains(trimmed, "log.Error(")
	if !hasLog {
		return false
	}

	// Must reference a .URL field access.
	if !strings.Contains(trimmed, ".URL") {
		return false
	}

	// If RedactURL is present on the same line the log statement is
	// already protected.
	if strings.Contains(trimmed, "RedactURL") {
		return false
	}

	return true
}
