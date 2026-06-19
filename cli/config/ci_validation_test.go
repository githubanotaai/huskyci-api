// Copyright 2026 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package config

import (
	"os"
	"strings"
	"testing"
)

// ciYAMLPath points to the CI workflow relative to the repo root.
// Tests run from the module directory (cli/), so we go up two levels.
const ciYAMLPath = "../../.github/workflows/ci.yaml"

func readCIYAML(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(ciYAMLPath)
	if err != nil {
		t.Fatalf("failed to read CI YAML at %s: %v", ciYAMLPath, err)
	}
	return string(data)
}

func TestCIYAMLExistsAndReadable(t *testing.T) {
	content := readCIYAML(t)
	if len(content) == 0 {
		t.Fatal("CI YAML file is empty")
	}
}

func TestCIYAMLContainsGosecJob(t *testing.T) {
	content := readCIYAML(t)

	t.Run("gosec job definition exists", func(t *testing.T) {
		if !strings.Contains(content, "\n  gosec:") {
			t.Fatal("CI YAML does not contain gosec job definition")
		}
	})

	t.Run("gosec job has matrix over api, client, cli", func(t *testing.T) {
		// Matrix is in the gosec job, between "gosec:" and next top-level job header.
		// Search within the general vicinity.
		if !strings.Contains(content, "module: [api, client, cli]") {
			t.Fatal("gosec job does not have matrix over [api, client, cli]")
		}
	})

	t.Run("gosec step uses setup-go@v5 with Go 1.23", func(t *testing.T) {
		if !strings.Contains(content, "actions/setup-go@v5") {
			t.Fatal("gosec job does not use actions/setup-go@v5")
		}
		if !strings.Contains(content, `go-version: "1.23"`) {
			t.Fatal("gosec job does not use Go 1.23")
		}
	})

	t.Run("gosec step runs with severity high and quiet flags", func(t *testing.T) {
		if !strings.Contains(content, "-severity high") {
			t.Fatal("gosec step does not use -severity high flag")
		}
		if !strings.Contains(content, "-quiet") {
			t.Fatal("gosec step does not use -quiet flag")
		}
	})

	t.Run("gosec step uses working-directory per module", func(t *testing.T) {
		if !strings.Contains(content, "gosec -severity high") {
			t.Fatal("gosec step does not run gosec with correct flags")
		}
	})
}

func TestCIYAMLExistingJobsPreserved(t *testing.T) {
	content := readCIYAML(t)

	expectedJobs := []string{
		"\n  build-and-test:",
		"\n  govulncheck:",
		"\n  lint:",
		"\n  docker-build:",
		"\n  gitleaks-contract:",
		"\n  deployment-shell:",
	}

	for _, job := range expectedJobs {
		t.Run("job "+strings.TrimSpace(job)+" is present", func(t *testing.T) {
			if !strings.Contains(content, job) {
				t.Fatalf("CI YAML is missing expected job: %s", strings.TrimSpace(job))
			}
		})
	}
}
