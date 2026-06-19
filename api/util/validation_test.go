// Copyright 2026 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package util_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo"

	"github.com/githubanotaai/huskyci-api/api/log"
	"github.com/githubanotaai/huskyci-api/api/util"
)

// log.Logger is a package-level variable that stays nil until InitLog runs;
// CheckMaliciousRepoBranch invokes log.Error on the invalid-input path and
// nil-derefs without it. The existing Ginkgo suite calls InitLog inside an
// It block, which is not guaranteed to run before these tests.
func init() {
	log.InitLog(true, "", "", "validation_test", "validation_test")
}

// Tier-3 input-validation safety net. Pins the contract of the three malicious
// input validators so SSRF/path-traversal hardening (gap #10) can land safely.
// Table rows that test desired-but-not-yet-implemented blocks are nested under
// t.Skip subtests so the parent test stays green on current code.

// TestCheckMaliciousRepoURL asserts the URL validator's contract for both
// (a) inputs that must remain accepted regardless of future hardening, and
// (b) SSRF/credential-leak vectors that are NOT yet blocked (gap #10).
func TestCheckMaliciousRepoURL(t *testing.T) {
	t.Parallel()

	validCases := []struct {
		name        string
		input       string
		wantBlocked bool
		reason      string
	}{
		{"https_github", "https://github.com/org/repo.git", false, "normal HTTPS clone URL"},
		{"ssh_github", "git@github.com:org/repo.git", false, "normal SSH clone URL"},
		{"https_gitlab", "https://gitlab.com/org/repo.git", false, "normal HTTPS GitLab URL"},
		{"https_bitbucket", "https://bitbucket.org/org/repo.git", false, "normal HTTPS Bitbucket URL"},
	}
	for _, tc := range validCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := util.CheckMaliciousRepoURL(tc.input)
			gotBlocked := err != nil
			if gotBlocked != tc.wantBlocked {
				t.Errorf("CheckMaliciousRepoURL(%q): wantBlocked=%v gotBlocked=%v err=%v (%s)",
					tc.input, tc.wantBlocked, gotBlocked, err, tc.reason)
			}
		})
	}

	t.Run("gap_10_ssrf_targets_not_yet_blocked", func(t *testing.T) {
		t.Skip("Gap #10 — remove this Skip after CheckMaliciousRepoURL blocks RFC1918, link-local, loopback, file://, and credentials-in-URL")

		ssrfCases := []struct {
			name        string
			input       string
			wantBlocked bool
			reason      string
		}{
			{"rfc1918_10x", "http://10.0.0.1/repo.git", true, "RFC1918 — SSRF"},
			{"rfc1918_192", "http://192.168.1.1/repo.git", true, "RFC1918 — SSRF"},
			{"rfc1918_172", "http://172.16.0.1/repo.git", true, "RFC1918 — SSRF"},
			{"link_local", "http://169.254.169.254/repo.git", true, "link-local — cloud metadata endpoint"},
			{"loopback_name", "http://localhost/repo.git", true, "loopback — SSRF"},
			{"loopback_ip", "http://127.0.0.1/repo.git", true, "loopback — SSRF"},
			{"file_scheme", "file:///etc/passwd", true, "file:// scheme — local file read"},
			{"creds_in_url", "https://user:ghp_abc@github.com/org/repo.git", true, "credentials in URL — PAT leakage to logs"},
		}
		for _, tc := range ssrfCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := util.CheckMaliciousRepoURL(tc.input)
				gotBlocked := err != nil
				if gotBlocked != tc.wantBlocked {
					t.Errorf("CheckMaliciousRepoURL(%q): wantBlocked=%v gotBlocked=%v err=%v (%s)",
						tc.input, tc.wantBlocked, gotBlocked, err, tc.reason)
				}
			})
		}
	})
}

// branchValidatorVerdict runs CheckMaliciousRepoBranch with a fresh
// echo.Context so the recorder's status code can act as the "blocked" signal.
// Returns true if the validator wrote a 4xx/5xx response (i.e. blocked).
func branchValidatorVerdict(t *testing.T, branch string) bool {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	_ = util.CheckMaliciousRepoBranch(branch, c)
	return rec.Code >= 400
}

// TestCheckMaliciousBranch asserts the branch validator blocks shell
// metacharacters and null bytes today; the path-traversal cases ride a
// skipped subtest because the regex currently allows "." and "/".
func TestCheckMaliciousBranch(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		input       string
		wantBlocked bool
		reason      string
	}{
		{"shell_semicolon", "main; rm -rf /", true, "shell injection via semicolon"},
		{"cmd_substitution", "$(whoami)", true, "command substitution $()"},
		{"backtick_sub", "`id`", true, "backtick command substitution"},
		{"null_byte", "main\x00suffix", true, "null byte injection"},
		{"simple", "main", false, "standard branch name"},
		{"slash", "feature/my-branch", false, "branch with single slash"},
		{"release", "release-1.0.0", false, "semver-style release branch"},
		{"numbers", "sprint-42", false, "branch with numbers"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := branchValidatorVerdict(t, tc.input)
			if got != tc.wantBlocked {
				t.Errorf("CheckMaliciousRepoBranch(%q): wantBlocked=%v got=%v (%s)",
					tc.input, tc.wantBlocked, got, tc.reason)
			}
		})
	}

	t.Run("gap_path_traversal_not_yet_blocked", func(t *testing.T) {
		t.Skip("Branch path-traversal gap — remove this Skip after CheckMaliciousRepoBranch (util.go:184) rejects '..' segments")

		traversal := []struct {
			name        string
			input       string
			wantBlocked bool
			reason      string
		}{
			{"path_traversal", "../../../etc/passwd", true, "path traversal"},
			{"double_dot", "branch/../../../secret", true, "path traversal via .."},
		}
		for _, tc := range traversal {
			t.Run(tc.name, func(t *testing.T) {
				got := branchValidatorVerdict(t, tc.input)
				if got != tc.wantBlocked {
					t.Errorf("CheckMaliciousRepoBranch(%q): wantBlocked=%v got=%v (%s)",
						tc.input, tc.wantBlocked, got, tc.reason)
				}
			})
		}
	})
}

// TestCheckMaliciousChangedFiles asserts the changed-files validator blocks
// shell metacharacters and null bytes today; path-traversal and absolute
// paths ride a skipped subtest because the current regex permits "." and "/".
func TestCheckMaliciousChangedFiles(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		input       string
		wantBlocked bool
		reason      string
	}{
		{"null_byte", "main.go\x00evil", true, "null byte in filename"},
		{"semicolon", "file.go; rm -rf /", true, "shell injection"},
		{"go_file", "main.go", false, "normal Go source file"},
		{"nested_go", "pkg/util/util.go", false, "nested Go source file"},
		{"python_file", "src/app.py", false, "normal Python file"},
		{"multiple_dots", "my.config.yaml", false, "filename with multiple dots"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := util.CheckMaliciousChangedFiles(tc.input)
			gotBlocked := err != nil
			if gotBlocked != tc.wantBlocked {
				t.Errorf("CheckMaliciousChangedFiles(%q): wantBlocked=%v gotBlocked=%v err=%v (%s)",
					tc.input, tc.wantBlocked, gotBlocked, err, tc.reason)
			}
		})
	}

	t.Run("gap_path_and_absolute_not_yet_blocked", func(t *testing.T) {
		t.Skip("Changed-files path/absolute gap — remove this Skip after CheckMaliciousChangedFiles (util.go:204) rejects '..' and leading '/'")

		extra := []struct {
			name        string
			input       string
			wantBlocked bool
			reason      string
		}{
			{"path_traversal", "../../../etc/passwd", true, "path traversal"},
			{"absolute_path", "/etc/passwd", true, "absolute path"},
		}
		for _, tc := range extra {
			t.Run(tc.name, func(t *testing.T) {
				err := util.CheckMaliciousChangedFiles(tc.input)
				gotBlocked := err != nil
				if gotBlocked != tc.wantBlocked {
					t.Errorf("CheckMaliciousChangedFiles(%q): wantBlocked=%v gotBlocked=%v err=%v (%s)",
						tc.input, tc.wantBlocked, gotBlocked, err, tc.reason)
				}
			})
		}
	})
}
