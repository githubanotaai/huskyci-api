// Copyright 2026 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package util_test

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/githubanotaai/huskyci-api/api/util"
)

// urlPattern is the same regex used by util.validRepoURL, kept here as a
// constant for the per-call benchmark variant so we can quantify the cost
// of compiling this pattern on every call.
const urlPattern = `((git|ssh|http(s)?)|((git@|gitlab@)[\w\.]+))(:(//)?)([\w\.@\:/\-~]+)(\.git)(/)?`

// corpusURLs returns a deterministic slice of valid and invalid URLs
// constructed by interleaving the fixed test inputs to reach the requested
// count. Valid URLs cycle through the valid set; invalid through the invalid
// set; they alternate so the corpus exercises both paths evenly.
func corpusURLs(n int) []string {
	valid := []string{
		"https://github.com/org/repo.git",
		"git@github.com:org/repo.git",
		"ssh://git@github.com/org/repo.git",
	}
	invalid := []string{
		"http://localhost/repo.git",
		"file:///etc/passwd",
		"https://user:token@github.com/org/repo.git",
	}

	urls := make([]string, n)
	for i := range urls {
		if i%2 == 0 {
			urls[i] = valid[i%len(valid)]
		} else {
			urls[i] = invalid[i%len(invalid)]
		}
	}
	return urls
}

// perCallCheckMaliciousRepoURL is a functional copy of
// util.CheckMaliciousRepoURL that compiles the URL regex on every call
// instead of using the package-level precompiled regex. It exists solely
// for benchmarking — it does NOT modify production code and is never
// called from outside this test file.
func perCallCheckMaliciousRepoURL(repositoryURL string) (string, error) {
	re := regexp.MustCompile(urlPattern)
	if !re.MatchString(repositoryURL) {
		return "", fmt.Errorf("invalid URL format: %s", repositoryURL)
	}
	sanitized := re.FindString(repositoryURL)
	if strings.HasPrefix(sanitized, "git@") || strings.HasPrefix(sanitized, "gitlab@") {
		return sanitized, nil
	}

	parsed, err := url.Parse(sanitized)
	if err != nil {
		return "", err
	}
	switch parsed.Scheme {
	case "git", "http", "https", "ssh":
	default:
		return "", fmt.Errorf("invalid repository URL scheme: %s", parsed.Scheme)
	}
	if parsed.User != nil {
		return "", fmt.Errorf("repository URL must not contain credentials")
	}
	if isUnsafeRepoHostBench(parsed.Hostname()) {
		return "", fmt.Errorf("repository URL points to a blocked host")
	}
	return sanitized, nil
}

// isUnsafeRepoHostBench is a copy of util.isUnsafeRepoHost for benchmark use
// since the original is unexported.
func isUnsafeRepoHostBench(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// BenchmarkCheckMaliciousRepoURLConcurrent measures throughput and
// allocations of CheckMaliciousRepoURL under parallel validation. It
// compares two variants:
//
//   - Compiled: calls util.CheckMaliciousRepoURL, which uses the
//     package-level precompiled regex (current production path).
//   - PerCall: calls perCallCheckMaliciousRepoURL, which recompiles the
//     identical pattern on every call (hypothetical worst-case used only
//     for comparison).
//
// Corpus sizes: 10, 100, 1000 URLs.
func BenchmarkCheckMaliciousRepoURLConcurrent(b *testing.B) {
	sizes := []int{10, 100, 1000}

	for _, n := range sizes {
		urls := corpusURLs(n)

		b.Run(fmt.Sprintf("Corpus=N=%d", n), func(b *testing.B) {
			b.Run("Variant=Compiled", func(b *testing.B) {
				b.ReportAllocs()
				b.RunParallel(func(pb *testing.PB) {
					i := 0
					for pb.Next() {
						_, _ = util.CheckMaliciousRepoURL(urls[i%len(urls)])
						i++
					}
				})
			})

			b.Run("Variant=PerCall", func(b *testing.B) {
				b.ReportAllocs()
				b.RunParallel(func(pb *testing.PB) {
					i := 0
					for pb.Next() {
						_, _ = perCallCheckMaliciousRepoURL(urls[i%len(urls)])
						i++
					}
				})
			})
		})
	}
}

// TestCheckMaliciousRepoURLCorpusBehavior verifies that the compiled
// (util.CheckMaliciousRepoURL) and per-call
// (perCallCheckMaliciousRepoURL) variants produce identical results for
// every URL in the full corpus — same accepted/rejected verdict and same
// sanitized output.
func TestCheckMaliciousRepoURLCorpusBehavior(t *testing.T) {
	t.Parallel()

	allURLs := []string{
		"https://github.com/org/repo.git",
		"git@github.com:org/repo.git",
		"ssh://git@github.com/org/repo.git",
		"http://localhost/repo.git",
		"file:///etc/passwd",
		"https://user:token@github.com/org/repo.git",
	}

	for _, raw := range allURLs {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()

			compiledSan, compiledErr := util.CheckMaliciousRepoURL(raw)
			perCallSan, perCallErr := perCallCheckMaliciousRepoURL(raw)

			// Both must agree on whether the URL was accepted.
			compiledPass := compiledErr == nil
			perCallPass := perCallErr == nil
			if compiledPass != perCallPass {
				t.Errorf("mismatched verdict for %q: compiled=%v perCall=%v",
					raw, compiledPass, perCallPass)
			}

			// When accepted, sanitized output must match.
			if compiledPass && compiledSan != perCallSan {
				t.Errorf("sanitized mismatch for %q:\ncompiled: %q\nperCall: %q",
					raw, compiledSan, perCallSan)
			}
		})
	}
}
