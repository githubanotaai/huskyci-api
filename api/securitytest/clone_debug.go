package securitytest

import (
	"regexp"
	"strings"
)

var pemBlockPattern = regexp.MustCompile(`-----BEGIN[^-]+-----[\s\S]*?-----END[^-]+-----`)

// extractGitCloneFailureHint returns text after ERROR_CLONING from container logs (sanitized, truncated).
func extractGitCloneFailureHint(cOutput string) string {
	idx := strings.Index(cOutput, "ERROR_CLONING")
	if idx < 0 {
		return ""
	}
	tail := strings.TrimSpace(cOutput[idx+len("ERROR_CLONING"):])
	tail = pemBlockPattern.ReplaceAllString(tail, "[redacted PEM]")
	tail = strings.TrimSpace(tail)
	if len(tail) > 800 {
		tail = tail[:800] + "...(truncated)"
	}
	return tail
}
