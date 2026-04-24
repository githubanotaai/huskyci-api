package securitytest

import (
	"os"
	"regexp"
	"strings"

	"github.com/githubanotaai/huskyci-api/api/util"
)

// sshKeyEnvDiagnostics returns non-secret fields to compare staging vs prod secret injection (hypothesis H6/H7).
func sshKeyEnvDiagnostics() map[string]interface{} {
	raw := os.Getenv("HUSKYCI_API_GIT_PRIVATE_SSH_KEY")
	key := strings.TrimSpace(raw)
	norm := util.NormalizeGitSSHPrivateKeyFromEnv(raw)
	return map[string]interface{}{
		"keyPresent":              len(key) > 0,
		"trimmedByteLen":          len(key),
		"newlineCountRaw":         strings.Count(key, "\n"),
		"newlineCountAfterNorm":   strings.Count(norm, "\n"),
		"literalBackslashNPair":   strings.Contains(key, "\\n"),
		"hasCR":                   strings.Contains(key, "\r"),
		"hasSingleQuote":          strings.Contains(norm, "'"),
		"beginsBEGIN":             strings.HasPrefix(norm, "-----BEGIN"),
		"gitSshURLSet":            strings.TrimSpace(os.Getenv("HUSKYCI_API_GIT_SSH_URL")) != "",
		"gitURLSubstituteSet":     strings.TrimSpace(os.Getenv("HUSKYCI_API_GIT_URL_TO_SUBSTITUTE")) != "",
	}
}

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
