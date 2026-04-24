package securitytest

import (
	"strings"
	"testing"
)

func TestExtractGitCloneFailureHint_PublicKey(t *testing.T) {
	raw := "something\nERROR_CLONING\nfatal: Could not read from remote repository.\n\nPlease make sure you have the correct access rights\n"
	got := extractGitCloneFailureHint(raw)
	if got == "" {
		t.Fatal("expected non-empty hint")
	}
	if !strings.Contains(got, "Could not read from remote repository") {
		t.Fatalf("unexpected hint: %q", got)
	}
}

func TestExtractGitCloneFailureHint_StripsPEM(t *testing.T) {
	raw := "ERROR_CLONING\n-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\nPermission denied (publickey)."
	got := extractGitCloneFailureHint(raw)
	if strings.Contains(got, "BEGIN RSA") {
		t.Fatalf("PEM should be redacted: %q", got)
	}
	if !strings.Contains(got, "Permission denied") {
		t.Fatalf("expected permission line: %q", got)
	}
}
