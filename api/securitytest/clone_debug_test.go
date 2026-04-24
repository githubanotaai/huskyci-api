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

func TestSSHKeyEnvDiagnostics_NoSecrets(t *testing.T) {
	t.Setenv("HUSKYCI_API_GIT_PRIVATE_SSH_KEY", "-----BEGIN TEST-----\nLINE\n-----END TEST-----")
	t.Setenv("HUSKYCI_API_GIT_SSH_URL", "")
	t.Setenv("HUSKYCI_API_GIT_URL_TO_SUBSTITUTE", "")
	d := sshKeyEnvDiagnostics()
	if d["beginsBEGIN"] != true {
		t.Fatalf("beginsBEGIN: %v", d["beginsBEGIN"])
	}
	if d["newlineCountRaw"].(int) < 1 {
		t.Fatalf("newlineCountRaw: %v", d["newlineCountRaw"])
	}
}

func TestSSHKeyEnvDiagnostics_AWSOneLinerLiteralN(t *testing.T) {
	t.Setenv("HUSKYCI_API_GIT_PRIVATE_SSH_KEY", "-----BEGIN X-----\\nABC\\n-----END X-----")
	t.Setenv("HUSKYCI_API_GIT_SSH_URL", "")
	t.Setenv("HUSKYCI_API_GIT_URL_TO_SUBSTITUTE", "")
	d := sshKeyEnvDiagnostics()
	if d["newlineCountRaw"].(int) != 0 {
		t.Fatalf("raw PEM one-liner should have zero real LF: got %v", d["newlineCountRaw"])
	}
	if d["newlineCountAfterNorm"].(int) < 2 {
		t.Fatalf("after API normalization expect multiple LFs: got %v", d["newlineCountAfterNorm"])
	}
	if d["literalBackslashNPair"] != true {
		t.Fatalf("expected literal \\\\n in secret: %v", d["literalBackslashNPair"])
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
