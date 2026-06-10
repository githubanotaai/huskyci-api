package util

import "testing"

func TestCheckMaliciousChangedFiles_Empty(t *testing.T) {
	if err := CheckMaliciousChangedFiles(""); err != nil {
		t.Errorf("expected nil for empty string, got: %v", err)
	}
}

func TestCheckMaliciousChangedFiles_Valid(t *testing.T) {
	valid := "src/main.go\nsrc/utils.go\nREADME.md\npath/to/file_test.go"
	if err := CheckMaliciousChangedFiles(valid); err != nil {
		t.Errorf("expected nil for valid paths, got: %v", err)
	}
}

func TestCheckMaliciousChangedFiles_ShellInjection(t *testing.T) {
	malicious := []string{
		"$(whoami)",
		"`id`",
		"file; rm -rf /",
		"file | cat /etc/passwd",
		"file&",
	}

	for _, m := range malicious {
		err := CheckMaliciousChangedFiles(m)
		if err == nil {
			t.Errorf("expected error for malicious input %q, got nil", m)
		}
	}
}
