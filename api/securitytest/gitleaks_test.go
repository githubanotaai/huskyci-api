// Copyright 2019 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securitytest

import (
	_ "embed"
	"encoding/json"
	"testing"
)

//go:embed testdata/gitleaks_v8_sample.json
var gitleaksV8SampleJSON string

func TestGitleaksV8JSONUnmarshal(t *testing.T) {
	var out GitleaksOutput
	if err := json.Unmarshal([]byte(gitleaksV8SampleJSON), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out))
	}
	issue := out[0]
	if issue.RuleID != "github-pat" {
		t.Errorf("RuleID: got %q", issue.RuleID)
	}
	if issue.File != "code/secret.txt" {
		t.Errorf("File: got %q", issue.File)
	}
	if issue.StartLine != 1 {
		t.Errorf("StartLine: got %d", issue.StartLine)
	}
}

func TestGitleaksV7JSONUnmarshal(t *testing.T) {
	const v7 = `[{"line":"// x","commit":"a","offender":"y","rule":"Password in URL","info":"i","commitMsg":"m","author":"u","email":"e","file":"src/a.go","repo":".","date":"d","tags":"t","severity":""}]`
	var out GitleaksOutput
	if err := json.Unmarshal([]byte(v7), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out) != 1 || out[0].effectiveRule() != "Password in URL" {
		t.Fatalf("v7 rule: %#v", out[0])
	}
}
