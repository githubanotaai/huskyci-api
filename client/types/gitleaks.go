// Copyright 2019 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package types

// GitleaksOutput is the struct that holds all data from Gitleaks output.
type GitleaksOutput []GitLeaksIssue

// GitLeaksIssue mirrors api/securitytest for API JSON; gitleaks v8 + v7 legacy fields.
type GitLeaksIssue struct {
	RuleID        string   `json:"RuleID"`
	Description   string   `json:"Description"`
	StartLine     int      `json:"StartLine"`
	EndLine       int      `json:"EndLine"`
	StartColumn   int      `json:"StartColumn"`
	EndColumn     int      `json:"EndColumn"`
	Match         string   `json:"Match"`
	Secret        string   `json:"Secret"`
	File          string   `json:"File"`
	SymlinkFile   string   `json:"SymlinkFile"`
	Commit        string   `json:"Commit"`
	Entropy       float64  `json:"Entropy"`
	Author        string   `json:"Author"`
	Email         string   `json:"Email"`
	Date          string   `json:"Date"`
	Message       string   `json:"Message"`
	Tags          []string `json:"Tags"`
	Fingerprint   string   `json:"Fingerprint"`
	LineContentV8 string   `json:"Line"`
	Offender      string   `json:"offender"`
	Info          string   `json:"info"`
	CommitMessage string   `json:"commitMsg"`
	Repository    string   `json:"repo"`
	RuleV7        string   `json:"rule"`
	SeverityV7    string   `json:"severity"`
	LineV7        string   `json:"line"`
	TagsV7        string   `json:"tags"`
}
