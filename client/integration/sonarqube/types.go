// Copyright 2019 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sonarqube

// HuskyCISonarOutput is the struct that holds the Sonar output
type HuskyCISonarOutput struct {
	Issues []SonarIssue `json:"issues"`
}

// SonarIssue represents a single issue in the SonarQube Generic Issue Import Format
type SonarIssue struct {
	EngineID           string          `json:"engineId"`
	RuleID             string          `json:"ruleId"`
	Severity           string          `json:"severity"`
	Type               string          `json:"type"`
	PrimaryLocation    SonarLocation   `json:"primaryLocation"`
	SecondaryLocations []SonarLocation `json:"secondaryLocations,omitempty"`
	EffortMinutes      int             `json:"effortMinutes,omitempty"`
}

// SonarLocation is the struct that holds a vulnerability location within code
type SonarLocation struct {
	Message   string         `json:"message"`
	FilePath  string         `json:"filePath"`
	TextRange SonarTextRange `json:"textRange"`
}

// SonarTextRange is the struct that holds addtional location fields
type SonarTextRange struct {
	StartLine   int `json:"startLine"`
	EndLine     int `json:"endLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}
