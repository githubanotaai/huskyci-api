// Copyright 2019 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package types

// PnpmAuditOutput is the struct that stores all pnpm audit output.
type PnpmAuditOutput struct {
	Advisories map[string]PnpmAdvisory `json:"advisories"`
	Metadata   PnpmMetadata            `json:"metadata"`
}

// PnpmAdvisory is a single advisory from pnpm audit.
type PnpmAdvisory struct {
	Findings           []PnpmFinding `json:"findings"`
	ID                 int           `json:"id"`
	Title              string        `json:"title"`
	ModuleName         string        `json:"module_name"`
	VulnerableVersions string        `json:"vulnerable_versions"`
	Severity           string        `json:"severity"`
}

// PnpmFinding represents a specific finding of a vulnerable dependency.
type PnpmFinding struct {
	Version string `json:"version"`
}

// PnpmMetadata is the struct that holds vulnerabilities summary.
type PnpmMetadata struct {
	Vulnerabilities PnpmVulnerabilitiesSummary `json:"vulnerabilities"`
}

// PnpmVulnerabilitiesSummary holds the count of vulnerabilities by severity.
type PnpmVulnerabilitiesSummary struct {
	Info     int `json:"info"`
	Low      int `json:"low"`
	Moderate int `json:"moderate"`
	High     int `json:"high"`
	Critical int `json:"critical"`
}
