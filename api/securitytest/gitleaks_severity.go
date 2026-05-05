// Copyright 2019 Globo.com authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securitytest

// Buckets for HuskyCI severity, aligned with gitleaks/gitleaks default rules (v8) and
// historical v7 rule *names* for backwards compatibility.
var gitleaksHighRules = map[string]struct{}{
	"PKCS8": {},
	"RSA":   {},
	"SSH":   {},
	"PGP":   {},
	"EC":    {},

	// gitleaks v8 rule IDs (key material)
	"private-key": {},
	"pkcs12-file": {},
}

// Medium: former v7 human-readable names and common gitleaks v8 RuleIDs.
var gitleaksMediumRules = map[string]struct{}{
	"AWS Secret Key": {},
	"aws-access-key":  {},
	"aws-secret-key":  {},
	"aws-session-token":  {},
	"aws-access-token":  {},

	"Facebook access token":  {},
	"Facebook Secret Key":  {},
	"facebook-access-token":  {},
	"facebook-page-access-token":  {},
	"facebook-secret":  {},

	"Google OAuth access token": {},
	"Google Cloud Platform API key": {},
	"gcp-api-key":  {},

	"Twitter API Key": {},
	"Twitter Secret Key":  {},
	"twitter-access-token":  {},
	"twitter-api-key":  {},
	"twitter-api-secret":  {},
	"twitter-access-secret":  {},
	"twitter-bearer-token":  {},

	"LinkedIn Secret Key":    {},
	"LinkedIn Client ID":  {},
	"linkedin-client-id":  {},
	"linkedin-client-secret":  {},

	"Heroku API key":  {},
	"heroku-api-key":  {},
	"heroku-api-key-v2":  {},

	"MailChimp API key":  {},
	"mailchimp-api-key":  {},

	"mailgun-pub-key":  {},
	"mailgun-private-api-token":  {},
	"mailgun-signing-key":  {},

	"PayPal Braintree access token":  {},

	"Picatic API key":  {},

	"Stripe API key":  {},
	"stripe-access-token":  {},

	"twilio-api-key":  {},
}

// gitleaksBucketSeverity returns HuskyCI severity: HIGH, MEDIUM, or LOW.
func gitleaksBucketSeverity(ruleID string) string {
	if ruleID == "" {
		return "LOW"
	}
	if _, ok := gitleaksHighRules[ruleID]; ok {
		return "HIGH"
	}
	if _, ok := gitleaksMediumRules[ruleID]; ok {
		return "MEDIUM"
	}
	return "LOW"
}
