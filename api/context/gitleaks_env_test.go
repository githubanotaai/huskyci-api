// Copyright 2026 Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package context

import (
	"errors"
	"testing"
	"time"
)

// gitleaksMapCaller is a test double with independent config keys and env vars.
type gitleaksMapCaller struct {
	config map[string]string
	env    map[string]string
}

func (g *gitleaksMapCaller) SetConfigFile(configName, configPath string) error { return nil }
func (g *gitleaksMapCaller) GetStringFromConfigFile(value string) string {
	if g.config == nil {
		return ""
	}
	return g.config[value]
}
func (g *gitleaksMapCaller) GetBoolFromConfigFile(value string) bool   { return false }
func (g *gitleaksMapCaller) GetIntFromConfigFile(value string) int     { return 0 }
func (g *gitleaksMapCaller) GetEnvironmentVariable(envName string) string {
	if g.env == nil {
		return ""
	}
	return g.env[envName]
}
func (g *gitleaksMapCaller) ConvertStrToInt(str string) (int, error) { return 0, errors.New("not used") }
func (g *gitleaksMapCaller) GetTimeDurationInSeconds(duration int) time.Duration {
	return time.Duration(duration) * time.Second
}

func TestGetSecurityTestConfig_gitleaksEnvOverride(t *testing.T) {
	base := map[string]string{
		"gitleaks.name":     "gitleaks",
		"gitleaks.image":    "huskyci/gitleaks",
		"gitleaks.imageTag": "8.30.1",
		"gitleaks.cmd":      "true",
		"gitleaks.type":     "Generic",
		"gitleaks.language": "",
		"gitleaks.default":  "true",
		"gitleaks.timeOutInSeconds": "360",
		"enry.name":     "enry",
		"enry.image":    "huskyci/enry",
		"enry.imageTag": "1.0.0",
		"enry.cmd":      "x",
		"enry.type":     "Generic",
		"enry.language": "",
		"enry.default":  "true",
		"enry.timeOutInSeconds": "60",
	}

	df := DefaultConfig{Caller: &gitleaksMapCaller{config: base, env: map[string]string{
		"HUSKYCI_GITLEAKS_IMAGE":     "123456789012.dkr.ecr.us-east-1.amazonaws.com/huskyci-gitleaks",
		"HUSKYCI_GITLEAKS_IMAGE_TAG": "custom",
	}}}

	gl := df.getSecurityTestConfig("gitleaks")
	if gl.Image != "123456789012.dkr.ecr.us-east-1.amazonaws.com/huskyci-gitleaks" {
		t.Errorf("gitleaks image: got %q", gl.Image)
	}
	if gl.ImageTag != "custom" {
		t.Errorf("gitleaks imageTag: got %q", gl.ImageTag)
	}

	en := df.getSecurityTestConfig("enry")
	if en.Image != "huskyci/enry" {
		t.Errorf("enry image should be unchanged: got %q", en.Image)
	}
}

func TestGetSecurityTestConfig_gitleaksNoEnvUsesYaml(t *testing.T) {
	base := map[string]string{
		"gitleaks.name":             "gitleaks",
		"gitleaks.image":            "huskyci/gitleaks",
		"gitleaks.imageTag":         "8.30.1",
		"gitleaks.cmd":              "true",
		"gitleaks.type":             "Generic",
		"gitleaks.language":         "",
		"gitleaks.default":          "true",
		"gitleaks.timeOutInSeconds": "360",
	}
	df := DefaultConfig{Caller: &gitleaksMapCaller{config: base, env: map[string]string{}}}

	gl := df.getSecurityTestConfig("gitleaks")
	if gl.Image != "huskyci/gitleaks" || gl.ImageTag != "8.30.1" {
		t.Errorf("gitleaks: got image=%q tag=%q", gl.Image, gl.ImageTag)
	}
}

func TestGetSecurityTestConfig_gitleaksPartialOverride(t *testing.T) {
	base := map[string]string{
		"gitleaks.name":             "gitleaks",
		"gitleaks.image":            "huskyci/gitleaks",
		"gitleaks.imageTag":         "8.30.1",
		"gitleaks.cmd":              "true",
		"gitleaks.type":             "Generic",
		"gitleaks.language":         "",
		"gitleaks.default":          "true",
		"gitleaks.timeOutInSeconds": "360",
	}
	df := DefaultConfig{Caller: &gitleaksMapCaller{config: base, env: map[string]string{
		"HUSKYCI_GITLEAKS_IMAGE_TAG": "9.0.0",
	}}}

	gl := df.getSecurityTestConfig("gitleaks")
	if gl.Image != "huskyci/gitleaks" {
		t.Errorf("image should stay from yaml: %q", gl.Image)
	}
	if gl.ImageTag != "9.0.0" {
		t.Errorf("imageTag: got %q", gl.ImageTag)
	}
}
