package kubernetes

import (
	"testing"

	apiContext "github.com/githubanotaai/huskyci-api/api/context"
	core "k8s.io/api/core/v1"
)

func TestBuildTolerations(t *testing.T) {
	tests := []struct {
		name     string
		input    []apiContext.TolerationConfig
		expected []core.Toleration
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: nil,
		},
		{
			name:     "empty slice",
			input:    []apiContext.TolerationConfig{},
			expected: nil,
		},
		{
			name: "single toleration",
			input: []apiContext.TolerationConfig{
				{Key: "actions-runner", Value: "true", Effect: "NoSchedule"},
			},
			expected: []core.Toleration{
				{
					Key:      "actions-runner",
					Operator: core.TolerationOpEqual,
					Value:    "true",
					Effect:   core.TaintEffectNoSchedule,
				},
			},
		},
		{
			name: "multiple tolerations",
			input: []apiContext.TolerationConfig{
				{Key: "actions-runner", Value: "true", Effect: "NoSchedule"},
				{Key: "gpu", Value: "nvidia", Effect: "NoExecute"},
			},
			expected: []core.Toleration{
				{
					Key:      "actions-runner",
					Operator: core.TolerationOpEqual,
					Value:    "true",
					Effect:   core.TaintEffectNoSchedule,
				},
				{
					Key:      "gpu",
					Operator: core.TolerationOpEqual,
					Value:    "nvidia",
					Effect:   core.TaintEffectNoExecute,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildTolerations(tt.input)
			if len(got) != len(tt.expected) {
				t.Fatalf("got %d tolerations, want %d", len(got), len(tt.expected))
			}
			for i := range tt.expected {
				if got[i].Key != tt.expected[i].Key {
					t.Errorf("[%d] Key: got %q, want %q", i, got[i].Key, tt.expected[i].Key)
				}
				if got[i].Operator != tt.expected[i].Operator {
					t.Errorf("[%d] Operator: got %q, want %q", i, got[i].Operator, tt.expected[i].Operator)
				}
				if got[i].Value != tt.expected[i].Value {
					t.Errorf("[%d] Value: got %q, want %q", i, got[i].Value, tt.expected[i].Value)
				}
				if got[i].Effect != tt.expected[i].Effect {
					t.Errorf("[%d] Effect: got %q, want %q", i, got[i].Effect, tt.expected[i].Effect)
				}
			}
		})
	}
}
