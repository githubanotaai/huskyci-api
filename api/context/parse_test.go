package context

import (
	"testing"
)

func TestParseNodeSelector(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected map[string]string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: map[string]string{},
		},
		{
			name:     "single pair",
			input:    "karpenter.sh/nodepool=actions-runner",
			expected: map[string]string{"karpenter.sh/nodepool": "actions-runner"},
		},
		{
			name:  "multiple pairs",
			input: "karpenter.sh/nodepool=actions-runner,env=prod",
			expected: map[string]string{
				"karpenter.sh/nodepool": "actions-runner",
				"env":                   "prod",
			},
		},
		{
			name:     "whitespace around pairs",
			input:    " foo=bar , baz=qux ",
			expected: map[string]string{"foo": "bar", "baz": "qux"},
		},
		{
			name:     "malformed entry skipped",
			input:    "good=value,noequals,also=fine",
			expected: map[string]string{"good": "value", "also": "fine"},
		},
		{
			name:     "value containing equals",
			input:    "key=val=ue",
			expected: map[string]string{"key": "val=ue"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseNodeSelector(tt.input)
			if len(got) != len(tt.expected) {
				t.Fatalf("got %d entries, want %d: %v", len(got), len(tt.expected), got)
			}
			for k, v := range tt.expected {
				if got[k] != v {
					t.Errorf("key %q: got %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestParseTolerations(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []TolerationConfig
	}{
		{
			name:     "empty string",
			input:    "",
			expected: nil,
		},
		{
			name:  "single toleration",
			input: "actions-runner=true:NoSchedule",
			expected: []TolerationConfig{
				{Key: "actions-runner", Value: "true", Effect: "NoSchedule"},
			},
		},
		{
			name:  "multiple tolerations",
			input: "actions-runner=true:NoSchedule,gpu=nvidia:NoExecute",
			expected: []TolerationConfig{
				{Key: "actions-runner", Value: "true", Effect: "NoSchedule"},
				{Key: "gpu", Value: "nvidia", Effect: "NoExecute"},
			},
		},
		{
			name:  "whitespace tolerance",
			input: " actions-runner=true:NoSchedule , gpu=nvidia:NoExecute ",
			expected: []TolerationConfig{
				{Key: "actions-runner", Value: "true", Effect: "NoSchedule"},
				{Key: "gpu", Value: "nvidia", Effect: "NoExecute"},
			},
		},
		{
			name:     "missing effect skipped",
			input:    "actions-runner=true",
			expected: nil,
		},
		{
			name:     "missing value skipped",
			input:    "actions-runner:NoSchedule",
			expected: nil,
		},
		{
			name:  "key with slash",
			input: "karpenter.sh/do-not-disrupt=true:NoSchedule",
			expected: []TolerationConfig{
				{Key: "karpenter.sh/do-not-disrupt", Value: "true", Effect: "NoSchedule"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseTolerations(tt.input)
			if len(got) != len(tt.expected) {
				t.Fatalf("got %d entries, want %d: %v", len(got), len(tt.expected), got)
			}
			for i := range tt.expected {
				if got[i] != tt.expected[i] {
					t.Errorf("index %d: got %+v, want %+v", i, got[i], tt.expected[i])
				}
			}
		})
	}
}
