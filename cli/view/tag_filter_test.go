package view

import (
	"testing"
)

func TestParseTagFilters(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		want    map[string]string
		wantErr bool
	}{
		{
			name:  "single tag",
			input: []string{"AgentName=claude-code"},
			want:  map[string]string{"AgentName": "claude-code"},
		},
		{
			name:  "multiple tags",
			input: []string{"AgentName=claude-code", "Task=deploy-lambda"},
			want:  map[string]string{"AgentName": "claude-code", "Task": "deploy-lambda"},
		},
		{
			name:  "value contains equals sign",
			input: []string{"Key=a=b"},
			want:  map[string]string{"Key": "a=b"},
		},
		{
			name:    "missing equals",
			input:   []string{"NoEqualsSign"},
			wantErr: true,
		},
		{
			name:    "empty key",
			input:   []string{"=value"},
			wantErr: true,
		},
		{
			name:  "empty input",
			input: []string{},
			want:  map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTagFilters(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseTagFilters() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				for k, v := range tt.want {
					if got[k] != v {
						t.Errorf("ParseTagFilters()[%q] = %q, want %q", k, got[k], v)
					}
				}
				if len(got) != len(tt.want) {
					t.Errorf("ParseTagFilters() len = %d, want %d", len(got), len(tt.want))
				}
			}
		})
	}
}

func TestSessionMatchesTags(t *testing.T) {
	tests := []struct {
		name        string
		sessionTags map[string]string
		filters     map[string]string
		want        bool
	}{
		{
			name:        "all filters match",
			sessionTags: map[string]string{"AgentName": "claude-code", "Task": "deploy-lambda"},
			filters:     map[string]string{"AgentName": "claude-code"},
			want:        true,
		},
		{
			name:        "all filters match multi",
			sessionTags: map[string]string{"AgentName": "claude-code", "Task": "deploy-lambda"},
			filters:     map[string]string{"AgentName": "claude-code", "Task": "deploy-lambda"},
			want:        true,
		},
		{
			name:        "one filter mismatch",
			sessionTags: map[string]string{"AgentName": "claude-code", "Task": "deploy-lambda"},
			filters:     map[string]string{"AgentName": "claude-code", "Task": "review-pr"},
			want:        false,
		},
		{
			name:        "key absent in session",
			sessionTags: map[string]string{"AgentName": "claude-code"},
			filters:     map[string]string{"Task": "deploy-lambda"},
			want:        false,
		},
		{
			name:        "nil session tags, no filters",
			sessionTags: nil,
			filters:     map[string]string{},
			want:        true,
		},
		{
			name:        "nil session tags, with filter",
			sessionTags: nil,
			filters:     map[string]string{"AgentName": "claude-code"},
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SessionMatchesTags(tt.sessionTags, tt.filters)
			if got != tt.want {
				t.Errorf("SessionMatchesTags() = %v, want %v", got, tt.want)
			}
		})
	}
}
