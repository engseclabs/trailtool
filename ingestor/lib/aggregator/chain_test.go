package aggregator

import (
	"testing"

	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

func TestExtractIssuedAccessKeyID(t *testing.T) {
	tests := []struct {
		name  string
		event types.CloudTrailRecord
		want  string
	}{
		{
			name: "valid AssumeRole response",
			event: types.CloudTrailRecord{
				EventName: "AssumeRole",
				ResponseElements: map[string]interface{}{
					"credentials": map[string]interface{}{
						"accessKeyId":     "ASIAIOSFODNN7EXAMPLE",
						"secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY",
						"sessionToken":    "AQoXnyc4lcK4...",
					},
				},
			},
			want: "ASIAIOSFODNN7EXAMPLE",
		},
		{
			name: "missing credentials field",
			event: types.CloudTrailRecord{
				EventName: "AssumeRole",
				ResponseElements: map[string]interface{}{
					"assumedRoleUser": map[string]interface{}{
						"arn": "arn:aws:sts::123456789012:assumed-role/MyRole/session",
					},
				},
			},
			want: "",
		},
		{
			name: "nil ResponseElements",
			event: types.CloudTrailRecord{
				EventName:        "AssumeRole",
				ResponseElements: nil,
			},
			want: "",
		},
		{
			name: "non-AssumeRole event",
			event: types.CloudTrailRecord{
				EventName: "GetCallerIdentity",
				ResponseElements: map[string]interface{}{
					"credentials": map[string]interface{}{
						"accessKeyId": "ASIAIOSFODNN7EXAMPLE",
					},
				},
			},
			want: "",
		},
		{
			name: "AssumeRole with empty credentials",
			event: types.CloudTrailRecord{
				EventName: "AssumeRole",
				ResponseElements: map[string]interface{}{
					"credentials": map[string]interface{}{},
				},
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractIssuedAccessKeyID(tt.event)
			if got != tt.want {
				t.Errorf("ExtractIssuedAccessKeyID() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractAssumedRoleARN(t *testing.T) {
	tests := []struct {
		name  string
		event types.CloudTrailRecord
		want  string
	}{
		{
			name: "valid AssumeRole request",
			event: types.CloudTrailRecord{
				EventName: "AssumeRole",
				RequestParameters: map[string]interface{}{
					"roleArn":         "arn:aws:iam::123456789012:role/TargetRole",
					"roleSessionName": "my-session",
				},
			},
			want: "arn:aws:iam::123456789012:role/TargetRole",
		},
		{
			name: "missing roleArn",
			event: types.CloudTrailRecord{
				EventName: "AssumeRole",
				RequestParameters: map[string]interface{}{
					"roleSessionName": "my-session",
				},
			},
			want: "",
		},
		{
			name: "nil RequestParameters",
			event: types.CloudTrailRecord{
				EventName:         "AssumeRole",
				RequestParameters: nil,
			},
			want: "",
		},
		{
			name: "non-AssumeRole event",
			event: types.CloudTrailRecord{
				EventName: "GetObject",
				RequestParameters: map[string]interface{}{
					"roleArn": "arn:aws:iam::123456789012:role/TargetRole",
				},
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractAssumedRoleARN(tt.event)
			if got != tt.want {
				t.Errorf("ExtractAssumedRoleARN() = %q, want %q", got, tt.want)
			}
		})
	}
}
