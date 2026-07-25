package policy

import (
	"reflect"
	"testing"
)

func TestMapEventToIAMActionsUsesAWSServiceAuthorizationReference(t *testing.T) {
	mapper := NewIAMActionMapper()
	tests := []struct {
		name        string
		eventSource string
		eventName   string
		want        []string
	}{
		{
			name:        "operation name differs from action",
			eventSource: "lambda.amazonaws.com",
			eventName:   "Invoke",
			want:        []string{"lambda:InvokeFunction"},
		},
		{
			name:        "operation authorizes multiple actions",
			eventSource: "cloudformation.amazonaws.com",
			eventName:   "CreateStack",
			want: []string{
				"cloudformation:CreateStack",
				"cloudformation:TagResource",
				"iam:PassRole",
			},
		},
		{
			name:        "sdk name differs from action prefix",
			eventSource: "accessanalyzer.amazonaws.com",
			eventName:   "ApplyArchiveRule",
			want:        []string{"access-analyzer:ApplyArchiveRule"},
		},
		{
			name:        "cloudtrail source differs from sdk name",
			eventSource: "monitoring.amazonaws.com",
			eventName:   "GetMetricData",
			want:        []string{"cloudwatch:GetMetricData"},
		},
		{
			name:        "cloudtrail source is the action prefix",
			eventSource: "logs.amazonaws.com",
			eventName:   "PutLogEvents",
			want:        []string{"logs:PutLogEvents"},
		},
		{
			name:        "dated event name",
			eventSource: "sqs.amazonaws.com",
			eventName:   "GetQueueUrl20121105",
			want:        []string{"sqs:GetQueueUrl"},
		},
		{
			name:        "unknown operation fallback",
			eventSource: "example.amazonaws.com",
			eventName:   "DoThing",
			want:        []string{"example:DoThing"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := mapper.MapEventToIAMActions(test.eventSource, test.eventName)
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("MapEventToIAMActions(%q, %q) = %#v, want %#v", test.eventSource, test.eventName, got, test.want)
			}
		})
	}
}

func TestParseServiceAuthorizationMappingsRejectsInvalidData(t *testing.T) {
	if _, err := parseServiceAuthorizationMappings([]byte("missing-actions")); err == nil {
		t.Fatal("parseServiceAuthorizationMappings() error = nil, want malformed line error")
	}
}
