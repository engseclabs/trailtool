package main

import (
	"testing"
)

func TestExtractS3Bucket(t *testing.T) {
	tests := []struct {
		name   string
		params interface{}
		want   string
	}{
		{
			name: "standard bucket name",
			params: map[string]interface{}{
				"bucketName": "my-bucket",
			},
			want: "my-bucket",
		},
		{
			name: "bucket name with dots",
			params: map[string]interface{}{
				"bucketName": "my.bucket.name",
			},
			want: "my.bucket.name",
		},
		{
			name:   "nil params",
			params: nil,
			want:   "",
		},
		{
			name:   "empty map",
			params: map[string]interface{}{},
			want:   "",
		},
		{
			name: "wrong type",
			params: map[string]interface{}{
				"bucketName": 123,
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractS3Bucket(tt.params)
			if got != tt.want {
				t.Errorf("extractS3Bucket() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractLambdaFunction(t *testing.T) {
	tests := []struct {
		name   string
		params interface{}
		want   string
	}{
		{
			name: "simple function name",
			params: map[string]interface{}{
				"functionName": "my-function",
			},
			want: "my-function",
		},
		{
			name: "function ARN",
			params: map[string]interface{}{
				"functionName": "arn:aws:lambda:us-east-1:123456789012:function:my-function",
			},
			want: "my-function",
		},
		{
			name:   "nil params",
			params: nil,
			want:   "",
		},
		{
			name:   "empty map",
			params: map[string]interface{}{},
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractLambdaFunction(tt.params)
			if got != tt.want {
				t.Errorf("extractLambdaFunction() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractDynamoTable(t *testing.T) {
	tests := []struct {
		name   string
		params interface{}
		want   string
	}{
		{
			name: "simple table name",
			params: map[string]interface{}{
				"tableName": "my-table",
			},
			want: "my-table",
		},
		{
			name:   "nil params",
			params: nil,
			want:   "",
		},
		{
			name:   "empty map",
			params: map[string]interface{}{},
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractDynamoTable(tt.params)
			if got != tt.want {
				t.Errorf("extractDynamoTable() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractEC2Instance(t *testing.T) {
	tests := []struct {
		name   string
		params interface{}
		want   string
	}{
		{
			name: "simple instance ID",
			params: map[string]interface{}{
				"instanceId": "i-1234567890abcdef0",
			},
			want: "i-1234567890abcdef0",
		},
		{
			name: "instancesSet format",
			params: map[string]interface{}{
				"instancesSet": map[string]interface{}{
					"items": []interface{}{
						map[string]interface{}{
							"instanceId": "i-abcdef1234567890",
						},
					},
				},
			},
			want: "i-abcdef1234567890",
		},
		{
			name:   "nil params",
			params: nil,
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractEC2Instance(tt.params)
			if got != tt.want {
				t.Errorf("extractEC2Instance() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractIAMResource(t *testing.T) {
	tests := []struct {
		name      string
		params    interface{}
		eventName string
		want      string
	}{
		{
			name: "user resource",
			params: map[string]interface{}{
				"userName": "admin",
			},
			eventName: "GetUser",
			want:      "iam:user:admin",
		},
		{
			name: "role resource",
			params: map[string]interface{}{
				"roleName": "MyRole",
			},
			eventName: "GetRole",
			want:      "iam:role:MyRole",
		},
		{
			name: "policy resource",
			params: map[string]interface{}{
				"policyName": "MyPolicy",
			},
			eventName: "CreatePolicy",
			want:      "iam:policy:MyPolicy",
		},
		{
			name:      "nil params",
			params:    nil,
			eventName: "GetUser",
			want:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractIAMResource(tt.params, tt.eventName)
			if got != tt.want {
				t.Errorf("extractIAMResource() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractCloudFormationStack(t *testing.T) {
	tests := []struct {
		name   string
		params interface{}
		want   string
	}{
		{
			name: "stack name",
			params: map[string]interface{}{
				"stackName": "my-stack",
			},
			want: "my-stack",
		},
		{
			name: "stack ARN",
			params: map[string]interface{}{
				"stackId": "arn:aws:cloudformation:us-east-1:123456789012:stack/my-stack/guid-1234",
			},
			want: "my-stack",
		},
		{
			name:   "nil params",
			params: nil,
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractCloudFormationStack(tt.params)
			if got != tt.want {
				t.Errorf("extractCloudFormationStack() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractSQSQueue(t *testing.T) {
	tests := []struct {
		name   string
		params interface{}
		want   string
	}{
		{
			name: "queue name",
			params: map[string]interface{}{
				"queueName": "my-queue",
			},
			want: "my-queue",
		},
		{
			name: "queue URL",
			params: map[string]interface{}{
				"queueUrl": "https://sqs.us-east-1.amazonaws.com/123456789012/my-queue",
			},
			want: "my-queue",
		},
		{
			name:   "nil params",
			params: nil,
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSQSQueue(tt.params)
			if got != tt.want {
				t.Errorf("extractSQSQueue() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractKMSKey(t *testing.T) {
	tests := []struct {
		name   string
		params interface{}
		want   string
	}{
		{
			name: "key ID",
			params: map[string]interface{}{
				"keyId": "1234abcd-12ab-34cd-56ef-1234567890ab",
			},
			want: "kms:key:1234abcd-12ab-34cd-56ef-1234567890ab",
		},
		{
			name: "alias name",
			params: map[string]interface{}{
				"aliasName": "alias/my-key",
			},
			want: "kms:alias:alias/my-key",
		},
		{
			name: "key ARN",
			params: map[string]interface{}{
				"keyId": "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab",
			},
			want: "kms:key:1234abcd-12ab-34cd-56ef-1234567890ab",
		},
		{
			name:   "nil params",
			params: nil,
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractKMSKey(tt.params)
			if got != tt.want {
				t.Errorf("extractKMSKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractLogGroup(t *testing.T) {
	tests := []struct {
		name   string
		params interface{}
		want   string
	}{
		{
			name: "log group name",
			params: map[string]interface{}{
				"logGroupName": "/aws/lambda/my-function",
			},
			want: "/aws/lambda/my-function",
		},
		{
			name:   "nil params",
			params: nil,
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractLogGroup(tt.params)
			if got != tt.want {
				t.Errorf("extractLogGroup() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetServiceDisplayName(t *testing.T) {
	tests := []struct {
		name        string
		eventSource string
		want        string
	}{
		{
			name:        "Lambda",
			eventSource: "lambda.amazonaws.com",
			want:        "AWS Lambda",
		},
		{
			name:        "S3",
			eventSource: "s3.amazonaws.com",
			want:        "Amazon S3",
		},
		{
			name:        "DynamoDB",
			eventSource: "dynamodb.amazonaws.com",
			want:        "Amazon DynamoDB",
		},
		{
			name:        "Unknown service",
			eventSource: "unknownservice.amazonaws.com",
			want:        "Unknownservice",
		},
		{
			name:        "Non-AWS service",
			eventSource: "custom.service",
			want:        "custom.service",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetServiceDisplayName(tt.eventSource)
			if got != tt.want {
				t.Errorf("GetServiceDisplayName(%q) = %q, want %q", tt.eventSource, got, tt.want)
			}
		})
	}
}

func TestGetServiceCategory(t *testing.T) {
	tests := []struct {
		name        string
		eventSource string
		want        string
	}{
		{
			name:        "Compute service",
			eventSource: "lambda.amazonaws.com",
			want:        "Compute",
		},
		{
			name:        "Storage service",
			eventSource: "s3.amazonaws.com",
			want:        "Storage",
		},
		{
			name:        "Database service",
			eventSource: "dynamodb.amazonaws.com",
			want:        "Database",
		},
		{
			name:        "Security service",
			eventSource: "iam.amazonaws.com",
			want:        "Security",
		},
		{
			name:        "Unknown service",
			eventSource: "unknownservice.amazonaws.com",
			want:        "Other",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetServiceCategory(tt.eventSource)
			if got != tt.want {
				t.Errorf("GetServiceCategory(%q) = %q, want %q", tt.eventSource, got, tt.want)
			}
		})
	}
}

func TestNormalizeResourceFromARN(t *testing.T) {
	tests := []struct {
		name string
		arn  string
		want string
	}{
		{
			name: "Lambda function ARN",
			arn:  "arn:aws:lambda:us-east-1:123456789012:function:my-function",
			want: "lambda:function:my-function",
		},
		{
			name: "S3 bucket ARN",
			arn:  "arn:aws:s3:::my-bucket",
			want: "s3:my-bucket",
		},
		{
			name: "DynamoDB table ARN",
			arn:  "arn:aws:dynamodb:us-east-1:123456789012:table/my-table",
			want: "dynamodb:table:my-table",
		},
		{
			name: "IAM role ARN",
			arn:  "arn:aws:iam::123456789012:role/my-role",
			want: "iam:role:my-role",
		},
		{
			name: "Short ARN",
			arn:  "arn:aws",
			want: "arn:aws",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeResourceFromARN(tt.arn)
			if got != tt.want {
				t.Errorf("normalizeResourceFromARN(%q) = %q, want %q", tt.arn, got, tt.want)
			}
		})
	}
}

func TestExtractResources(t *testing.T) {
	tests := []struct {
		name  string
		event CloudTrailRecord
		want  []string
	}{
		{
			name: "S3 GetObject",
			event: CloudTrailRecord{
				EventSource: "s3.amazonaws.com",
				EventName:   "GetObject",
				RequestParameters: map[string]interface{}{
					"bucketName": "my-bucket",
				},
			},
			want: []string{"s3:bucket:my-bucket"},
		},
		{
			name: "Lambda Invoke",
			event: CloudTrailRecord{
				EventSource: "lambda.amazonaws.com",
				EventName:   "Invoke",
				RequestParameters: map[string]interface{}{
					"functionName": "my-function",
				},
			},
			want: []string{"lambda:function:my-function"},
		},
		{
			name: "DynamoDB GetItem",
			event: CloudTrailRecord{
				EventSource: "dynamodb.amazonaws.com",
				EventName:   "GetItem",
				RequestParameters: map[string]interface{}{
					"tableName": "my-table",
				},
			},
			want: []string{"dynamodb:table:my-table"},
		},
		{
			name: "No extractable resource",
			event: CloudTrailRecord{
				EventSource:       "sts.amazonaws.com",
				EventName:         "AssumeRole",
				RequestParameters: map[string]interface{}{},
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractResources(tt.event)
			if len(got) != len(tt.want) {
				t.Errorf("ExtractResources() returned %d resources, want %d", len(got), len(tt.want))
				return
			}
			for i, r := range got {
				if r != tt.want[i] {
					t.Errorf("ExtractResources()[%d] = %q, want %q", i, r, tt.want[i])
				}
			}
		})
	}
}
