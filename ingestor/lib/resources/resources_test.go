package resources

import (
	"reflect"
	"testing"

	"github.com/engseclabs/trailtool/ingestor/lib/types"
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
			want: "s3:bucket:my-bucket",
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
			got := NormalizeResourceFromARN(tt.arn)
			if got != tt.want {
				t.Errorf("NormalizeResourceFromARN(%q) = %q, want %q", tt.arn, got, tt.want)
			}
		})
	}
}

func TestExtractResources(t *testing.T) {
	tests := []struct {
		name            string
		event           types.CloudTrailRecord
		callerAccountID string
		want            []types.ResourceIdentity
	}{
		{
			name: "S3 GetObject",
			event: types.CloudTrailRecord{
				EventSource: "s3.amazonaws.com",
				EventName:   "GetObject",
				RequestParameters: map[string]interface{}{
					"bucketName": "my-bucket",
				},
			},
			callerAccountID: "111111111111",
			want: []types.ResourceIdentity{{
				Identifier: "s3:bucket:my-bucket",
				AccountID:  "111111111111",
				Type:       "s3:bucket",
				Name:       "my-bucket",
			}},
		},
		{
			name: "Lambda Invoke",
			event: types.CloudTrailRecord{
				EventSource: "lambda.amazonaws.com",
				EventName:   "Invoke",
				RequestParameters: map[string]interface{}{
					"functionName": "my-function",
				},
			},
			callerAccountID: "111111111111",
			want: []types.ResourceIdentity{{
				Identifier: "lambda:function:my-function",
				AccountID:  "111111111111",
				Type:       "lambda:function",
				Name:       "my-function",
			}},
		},
		{
			name: "DynamoDB GetItem uses recipient account",
			event: types.CloudTrailRecord{
				EventSource:        "dynamodb.amazonaws.com",
				EventName:          "GetItem",
				RecipientAccountID: "222222222222",
				RequestParameters: map[string]interface{}{
					"tableName": "my-table",
				},
			},
			callerAccountID: "111111111111",
			want: []types.ResourceIdentity{{
				Identifier: "dynamodb:table:my-table",
				AccountID:  "222222222222",
				Type:       "dynamodb:table",
				Name:       "my-table",
			}},
		},
		{
			name: "No extractable resource",
			event: types.CloudTrailRecord{
				EventSource:       "sts.amazonaws.com",
				EventName:         "AssumeRole",
				RequestParameters: map[string]interface{}{},
			},
			callerAccountID: "111111111111",
			want:            []types.ResourceIdentity{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractResources(tt.event, tt.callerAccountID)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ExtractResources() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestExtractResourcesPrefersCloudTrailResourceOwner(t *testing.T) {
	event := types.CloudTrailRecord{
		EventSource:        "s3.amazonaws.com",
		EventName:          "GetObject",
		RecipientAccountID: "111111111111",
		RequestParameters: map[string]interface{}{
			"bucketName": "shared-bucket",
		},
		Resources: []types.CloudTrailResource{{
			ARN:       "arn:aws:s3:::shared-bucket",
			AccountID: "222222222222",
			Type:      "AWS::S3::Bucket",
		}},
	}

	got := ExtractResources(event, "111111111111")
	want := []types.ResourceIdentity{{
		Identifier: "s3:bucket:shared-bucket",
		AccountID:  "222222222222",
		ARN:        "arn:aws:s3:::shared-bucket",
		Type:       "s3:bucket",
		Name:       "shared-bucket",
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ExtractResources() = %#v, want %#v", got, want)
	}
}

func TestExtractResourcesUsesARNAccount(t *testing.T) {
	event := types.CloudTrailRecord{
		EventSource: "lambda.amazonaws.com",
		EventName:   "Invoke",
		Resources: []types.CloudTrailResource{{
			ARN:  "arn:aws:lambda:us-east-1:222222222222:function:shared-function",
			Type: "AWS::Lambda::Function",
		}},
	}

	got := ExtractResources(event, "111111111111")
	if len(got) != 1 ||
		got[0].Identifier != "lambda:function:shared-function" ||
		got[0].AccountID != "222222222222" {
		t.Fatalf("resource identity = %#v", got)
	}
}

func TestResourceKeyQualifiesIdentifierByAccount(t *testing.T) {
	identifier := "lambda:function:shared-function"
	first := ResourceKey("111111111111", identifier)
	second := ResourceKey("222222222222", identifier)
	if first == second {
		t.Fatalf("ResourceKey returned %q for two accounts", first)
	}
	if want := "111111111111#bGFtYmRhOmZ1bmN0aW9uOnNoYXJlZC1mdW5jdGlvbg"; first != want {
		t.Fatalf("ResourceKey() = %q, want %q", first, want)
	}
}
