package main

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

// gzipString compresses a string using gzip and returns a bytes.Reader
func gzipString(s string) *bytes.Reader {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write([]byte(s))
	gz.Close()
	return bytes.NewReader(buf.Bytes())
}

func TestParseCloudTrailLog(t *testing.T) {
	tests := []struct {
		name        string
		input       *bytes.Reader
		wantRecords int
		wantErr     bool
		errContains string
	}{
		{
			name: "valid CloudTrail log with one record",
			input: gzipString(`{
				"Records": [{
					"eventVersion": "1.08",
					"eventTime": "2024-01-15T10:30:00Z",
					"eventName": "GetObject",
					"eventSource": "s3.amazonaws.com",
					"userIdentity": {
						"type": "AssumedRole",
						"principalId": "AROAIDPPEZS35WEXAMPLE:user@example.com",
						"arn": "arn:aws:sts::123456789012:assumed-role/MyRole/user@example.com"
					}
				}]
			}`),
			wantRecords: 1,
			wantErr:     false,
		},
		{
			name: "valid CloudTrail log with multiple records",
			input: gzipString(`{
				"Records": [
					{
						"eventVersion": "1.08",
						"eventTime": "2024-01-15T10:30:00Z",
						"eventName": "GetObject",
						"eventSource": "s3.amazonaws.com",
						"userIdentity": {"type": "AssumedRole", "principalId": "AROA:user@example.com", "arn": "arn:aws:sts::123456789012:assumed-role/MyRole/user"}
					},
					{
						"eventVersion": "1.08",
						"eventTime": "2024-01-15T10:31:00Z",
						"eventName": "PutObject",
						"eventSource": "s3.amazonaws.com",
						"userIdentity": {"type": "AssumedRole", "principalId": "AROA:user@example.com", "arn": "arn:aws:sts::123456789012:assumed-role/MyRole/user"}
					},
					{
						"eventVersion": "1.08",
						"eventTime": "2024-01-15T10:32:00Z",
						"eventName": "Invoke",
						"eventSource": "lambda.amazonaws.com",
						"userIdentity": {"type": "AssumedRole", "principalId": "AROA:user@example.com", "arn": "arn:aws:sts::123456789012:assumed-role/MyRole/user"}
					}
				]
			}`),
			wantRecords: 3,
			wantErr:     false,
		},
		{
			name:        "empty CloudTrail log",
			input:       gzipString(`{"Records": []}`),
			wantRecords: 0,
			wantErr:     false,
		},
		{
			name:        "invalid gzip data",
			input:       bytes.NewReader([]byte("not gzip data")),
			wantRecords: 0,
			wantErr:     true,
			errContains: "gzip",
		},
		{
			name:        "valid gzip but invalid JSON",
			input:       gzipString(`{invalid json}`),
			wantRecords: 0,
			wantErr:     true,
			errContains: "parse CloudTrail log",
		},
		{
			name:        "valid gzip but empty content",
			input:       gzipString(``),
			wantRecords: 0,
			wantErr:     true,
			errContains: "parse CloudTrail log",
		},
		{
			name: "CloudTrail log with requestParameters",
			input: gzipString(`{
				"Records": [{
					"eventVersion": "1.08",
					"eventTime": "2024-01-15T10:30:00Z",
					"eventName": "GetObject",
					"eventSource": "s3.amazonaws.com",
					"userIdentity": {
						"type": "AssumedRole",
						"principalId": "AROAIDPPEZS35WEXAMPLE:user@example.com",
						"arn": "arn:aws:sts::123456789012:assumed-role/MyRole/user@example.com"
					},
					"requestParameters": {
						"bucketName": "my-bucket",
						"key": "my-key"
					}
				}]
			}`),
			wantRecords: 1,
			wantErr:     false,
		},
		{
			name: "CloudTrail log with sessionContext",
			input: gzipString(`{
				"Records": [{
					"eventVersion": "1.08",
					"eventTime": "2024-01-15T10:30:00Z",
					"eventName": "GetObject",
					"eventSource": "s3.amazonaws.com",
					"userIdentity": {
						"type": "AssumedRole",
						"principalId": "AROAIDPPEZS35WEXAMPLE:user@example.com",
						"arn": "arn:aws:sts::123456789012:assumed-role/MyRole/user@example.com",
						"sessionContext": {
							"attributes": {
								"creationDate": "2024-01-15T09:00:00Z",
								"mfaAuthenticated": "true"
							},
							"sessionIssuer": {
								"type": "Role",
								"principalId": "AROAIDPPEZS35WEXAMPLE",
								"arn": "arn:aws:iam::123456789012:role/MyRole",
								"accountId": "123456789012",
								"userName": "MyRole"
							}
						}
					}
				}]
			}`),
			wantRecords: 1,
			wantErr:     false,
		},
		{
			name: "CloudTrail log with errorCode (AccessDenied)",
			input: gzipString(`{
				"Records": [{
					"eventVersion": "1.08",
					"eventTime": "2024-01-15T10:30:00Z",
					"eventName": "GetObject",
					"eventSource": "s3.amazonaws.com",
					"userIdentity": {
						"type": "AssumedRole",
						"principalId": "AROAIDPPEZS35WEXAMPLE:user@example.com",
						"arn": "arn:aws:sts::123456789012:assumed-role/MyRole/user@example.com"
					},
					"errorCode": "AccessDenied",
					"errorMessage": "Access Denied"
				}]
			}`),
			wantRecords: 1,
			wantErr:     false,
		},
		{
			name: "CloudTrail log with resources array",
			input: gzipString(`{
				"Records": [{
					"eventVersion": "1.08",
					"eventTime": "2024-01-15T10:30:00Z",
					"eventName": "Invoke",
					"eventSource": "lambda.amazonaws.com",
					"userIdentity": {
						"type": "AssumedRole",
						"principalId": "AROAIDPPEZS35WEXAMPLE:user@example.com",
						"arn": "arn:aws:sts::123456789012:assumed-role/MyRole/user@example.com"
					},
					"resources": [
						{
							"ARN": "arn:aws:lambda:us-east-1:123456789012:function:my-function",
							"accountId": "123456789012",
							"type": "AWS::Lambda::Function"
						}
					]
				}]
			}`),
			wantRecords: 1,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCloudTrailLog(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseCloudTrailLog() expected error, got nil")
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ParseCloudTrailLog() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("ParseCloudTrailLog() unexpected error = %v", err)
				return
			}

			if got == nil {
				t.Errorf("ParseCloudTrailLog() returned nil, expected non-nil")
				return
			}

			if len(got.Records) != tt.wantRecords {
				t.Errorf("ParseCloudTrailLog() got %d records, want %d", len(got.Records), tt.wantRecords)
			}
		})
	}
}

func TestParseCloudTrailLog_FieldParsing(t *testing.T) {
	input := gzipString(`{
		"Records": [{
			"eventVersion": "1.08",
			"eventTime": "2024-01-15T10:30:00Z",
			"eventName": "GetObject",
			"eventSource": "s3.amazonaws.com",
			"eventType": "AwsApiCall",
			"sourceIPAddress": "192.168.1.1",
			"userAgent": "aws-cli/2.0",
			"userIdentity": {
				"type": "AssumedRole",
				"principalId": "AROAIDPPEZS35WEXAMPLE:user@example.com",
				"arn": "arn:aws:sts::123456789012:assumed-role/MyRole/user@example.com",
				"accountId": "123456789012",
				"accessKeyId": "ASIAIDEXAMPLE"
			},
			"requestParameters": {
				"bucketName": "test-bucket"
			},
			"errorCode": "",
			"errorMessage": ""
		}]
	}`)

	got, err := ParseCloudTrailLog(input)
	if err != nil {
		t.Fatalf("ParseCloudTrailLog() unexpected error = %v", err)
	}

	if len(got.Records) != 1 {
		t.Fatalf("ParseCloudTrailLog() got %d records, want 1", len(got.Records))
	}

	record := got.Records[0]

	// Verify all fields are parsed correctly
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"eventVersion", record.EventVersion, "1.08"},
		{"eventTime", record.EventTime, "2024-01-15T10:30:00Z"},
		{"eventName", record.EventName, "GetObject"},
		{"eventSource", record.EventSource, "s3.amazonaws.com"},
		{"eventType", record.EventType, "AwsApiCall"},
		{"sourceIPAddress", record.SourceIPAddress, "192.168.1.1"},
		{"userAgent", record.UserAgent, "aws-cli/2.0"},
		{"userIdentity.type", record.UserIdentity.Type, "AssumedRole"},
		{"userIdentity.principalId", record.UserIdentity.PrincipalID, "AROAIDPPEZS35WEXAMPLE:user@example.com"},
		{"userIdentity.arn", record.UserIdentity.ARN, "arn:aws:sts::123456789012:assumed-role/MyRole/user@example.com"},
		{"userIdentity.accountId", record.UserIdentity.AccountID, "123456789012"},
		{"userIdentity.accessKeyId", record.UserIdentity.AccessKeyID, "ASIAIDEXAMPLE"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("field %s = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}

	// Verify requestParameters is parsed
	if record.RequestParameters == nil {
		t.Error("requestParameters should not be nil")
	} else {
		params, ok := record.RequestParameters.(map[string]interface{})
		if !ok {
			t.Error("requestParameters should be a map")
		} else if params["bucketName"] != "test-bucket" {
			t.Errorf("requestParameters.bucketName = %v, want %q", params["bucketName"], "test-bucket")
		}
	}
}
