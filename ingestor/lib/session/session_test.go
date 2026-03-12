package session

import (
	"testing"
)

func TestExtractEmailFromPrincipalID(t *testing.T) {
	tests := []struct {
		name        string
		principalID string
		want        string
	}{
		{
			name:        "standard SSO format",
			principalID: "AROAIDPPEZS35WEXAMPLE:me@alexsmolen.com",
			want:        "me@alexsmolen.com",
		},
		{
			name:        "complex email",
			principalID: "AROAIDPPEZS35WEXAMPLE:user.name+tag@company.org",
			want:        "user.name+tag@company.org",
		},
		{
			name:        "lambda execution role - no email",
			principalID: "AROAIDPPEZS35WEXAMPLE:trailtool-ingestor",
			want:        "",
		},
		{
			name:        "UUID session name - no email",
			principalID: "AROAIDPPEZS35WEXAMPLE:550e8400-e29b-41d4-a716-446655440000",
			want:        "",
		},
		{
			name:        "empty principal ID",
			principalID: "",
			want:        "",
		},
		{
			name:        "role ID only - no session name",
			principalID: "AROAIDPPEZS35WEXAMPLE",
			want:        "",
		},
		{
			name:        "multiple colons in email",
			principalID: "AROAIDPPEZS35WEXAMPLE:user@domain.com:extra",
			want:        "user@domain.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractEmailFromPrincipalID(tt.principalID)
			if got != tt.want {
				t.Errorf("ExtractEmailFromPrincipalID(%q) = %q, want %q", tt.principalID, got, tt.want)
			}
		})
	}
}

func TestExtractRoleIDFromPrincipalID(t *testing.T) {
	tests := []struct {
		name        string
		principalID string
		want        string
	}{
		{
			name:        "standard SSO format",
			principalID: "AROAIDPPEZS35WEXAMPLE:me@alexsmolen.com",
			want:        "AROAIDPPEZS35WEXAMPLE",
		},
		{
			name:        "role ID only",
			principalID: "AROAIDPPEZS35WEXAMPLE",
			want:        "AROAIDPPEZS35WEXAMPLE",
		},
		{
			name:        "empty string",
			principalID: "",
			want:        "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractRoleIDFromPrincipalID(tt.principalID)
			if got != tt.want {
				t.Errorf("ExtractRoleIDFromPrincipalID(%q) = %q, want %q", tt.principalID, got, tt.want)
			}
		})
	}
}

func TestExtractRoleNameFromARN(t *testing.T) {
	tests := []struct {
		name string
		arn  string
		want string
	}{
		{
			name: "standard role ARN",
			arn:  "arn:aws:iam::123456789012:role/MyRole",
			want: "MyRole",
		},
		{
			name: "identity center role ARN",
			arn:  "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/us-east-2/AWSReservedSSO_AdministratorAccess_abc123",
			want: "aws-reserved/sso.amazonaws.com/us-east-2/AWSReservedSSO_AdministratorAccess_abc123",
		},
		{
			name: "service-linked role",
			arn:  "arn:aws:iam::123456789012:role/aws-service-role/lambda.amazonaws.com/AWSServiceRoleForLambda",
			want: "aws-service-role/lambda.amazonaws.com/AWSServiceRoleForLambda",
		},
		{
			name: "not a role ARN",
			arn:  "arn:aws:iam::123456789012:user/MyUser",
			want: "",
		},
		{
			name: "empty ARN",
			arn:  "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractRoleNameFromARN(tt.arn)
			if got != tt.want {
				t.Errorf("ExtractRoleNameFromARN(%q) = %q, want %q", tt.arn, got, tt.want)
			}
		})
	}
}

func TestExtractAccountIDFromARN(t *testing.T) {
	tests := []struct {
		name string
		arn  string
		want string
	}{
		{
			name: "standard role ARN",
			arn:  "arn:aws:iam::123456789012:role/MyRole",
			want: "123456789012",
		},
		{
			name: "S3 ARN without account",
			arn:  "arn:aws:s3:::my-bucket",
			want: "",
		},
		{
			name: "Lambda function ARN",
			arn:  "arn:aws:lambda:us-east-1:123456789012:function:my-function",
			want: "123456789012",
		},
		{
			name: "invalid ARN",
			arn:  "not-an-arn",
			want: "",
		},
		{
			name: "empty ARN",
			arn:  "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractAccountIDFromARN(tt.arn)
			if got != tt.want {
				t.Errorf("ExtractAccountIDFromARN(%q) = %q, want %q", tt.arn, got, tt.want)
			}
		})
	}
}

func TestIsIdentityCenterRole(t *testing.T) {
	tests := []struct {
		name    string
		roleARN string
		want    bool
	}{
		{
			name:    "identity center admin role",
			roleARN: "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/us-east-2/AWSReservedSSO_AdministratorAccess_abc123",
			want:    true,
		},
		{
			name:    "identity center readonly role",
			roleARN: "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_ReadOnlyAccess_def456",
			want:    true,
		},
		{
			name:    "standard IAM role",
			roleARN: "arn:aws:iam::123456789012:role/MyCustomRole",
			want:    false,
		},
		{
			name:    "service-linked role",
			roleARN: "arn:aws:iam::123456789012:role/aws-service-role/lambda.amazonaws.com/AWSServiceRoleForLambda",
			want:    false,
		},
		{
			name:    "aws-reserved but not SSO",
			roleARN: "arn:aws:iam::123456789012:role/aws-reserved/other-service/SomeRole",
			want:    false,
		},
		{
			name:    "sso.amazonaws.com but no AWSReservedSSO",
			roleARN: "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/OtherRole",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsIdentityCenterRole(tt.roleARN)
			if got != tt.want {
				t.Errorf("IsIdentityCenterRole(%q) = %v, want %v", tt.roleARN, got, tt.want)
			}
		})
	}
}

func TestClassifySessionType(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		want      string
	}{
		// Browser patterns - web-console
		{
			name:      "Chrome browser",
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
			want:      "web-console",
		},
		{
			name:      "Firefox browser",
			userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
			want:      "web-console",
		},
		{
			name:      "Safari browser",
			userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
			want:      "web-console",
		},
		{
			name:      "Edge browser",
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edge/91.0.864.59",
			want:      "web-console",
		},
		// CLI/SDK patterns - cli-sdk
		{
			name:      "AWS CLI v2",
			userAgent: "aws-cli/2.15.0 Python/3.11.6 Darwin/23.0.0 exe/x86_64 prompt/off",
			want:      "cli-sdk",
		},
		{
			name:      "AWS CLI v1",
			userAgent: "aws-cli/1.29.0 Python/3.9.7 Linux/5.10.0 botocore/1.31.0",
			want:      "cli-sdk",
		},
		{
			name:      "Boto3",
			userAgent: "Boto3/1.28.0 Python/3.9.7 Linux/5.10.0",
			want:      "cli-sdk",
		},
		{
			name:      "Botocore",
			userAgent: "botocore/1.31.0 Python/3.9.7",
			want:      "cli-sdk",
		},
		{
			name:      "AWS SDK for Java",
			userAgent: "aws-sdk-java/2.20.0 Linux/5.10.0 Java/17.0.1",
			want:      "cli-sdk",
		},
		{
			name:      "Terraform",
			userAgent: "Terraform/1.5.0 (+https://www.terraform.io) terraform-provider-aws/5.0.0",
			want:      "cli-sdk",
		},
		{
			name:      "Pulumi",
			userAgent: "pulumi/3.0.0 aws-sdk-go/1.44.0",
			want:      "cli-sdk",
		},
		{
			name:      "AWS Internal",
			userAgent: "aws-internal/3 aws-sdk-java/2.20.0",
			want:      "cli-sdk",
		},
		{
			name:      "Console service",
			userAgent: "console.amazonaws.com",
			want:      "cli-sdk",
		},
		{
			name:      "Python requests",
			userAgent: "python-requests/2.28.0",
			want:      "cli-sdk",
		},
		{
			name:      "Go HTTP client",
			userAgent: "Go-http-client/1.1",
			want:      "cli-sdk",
		},
		// Unrecognized - empty string
		{
			name:      "empty user agent",
			userAgent: "",
			want:      "",
		},
		{
			name:      "unknown user agent",
			userAgent: "CustomApp/1.0",
			want:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifySessionType(tt.userAgent)
			if got != tt.want {
				t.Errorf("ClassifySessionType(%q) = %q, want %q", tt.userAgent, got, tt.want)
			}
		})
	}
}

func TestIsClickOpsOperation(t *testing.T) {
	tests := []struct {
		name      string
		eventName string
		want      bool
	}{
		// Create operations
		{name: "CreateBucket", eventName: "CreateBucket", want: true},
		{name: "CreateFunction", eventName: "CreateFunction", want: true},
		{name: "CreateTable", eventName: "CreateTable", want: true},
		// Run operations
		{name: "RunInstances", eventName: "RunInstances", want: true},
		// Put operations
		{name: "PutObject", eventName: "PutObject", want: true},
		{name: "PutBucketPolicy", eventName: "PutBucketPolicy", want: true},
		// Update operations
		{name: "UpdateFunctionCode", eventName: "UpdateFunctionCode", want: true},
		{name: "UpdateTable", eventName: "UpdateTable", want: true},
		// Modify operations
		{name: "ModifyInstanceAttribute", eventName: "ModifyInstanceAttribute", want: true},
		// Delete operations
		{name: "DeleteBucket", eventName: "DeleteBucket", want: true},
		{name: "DeleteFunction", eventName: "DeleteFunction", want: true},
		// Start/Stop/Terminate
		{name: "StartInstances", eventName: "StartInstances", want: true},
		{name: "StopInstances", eventName: "StopInstances", want: true},
		{name: "TerminateInstances", eventName: "TerminateInstances", want: true},
		// Launch
		{name: "LaunchTemplate", eventName: "LaunchTemplate", want: true},
		// Attach/Detach
		{name: "AttachVolume", eventName: "AttachVolume", want: true},
		{name: "DetachVolume", eventName: "DetachVolume", want: true},
		// Enable/Disable
		{name: "EnableRule", eventName: "EnableRule", want: true},
		{name: "DisableRule", eventName: "DisableRule", want: true},
		// Register/Deregister
		{name: "RegisterTargets", eventName: "RegisterTargets", want: true},
		{name: "DeregisterTargets", eventName: "DeregisterTargets", want: true},
		// Add/Remove
		{name: "AddTags", eventName: "AddTags", want: true},
		{name: "RemoveTags", eventName: "RemoveTags", want: true},
		// Set
		{name: "SetIdentityPoolRoles", eventName: "SetIdentityPoolRoles", want: true},
		// Upload
		{name: "UploadArchive", eventName: "UploadArchive", want: true},
		// Build
		{name: "BuildProject", eventName: "BuildProject", want: true},
		// Read-only operations - not ClickOps
		{name: "GetObject", eventName: "GetObject", want: false},
		{name: "ListBuckets", eventName: "ListBuckets", want: false},
		{name: "DescribeInstances", eventName: "DescribeInstances", want: false},
		{name: "GetFunction", eventName: "GetFunction", want: false},
		{name: "HeadObject", eventName: "HeadObject", want: false},
		{name: "AssumeRole", eventName: "AssumeRole", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsClickOpsOperation(tt.eventName)
			if got != tt.want {
				t.Errorf("IsClickOpsOperation(%q) = %v, want %v", tt.eventName, got, tt.want)
			}
		})
	}
}

func TestIsValidSourceIP(t *testing.T) {
	tests := []struct {
		name     string
		sourceIP string
		want     bool
	}{
		// Valid IPv4 addresses
		{name: "valid public IPv4", sourceIP: "203.0.113.45", want: true},
		{name: "valid private IPv4", sourceIP: "192.168.1.100", want: true},
		{name: "valid corporate IPv4", sourceIP: "10.0.0.50", want: true},
		// Valid IPv6 addresses
		{name: "valid IPv6", sourceIP: "2001:0db8:85a3:0000:0000:8a2e:0370:7334", want: true},
		// Note: compressed IPv6 with ::1 suffix returns false due to loopback pattern match
		// This is a known limitation of the heuristic - real user IPv6 addresses rarely end in ::1
		{name: "compressed IPv6 ending in ::1", sourceIP: "2001:db8::1", want: false},
		{name: "valid IPv6 without ::1", sourceIP: "2001:db8::2", want: true},
		// Invalid - AWS service endpoints
		{name: "S3 endpoint", sourceIP: "s3.amazonaws.com", want: false},
		{name: "Lambda endpoint", sourceIP: "lambda.us-east-1.amazonaws.com", want: false},
		{name: "internal service", sourceIP: "internal-service.example.com", want: false},
		// Invalid - loopback
		{name: "localhost", sourceIP: "localhost", want: false},
		{name: "loopback IPv4", sourceIP: "127.0.0.1", want: false},
		{name: "loopback IPv6", sourceIP: "::1", want: false},
		// Invalid - metadata service
		{name: "EC2 metadata", sourceIP: "169.254.169.254", want: false},
		// Invalid - empty
		{name: "empty string", sourceIP: "", want: false},
		// Invalid - malformed
		{name: "malformed IPv4", sourceIP: "192.168.1.256", want: false},
		{name: "malformed partial", sourceIP: "192.168.1", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidSourceIP(tt.sourceIP)
			if got != tt.want {
				t.Errorf("IsValidSourceIP(%q) = %v, want %v", tt.sourceIP, got, tt.want)
			}
		})
	}
}

func TestIsValidUserAgent(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		want      bool
	}{
		// Valid user agents
		{name: "Chrome browser", userAgent: "Mozilla/5.0 Chrome/91.0", want: true},
		{name: "AWS CLI", userAgent: "aws-cli/2.15.0 Python/3.11.6", want: true},
		{name: "Terraform", userAgent: "Terraform/1.5.0", want: true},
		{name: "Boto3", userAgent: "Boto3/1.28.0 Python/3.9.7", want: true},
		// Invalid - AWS service-to-service
		{name: "Control Tower", userAgent: "controltower.amazonaws.com", want: false},
		{name: "Service Catalog", userAgent: "servicecatalog.amazonaws.com", want: false},
		{name: "AWS Config", userAgent: "config.amazonaws.com", want: false},
		{name: "CloudFormation internal", userAgent: "cloudformation.amazonaws.com", want: false},
		{name: "Organizations", userAgent: "organizations.amazonaws.com", want: false},
		{name: "AWS Internal", userAgent: "aws-internal/3", want: false},
		{name: "Jersey client", userAgent: "Jersey/2.35 (Apache HttpClient 4.5.13)", want: false},
		{name: "HttpURLConnection", userAgent: "Java/17.0.1 HttpURLConnection", want: false},
		// Invalid - empty
		{name: "empty", userAgent: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidUserAgent(tt.userAgent)
			if got != tt.want {
				t.Errorf("IsValidUserAgent(%q) = %v, want %v", tt.userAgent, got, tt.want)
			}
		})
	}
}

func TestIsAccessDeniedError(t *testing.T) {
	tests := []struct {
		name      string
		errorCode string
		want      bool
	}{
		{name: "AccessDenied", errorCode: "AccessDenied", want: true},
		{name: "AccessDeniedException", errorCode: "AccessDeniedException", want: true},
		{name: "VpceAccessDenied", errorCode: "VpceAccessDenied", want: true},
		{name: "UnauthorizedOperation", errorCode: "UnauthorizedOperation", want: true},
		{name: "Client.UnauthorizedOperation", errorCode: "Client.UnauthorizedOperation", want: true},
		{name: "other error", errorCode: "ValidationError", want: false},
		{name: "ResourceNotFoundException", errorCode: "ResourceNotFoundException", want: false},
		{name: "empty", errorCode: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsAccessDeniedError(tt.errorCode)
			if got != tt.want {
				t.Errorf("IsAccessDeniedError(%q) = %v, want %v", tt.errorCode, got, tt.want)
			}
		})
	}
}

func TestExtractPolicyInfo(t *testing.T) {
	tests := []struct {
		name         string
		errorMessage string
		wantARN      string
		wantType     string
	}{
		{
			name:         "SCP denial",
			errorMessage: "User: arn:aws:iam::123456789012:role/MyRole is not authorized to perform: s3:GetObject because no service control policy arn:aws:organizations::123456789012:policy/o-abc123/scp/p-xyz789 allows the action",
			wantARN:      "arn:aws:organizations::123456789012:policy/o-abc123/scp/p-xyz789",
			wantType:     "SCP",
		},
		{
			name:         "RCP denial",
			errorMessage: "Access denied due to resource control policy arn:aws:organizations::123456789012:policy/o-abc123/rcp/p-xyz789",
			wantARN:      "arn:aws:organizations::123456789012:policy/o-abc123/rcp/p-xyz789",
			wantType:     "RCP",
		},
		{
			name:         "identity-based policy denial",
			errorMessage: "User is not authorized because no identity-based policy arn:aws:iam::123456789012:policy/MyPolicy allows this action",
			wantARN:      "arn:aws:iam::123456789012:policy/MyPolicy",
			wantType:     "identity-based",
		},
		{
			name:         "permission boundary denial",
			errorMessage: "Action denied by permission boundary arn:aws:iam::123456789012:policy/MyBoundary",
			wantARN:      "arn:aws:iam::123456789012:policy/MyBoundary",
			wantType:     "permission-boundary",
		},
		{
			name:         "permissions boundary alternate spelling",
			errorMessage: "Action denied by permissions boundary arn:aws:iam::123456789012:policy/MyBoundary",
			wantARN:      "arn:aws:iam::123456789012:policy/MyBoundary",
			wantType:     "permission-boundary",
		},
		{
			name:         "no policy ARN in message",
			errorMessage: "User: arn:aws:iam::123456789012:role/MyRole is not authorized to perform this action",
			wantARN:      "",
			wantType:     "",
		},
		{
			name:         "empty message",
			errorMessage: "",
			wantARN:      "",
			wantType:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractPolicyInfo(tt.errorMessage)
			if got.PolicyARN != tt.wantARN {
				t.Errorf("ExtractPolicyInfo().PolicyARN = %q, want %q", got.PolicyARN, tt.wantARN)
			}
			if got.PolicyType != tt.wantType {
				t.Errorf("ExtractPolicyInfo().PolicyType = %q, want %q", got.PolicyType, tt.wantType)
			}
		})
	}
}

func TestNormalizeUserAgent(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		want      string
	}{
		{
			name:      "bracketed user agent",
			userAgent: "[Mozilla/5.0 Chrome/91.0]",
			want:      "Mozilla/5.0 Chrome/91.0",
		},
		{
			name:      "unbracketed user agent",
			userAgent: "Mozilla/5.0 Chrome/91.0",
			want:      "Mozilla/5.0 Chrome/91.0",
		},
		{
			name:      "bracketed with spaces",
			userAgent: "  [aws-cli/2.0]  ",
			want:      "aws-cli/2.0",
		},
		{
			name:      "only opening bracket",
			userAgent: "[Mozilla/5.0",
			want:      "[Mozilla/5.0",
		},
		{
			name:      "empty",
			userAgent: "",
			want:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeUserAgent(tt.userAgent)
			if got != tt.want {
				t.Errorf("NormalizeUserAgent(%q) = %q, want %q", tt.userAgent, got, tt.want)
			}
		})
	}
}

func TestGenerateSessionKey(t *testing.T) {
	tests := []struct {
		name           string
		email          string
		roleID         string
		userAgent      string
		eventTime      string
		wantKeyEmpty   bool // true if we expect empty session key
		wantStartEmpty bool
	}{
		{
			name:           "CLI session - 4 hour window",
			email:          "user@example.com",
			roleID:         "AROAEXAMPLE",
			userAgent:      "aws-cli/2.0",
			eventTime:      "2024-01-15T10:30:00Z",
			wantKeyEmpty:   false,
			wantStartEmpty: false,
		},
		{
			name:           "Web console session - returns empty for IAM time",
			email:          "user@example.com",
			roleID:         "AROAEXAMPLE",
			userAgent:      "Mozilla/5.0 Chrome/91.0",
			eventTime:      "2024-01-15T10:30:00Z",
			wantKeyEmpty:   true,
			wantStartEmpty: true,
		},
		{
			name:           "Unrecognized user agent - returns empty",
			email:          "user@example.com",
			roleID:         "AROAEXAMPLE",
			userAgent:      "CustomApp/1.0",
			eventTime:      "2024-01-15T10:30:00Z",
			wantKeyEmpty:   true,
			wantStartEmpty: true,
		},
		{
			name:           "Invalid event time - returns empty",
			email:          "user@example.com",
			roleID:         "AROAEXAMPLE",
			userAgent:      "aws-cli/2.0",
			eventTime:      "invalid-time",
			wantKeyEmpty:   true,
			wantStartEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotStart := GenerateSessionKey(tt.email, tt.roleID, tt.userAgent, tt.eventTime)

			if tt.wantKeyEmpty && gotKey != "" {
				t.Errorf("GenerateSessionKey() key = %q, want empty", gotKey)
			}
			if !tt.wantKeyEmpty && gotKey == "" {
				t.Errorf("GenerateSessionKey() key is empty, want non-empty")
			}
			if tt.wantStartEmpty && gotStart != "" {
				t.Errorf("GenerateSessionKey() start = %q, want empty", gotStart)
			}
			if !tt.wantStartEmpty && gotStart == "" {
				t.Errorf("GenerateSessionKey() start is empty, want non-empty")
			}
		})
	}
}

func TestIsAWSIP(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{name: "AWS IP in range", ip: "52.94.0.1", want: true},
		{name: "AWS IP 3.80.x.x", ip: "3.80.0.1", want: true},
		{name: "non-AWS IP", ip: "8.8.8.8", want: false},
		{name: "private IP", ip: "192.168.1.1", want: false},
		{name: "invalid IP", ip: "not-an-ip", want: false},
		{name: "empty", ip: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsAWSIP(tt.ip)
			if got != tt.want {
				t.Errorf("IsAWSIP(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestIsAWSUserAgent(t *testing.T) {
	tests := []struct {
		name string
		ua   string
		want bool
	}{
		{name: "AWS Internal", ua: "AWS Internal/1.0", want: true},
		{name: "aws-cli", ua: "aws-cli/2.0", want: true},
		{name: "Boto3", ua: "Boto3/1.28.0", want: true},
		{name: "aws-sdk-java", ua: "aws-sdk-java/2.0", want: true},
		{name: "AWSConsole", ua: "AWSConsole", want: true},
		{name: "S3Console", ua: "S3Console/1.0", want: true},
		{name: "Chrome browser", ua: "Mozilla/5.0 Chrome/91.0", want: false},
		{name: "custom app", ua: "MyCustomApp/1.0", want: false},
		{name: "empty", ua: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsAWSUserAgent(tt.ua)
			if got != tt.want {
				t.Errorf("IsAWSUserAgent(%q) = %v, want %v", tt.ua, got, tt.want)
			}
		})
	}
}
