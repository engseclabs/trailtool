// Package main provides the CloudTrail ingestor Lambda function.
// session.go contains functions for session detection, user identity extraction,
// and session type classification.
package main

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

// ExtractEmailFromPrincipalID extracts email from principalId
// Example: "AROAIDPPEZS35WEXAMPLE:me@alexsmolen.com" -> "me@alexsmolen.com"
// Only returns values that contain @ to filter out Lambda functions, UUIDs, etc.
func ExtractEmailFromPrincipalID(principalID string) string {
	parts := strings.Split(principalID, ":")
	if len(parts) >= 2 {
		email := parts[1]
		// Only return if it looks like an email (contains @)
		if strings.Contains(email, "@") {
			return email
		}
	}
	return ""
}

// ExtractRoleIDFromPrincipalID extracts role ID from principalId
// Example: "AROAIDPPEZS35WEXAMPLE:me@alexsmolen.com" -> "AROAIDPPEZS35WEXAMPLE"
func ExtractRoleIDFromPrincipalID(principalID string) string {
	parts := strings.Split(principalID, ":")
	if len(parts) >= 1 {
		return parts[0]
	}
	return principalID
}

// ExtractRoleNameFromARN extracts role name from ARN
// Example: "arn:aws:iam::123456789012:role/MyRole" -> "MyRole"
// Example: "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/us-east-2/MyRole" -> "aws-reserved/sso.amazonaws.com/us-east-2/MyRole"
func ExtractRoleNameFromARN(arn string) string {
	// Extract everything after "role/" to preserve full path
	rolePrefix := ":role/"
	idx := strings.Index(arn, rolePrefix)
	if idx != -1 {
		return arn[idx+len(rolePrefix):]
	}
	return ""
}

// ExtractAccountIDFromARN extracts account ID from ARN
// Example: "arn:aws:iam::123456789012:role/MyRole" -> "123456789012"
func ExtractAccountIDFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}

// IsIdentityCenterRole checks if a role ARN is an AWS IAM Identity Center (SSO) role
// These roles always follow the pattern: arn:aws:iam::ACCOUNT:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_*
func IsIdentityCenterRole(roleARN string) bool {
	return strings.Contains(roleARN, "/aws-reserved/sso.amazonaws.com/") &&
		strings.Contains(roleARN, "AWSReservedSSO_")
}

// NormalizeUserAgent strips surrounding brackets from user agent strings
func NormalizeUserAgent(userAgent string) string {
	ua := strings.TrimSpace(userAgent)
	if strings.HasPrefix(ua, "[") && strings.HasSuffix(ua, "]") {
		ua = ua[1 : len(ua)-1]
	}
	return ua
}

// ClassifySessionType determines the session type based on user agent
// Returns: "web-console" for web browser sessions, "cli-sdk" for CLI/SDK/IaC, or empty string for unrecognized
func ClassifySessionType(userAgent string) string {
	if userAgent == "" {
		log.Printf("UNRECOGNIZED_SESSION_TYPE: empty user agent")
		return ""
	}

	userAgentLower := strings.ToLower(userAgent)

	// Console/Browser patterns
	browserPatterns := []string{
		"mozilla/", "chrome/", "safari/", "firefox/", "edge/",
		"opera/", "msie", "trident/",
	}
	for _, pattern := range browserPatterns {
		if strings.Contains(userAgentLower, pattern) {
			return "web-console"
		}
	}

	// Programmatic patterns (CLI, SDK, IaC tools)
	programmaticPatterns := []string{
		"aws-cli/", "boto3/", "botocore/", "aws-sdk-",
		"terraform/", "pulumi/", "cloudformation/",
		"aws-internal/", "console.amazonaws.com",
		"python-requests/", "go-http-client/",
	}
	for _, pattern := range programmaticPatterns {
		if strings.Contains(userAgentLower, pattern) {
			return "cli-sdk"
		}
	}

	// Log unrecognized user agents for review - return empty string to prevent merging
	log.Printf("UNRECOGNIZED_SESSION_TYPE: user_agent=%s", userAgent)
	return ""
}

// IsClickOpsOperation checks if an event name represents a resource create/modify operation
// that should be flagged as ClickOps when performed from web console
func IsClickOpsOperation(eventName string) bool {
	// Check for create/modify/delete operations
	clickOpsPatterns := []string{
		"Create", "Run", "Put", "Update", "Modify", "Delete",
		"Start", "Stop", "Terminate", "Launch", "Attach", "Detach",
		"Enable", "Disable", "Register", "Deregister",
		"Add", "Remove", "Set", "Upload", "Build",
	}

	for _, pattern := range clickOpsPatterns {
		if strings.HasPrefix(eventName, pattern) {
			return true
		}
	}

	return false
}

// IsValidSourceIP checks if a source IP is a real user/client IP (not an AWS service endpoint or internal hostname)
func IsValidSourceIP(sourceIP string) bool {
	if sourceIP == "" {
		return false
	}

	// Filter out AWS service endpoints and internal hostnames
	invalidPatterns := []string{
		"amazonaws.com",   // Any *.amazonaws.com service endpoint
		"internal",        // AWS internal services
		"localhost",       // Local connections
		"127.0.0.1",       // Loopback
		"::1",             // IPv6 loopback
		"169.254.169.254", // EC2 metadata service
	}

	sourceIPLower := strings.ToLower(sourceIP)
	for _, pattern := range invalidPatterns {
		if strings.Contains(sourceIPLower, pattern) {
			return false
		}
	}

	// Check if it's a valid IPv4 address (rough check)
	parts := strings.Split(sourceIP, ".")
	if len(parts) == 4 {
		for _, part := range parts {
			if num, err := strconv.Atoi(part); err != nil || num < 0 || num > 255 {
				return false
			}
		}
		return true
	}

	// Check if it's a valid IPv6 address (contains colons and is not just hostname)
	if strings.Contains(sourceIP, ":") && !strings.Contains(sourceIP, ".") {
		// Basic check for IPv6 format
		return !strings.Contains(sourceIP, " ") && len(sourceIP) > 2
	}

	// Anything else (hostname, unknown format) is considered invalid
	return false
}

// IsValidUserAgent checks if a user agent is from a real user/client (not an AWS service-to-service call)
func IsValidUserAgent(userAgent string) bool {
	if userAgent == "" {
		return false
	}

	// Filter out AWS service-to-service calls (these are not user sessions)
	invalidPatterns := []string{
		"controltower.amazonaws.com",
		"servicecatalog.amazonaws.com",
		"config.amazonaws.com",
		"cloudformation.amazonaws.com", // Internal CloudFormation service calls
		"organizations.amazonaws.com",
		"aws-internal",
		"jersey/",           // Jersey HTTP client (AWS internal services)
		"httpurlconnection", // Generic Java HTTP client (often AWS service-to-service)
	}

	userAgentLower := strings.ToLower(userAgent)
	for _, pattern := range invalidPatterns {
		if strings.Contains(userAgentLower, pattern) {
			return false
		}
	}

	return true
}

// IsAccessDeniedError checks if an error code indicates an access denied event
// Matches: AccessDenied, Client.UnauthorizedOperation, UnauthorizedOperation, VpceAccessDenied
func IsAccessDeniedError(errorCode string) bool {
	if errorCode == "" {
		return false
	}
	return strings.Contains(errorCode, "AccessDenied") ||
		strings.Contains(errorCode, "UnauthorizedOperation")
}

// PolicyInfo contains extracted policy information from an access denied error message
type PolicyInfo struct {
	PolicyARN  string
	PolicyType string
}

// ExtractPolicyInfo extracts the policy ARN and type from AWS access denied error messages
// AWS includes policy ARNs in error messages as of Jan 2026 for:
// - Service Control Policies (SCP)
// - Resource Control Policies (RCP)
// - Identity-based policies
// - Session policies
// - Permission boundaries
func ExtractPolicyInfo(errorMessage string) PolicyInfo {
	if errorMessage == "" {
		return PolicyInfo{}
	}

	// Policy type patterns with their identifiers
	policyPatterns := []struct {
		pattern    string
		policyType string
	}{
		{"service control policy arn:aws:", "SCP"},
		{"resource control policy arn:aws:", "RCP"},
		{"identity-based policy arn:aws:", "identity-based"},
		{"session policy arn:aws:", "session"},
		{"permission boundary arn:aws:", "permission-boundary"},
		{"permissions boundary arn:aws:", "permission-boundary"},
		// Generic patterns for explicit deny cases
		{"explicit deny in arn:aws:", "explicit-deny"},
		{"policy arn:aws:", "policy"},
	}

	lowerMsg := strings.ToLower(errorMessage)

	for _, pp := range policyPatterns {
		if idx := strings.Index(lowerMsg, pp.pattern); idx != -1 {
			// Extract the ARN starting from "arn:aws:"
			arnStart := idx + len(pp.pattern) - len("arn:aws:")
			if arnStart >= 0 && arnStart < len(errorMessage) {
				// Find the end of the ARN (space, comma, period, or end of string)
				remaining := errorMessage[arnStart:]
				arnEnd := len(remaining)
				for i, ch := range remaining {
					if ch == ' ' || ch == ',' || ch == '.' || ch == ')' || ch == '"' || ch == '\'' {
						arnEnd = i
						break
					}
				}
				policyARN := remaining[:arnEnd]
				// Validate it looks like an ARN
				if strings.HasPrefix(policyARN, "arn:aws:") {
					return PolicyInfo{
						PolicyARN:  policyARN,
						PolicyType: pp.policyType,
					}
				}
			}
		}
	}

	return PolicyInfo{}
}

// GetRoleARN extracts the role ARN from the event
func GetRoleARN(event CloudTrailRecord) string {
	if event.UserIdentity.SessionContext != nil {
		return event.UserIdentity.SessionContext.SessionIssuer.ARN
	}

	// Handle AWSAccount type (e.g., Lambda execution roles, service-to-service calls)
	// PrincipalId format: "AROAXXXXXXXXXXXXXXXXX:role-session-name"
	if event.UserIdentity.Type == "AWSAccount" && event.UserIdentity.PrincipalID != "" {
		parts := strings.Split(event.UserIdentity.PrincipalID, ":")
		if len(parts) >= 2 {
			roleID := parts[0]
			sessionName := parts[1]
			accountID := event.UserIdentity.AccountID

			// Construct role ARN from the principal ID and account
			// We don't have the actual role name, so use the session name as best guess
			if accountID != "" && strings.HasPrefix(roleID, "ARO") {
				return fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, sessionName)
			}
		}
	}

	return ""
}

// GetSessionCreationTime extracts session creation time
func GetSessionCreationTime(event CloudTrailRecord) string {
	if event.UserIdentity.SessionContext != nil {
		return event.UserIdentity.SessionContext.Attributes.CreationDate
	}
	return ""
}

// GenerateSessionKey creates a session key based on session type
// Console sessions: use exact IAM creation time (precise, no credential refreshes)
// CLI sessions: use 4-hour time windows (handles SSO credential refreshes)
func GenerateSessionKey(email, roleID, userAgent, eventTime string) (sessionKey, startTime string) {
	sessionType := ClassifySessionType(userAgent)

	if sessionType == "" {
		return "", "" // Unrecognized session type
	}

	if sessionType == "web-console" {
		// Console: Use exact IAM session creation time
		// This is already available from the event's sessionContext
		return "", "" // Caller will use IAM creation time
	}

	// CLI/SDK: Use 4-hour time windows to group across credential refreshes
	// Parse event time
	parsedTime, err := time.Parse(time.RFC3339, eventTime)
	if err != nil {
		log.Printf("WARNING: Could not parse event time %s: %v", eventTime, err)
		return "", ""
	}

	// Truncate to 4-hour window (0-4, 4-8, 8-12, 12-16, 16-20, 20-24)
	windowStart := parsedTime.Truncate(4 * time.Hour)
	windowStartStr := windowStart.Format(time.RFC3339)

	// Session key includes window start instead of IAM creation time
	sessionKey = fmt.Sprintf("%s:%s:%s", email, roleID, windowStartStr)
	return sessionKey, windowStartStr
}

// IsAWSIP checks if an IP appears to be in a published AWS range via simple prefix matching.
// NOTE: This is a heuristic for UI labeling only. For production, download and cache
// https://ip-ranges.amazonaws.com/ip-ranges.json and perform CIDR checks.
func IsAWSIP(ip string) bool {
	// Minimal subset of AWS published ranges (examples only, not exhaustive)
	// Using specific CIDRs instead of broad /8 or first-octet matching to reduce false positives.
	// For production: download https://ip-ranges.amazonaws.com/ip-ranges.json and build a full list.
	cidrs := []string{
		"3.5.140.0/22", "3.5.152.0/22", "3.80.0.0/12",
		"13.52.0.0/16", "13.54.0.0/15", "13.56.0.0/16", "13.58.0.0/15",
		"15.152.0.0/16",
		"18.144.0.0/15", "18.204.0.0/14",
		"34.192.0.0/12",
		"35.160.0.0/13",
		"44.192.0.0/11",
		"52.0.0.0/11", "52.94.0.0/15", "52.95.255.16/28",
		"54.144.0.0/14",
		"99.80.0.0/15",
	}
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return false
	}
	for _, block := range cidrs {
		_, network, err := net.ParseCIDR(block)
		if err != nil {
			continue
		}
		if network.Contains(ipAddr) {
			return true
		}
	}
	return false
}

// IsAWSUserAgent performs a simple substring match to detect AWS / SDK / console user agents.
// This is used only for labeling in the frontend; enrichment currently happens client-side.
func IsAWSUserAgent(ua string) bool {
	if ua == "" {
		return false
	}
	patterns := []string{
		"AWS Internal",
		"aws-cli",
		"Boto3",
		"aws-sdk",
		"AWSConsole",
		"Amazon CloudFront",
		"S3Console",
	}
	lower := strings.ToLower(ua)
	for _, p := range patterns {
		if strings.Contains(lower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}
