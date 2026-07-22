package aggregator

import (
	"encoding/json"
	"strings"

	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

// IsMCPServerResource reports whether an OAuth requestParameters.resource value points at the
// AWS MCP Server. AWS uses regional hostnames (aws-mcp.us-east-1.api.aws) as well as the
// aws-mcp.amazonaws.com resource identifier used in the client_credentials (headless) flow.
func IsMCPServerResource(resource string) bool {
	if resource == "" {
		return false
	}
	r := strings.ToLower(resource)
	return strings.Contains(r, "aws-mcp.") &&
		(strings.Contains(r, ".api.aws") || strings.Contains(r, "amazonaws.com"))
}

// ExtractOAuthResource returns requestParameters.resource from a signin OAuth event
// (AuthorizeOAuth2Access / CreateOAuth2Token). Returns "" if absent.
func ExtractOAuthResource(event types.CloudTrailRecord) string {
	if event.RequestParameters == nil {
		return ""
	}
	b, err := json.Marshal(event.RequestParameters)
	if err != nil {
		return ""
	}
	var params struct {
		Resource string `json:"resource"`
	}
	if err := json.Unmarshal(b, &params); err != nil {
		return ""
	}
	return params.Resource
}

// ExtractSignInSessionArn returns the OAuth sign-in session ARN correlating an event to its
// grant. It checks both locations AWS populates: additionalEventData.signInSessionArn (present
// on CreateOAuth2Token) and userIdentity.sessionContext.signInSessionArn (present on both the
// grant and every subsequent API call made with the OAuth access token). Returns "" if absent.
func ExtractSignInSessionArn(event types.CloudTrailRecord) string {
	if event.AdditionalEventData != nil {
		if b, err := json.Marshal(event.AdditionalEventData); err == nil {
			var aed struct {
				SignInSessionArn string `json:"signInSessionArn"`
			}
			if err := json.Unmarshal(b, &aed); err == nil && aed.SignInSessionArn != "" {
				return aed.SignInSessionArn
			}
		}
	}
	if event.UserIdentity.SessionContext != nil && event.UserIdentity.SessionContext.SignInSessionArn != "" {
		return event.UserIdentity.SessionContext.SignInSessionArn
	}
	return ""
}

// ExtractIssuedAccessKeyID extracts the access key ID from an AssumeRole response.
// CloudTrail structure: responseElements.credentials.accessKeyId
// Returns empty string if not present or not an AssumeRole event.
func ExtractIssuedAccessKeyID(event types.CloudTrailRecord) string {
	if event.EventName != "AssumeRole" {
		return ""
	}
	if event.ResponseElements == nil {
		return ""
	}

	b, err := json.Marshal(event.ResponseElements)
	if err != nil {
		return ""
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(b, &resp); err != nil {
		return ""
	}

	creds, ok := resp["credentials"].(map[string]interface{})
	if !ok {
		return ""
	}

	keyID, _ := creds["accessKeyId"].(string)
	return keyID
}

// ExtractAssumedRoleARN extracts the role ARN from an AssumeRole request.
// CloudTrail structure: requestParameters.roleArn
// Returns empty string if not present.
func ExtractAssumedRoleARN(event types.CloudTrailRecord) string {
	if event.EventName != "AssumeRole" {
		return ""
	}
	if event.RequestParameters == nil {
		return ""
	}

	b, err := json.Marshal(event.RequestParameters)
	if err != nil {
		return ""
	}

	var params map[string]interface{}
	if err := json.Unmarshal(b, &params); err != nil {
		return ""
	}

	roleArn, _ := params["roleArn"].(string)
	return roleArn
}

// ExtractSessionTags extracts the session tags map from an AssumeRole requestParameters.
// Returns nil if the event is not an AssumeRole or has no tags.
// CloudTrail shape: requestParameters.tags = [{key: "AgentName", value: "claude-code"}, ...]
func ExtractSessionTags(event types.CloudTrailRecord) map[string]string {
	if event.EventName != "AssumeRole" || event.RequestParameters == nil {
		return nil
	}
	b, err := json.Marshal(event.RequestParameters)
	if err != nil {
		return nil
	}
	var params struct {
		Tags []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"tags"`
	}
	if err := json.Unmarshal(b, &params); err != nil || len(params.Tags) == 0 {
		return nil
	}
	result := make(map[string]string, len(params.Tags))
	for _, t := range params.Tags {
		result[t.Key] = t.Value
	}
	return result
}

// ExtractSessionPolicy extracts the inline session policy from an AssumeRole requestParameters.policy.
// Returns empty string if not an AssumeRole event or no policy was provided.
func ExtractSessionPolicy(event types.CloudTrailRecord) string {
	if event.EventName != "AssumeRole" || event.RequestParameters == nil {
		return ""
	}
	b, err := json.Marshal(event.RequestParameters)
	if err != nil {
		return ""
	}
	var params struct {
		Policy string `json:"policy"`
	}
	if err := json.Unmarshal(b, &params); err != nil {
		return ""
	}
	return params.Policy
}

// ExtractAssumedRoleID extracts the role ID (AROAID...) of the assumed role from an
// AssumeRole response. CloudTrail structure: responseElements.assumedRoleUser.assumedRoleId
// which has format "AROAID...:sessionName". Returns just the role ID portion.
func ExtractAssumedRoleID(event types.CloudTrailRecord) string {
	if event.EventName != "AssumeRole" || event.ResponseElements == nil {
		return ""
	}

	b, err := json.Marshal(event.ResponseElements)
	if err != nil {
		return ""
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(b, &resp); err != nil {
		return ""
	}

	aru, ok := resp["assumedRoleUser"].(map[string]interface{})
	if !ok {
		return ""
	}

	assumedRoleID, _ := aru["assumedRoleId"].(string)
	// Format is "AROAID...:sessionName" — extract just the role ID part
	if idx := len(assumedRoleID); idx > 0 {
		for i, c := range assumedRoleID {
			if c == ':' {
				return assumedRoleID[:i]
			}
		}
	}
	return assumedRoleID
}
