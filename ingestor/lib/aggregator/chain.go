package aggregator

import (
	"encoding/json"

	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

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
