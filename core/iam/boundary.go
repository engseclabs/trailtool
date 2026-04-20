// Package iam provides helpers for querying IAM metadata at query time.
package iam

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// PermissionBoundaryInfo holds the boundary ARN and optionally its policy document.
type PermissionBoundaryInfo struct {
	BoundaryARN    string `json:"boundary_arn"`
	PolicyDocument string `json:"policy_document,omitempty"`
}

// FetchPermissionBoundary fetches the permission boundary attached to the role identified
// by roleARN. Returns nil if no boundary is attached. The policy document is always fetched.
//
// Requires iam:GetRole on the role and iam:GetPolicy + iam:GetPolicyVersion on the boundary
// policy. These are read-only calls and are not recorded as management events in CloudTrail.
func FetchPermissionBoundary(ctx context.Context, client *iam.Client, roleARN string) (*PermissionBoundaryInfo, error) {
	roleName := extractRoleNameFromARN(roleARN)
	if roleName == "" {
		return nil, fmt.Errorf("could not extract role name from ARN: %s", roleARN)
	}

	roleOut, err := client.GetRole(ctx, &iam.GetRoleInput{
		RoleName: aws.String(roleName),
	})
	if err != nil {
		return nil, fmt.Errorf("iam:GetRole(%s): %w", roleName, err)
	}

	if roleOut.Role.PermissionsBoundary == nil || roleOut.Role.PermissionsBoundary.PermissionsBoundaryArn == nil {
		return nil, nil
	}

	boundaryARN := aws.ToString(roleOut.Role.PermissionsBoundary.PermissionsBoundaryArn)
	info := &PermissionBoundaryInfo{BoundaryARN: boundaryARN}

	policyOut, err := client.GetPolicy(ctx, &iam.GetPolicyInput{
		PolicyArn: aws.String(boundaryARN),
	})
	if err != nil {
		return info, nil // boundary ARN is useful even if we can't fetch the document
	}

	versionID := aws.ToString(policyOut.Policy.DefaultVersionId)
	versionOut, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: aws.String(boundaryARN),
		VersionId: aws.String(versionID),
	})
	if err != nil {
		return info, nil
	}

	if versionOut.PolicyVersion != nil && versionOut.PolicyVersion.Document != nil {
		info.PolicyDocument = aws.ToString(versionOut.PolicyVersion.Document)
	}

	return info, nil
}

// extractRoleNameFromARN extracts the role name from an IAM role ARN.
// e.g. "arn:aws:iam::123456789012:role/my-role" → "my-role"
func extractRoleNameFromARN(arn string) string {
	const prefix = ":role/"
	idx := strings.LastIndex(arn, prefix)
	if idx == -1 {
		return ""
	}
	return arn[idx+len(prefix):]
}
