package policy

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/engseclabs/trailtool/core/models"
)

var iamMapper *IAMActionMapper

func init() {
	iamMapper = NewIAMActionMapper()
}

// IAMActionUsage represents a single IAM action with usage count and associated resources
type IAMActionUsage struct {
	Action    string   `json:"action"`
	Count     int      `json:"count"`
	Resources []string `json:"resources,omitempty"`
}

// PolicyDocument represents an AWS IAM policy document
type PolicyDocument struct {
	Version   string            `json:"Version"`
	Statement []PolicyStatement `json:"Statement"`
}

// PolicyStatement represents a single IAM policy statement
type PolicyStatement struct {
	Sid      string   `json:"Sid,omitempty"`
	Effect   string   `json:"Effect"`
	Action   []string `json:"Action"`
	Resource []string `json:"Resource"`
}

// GenerateResult contains the policy generation output
type GenerateResult struct {
	RoleARN          string           `json:"role_arn"`
	RoleName         string           `json:"role_name"`
	AccountID        string           `json:"account_id"`
	TotalActionsUsed int              `json:"total_actions_used"`
	Actions          []IAMActionUsage `json:"actions"`
	UnmappedEvents   []string         `json:"unmapped_events,omitempty"`
	PolicyJSON       string           `json:"policy_json"`
}

// GeneratePolicy generates a least-privilege IAM policy for a role
func GeneratePolicy(role *models.Role, includeDenied bool) (*GenerateResult, error) {
	actionCounts := make(map[string]int)
	unmappedSet := make(map[string]bool)

	// Process ResourceAccesses
	if len(role.ResourceAccesses) > 0 {
		for _, access := range role.ResourceAccesses {
			iamActions := iamMapper.MapEventToIAMActions(access.Service, access.EventName)
			if len(iamActions) == 0 {
				unmappedSet[access.Service+":"+access.EventName] = true
				continue
			}
			for _, action := range iamActions {
				actionCounts[action] += access.Count
			}
		}
	}

	// Process TopEventNames
	if len(role.TopEventNames) > 0 {
		for eventKey, count := range role.TopEventNames {
			parts := strings.SplitN(eventKey, ":", 2)
			if len(parts) != 2 {
				unmappedSet[eventKey] = true
				continue
			}
			iamActions := iamMapper.MapEventToIAMActions(parts[0], parts[1])
			if len(iamActions) == 0 {
				unmappedSet[eventKey] = true
				continue
			}
			for _, action := range iamActions {
				actionCounts[action] += count
			}
		}
	}

	// Process denied events if requested
	if includeDenied {
		if len(role.DeniedResourceAccesses) > 0 {
			for _, access := range role.DeniedResourceAccesses {
				iamActions := iamMapper.MapEventToIAMActions(access.Service, access.EventName)
				if len(iamActions) == 0 {
					unmappedSet[access.Service+":"+access.EventName] = true
					continue
				}
				for _, action := range iamActions {
					actionCounts[action] += access.Count
				}
			}
		}
		if len(role.TopDeniedEventNames) > 0 {
			for eventKey, count := range role.TopDeniedEventNames {
				parts := strings.SplitN(eventKey, ":", 2)
				if len(parts) != 2 {
					unmappedSet[eventKey] = true
					continue
				}
				iamActions := iamMapper.MapEventToIAMActions(parts[0], parts[1])
				if len(iamActions) == 0 {
					unmappedSet[eventKey] = true
					continue
				}
				for _, action := range iamActions {
					actionCounts[action] += count
				}
			}
		}
	}

	// Build action list
	actions := make([]IAMActionUsage, 0, len(actionCounts))
	for action, count := range actionCounts {
		actions = append(actions, IAMActionUsage{Action: action, Count: count})
	}

	// Map resources to actions
	actionResourceMap := make(map[string]map[string]bool)
	mapResourceAccessesToActionResources(role.ResourceAccesses, actionResourceMap, role.AccountID)
	if includeDenied {
		mapResourceAccessesToActionResources(role.DeniedResourceAccesses, actionResourceMap, role.AccountID)
	}

	// Populate resources
	for i := range actions {
		if resourceSet, exists := actionResourceMap[actions[i].Action]; exists {
			resources := make([]string, 0, len(resourceSet))
			for resource := range resourceSet {
				resources = append(resources, resource)
			}
			sort.Strings(resources)
			if len(resources) > 50 {
				resources = resources[:50]
			}
			actions[i].Resources = resources
		}
	}

	// Sort by count descending
	sort.Slice(actions, func(i, j int) bool {
		return actions[i].Count > actions[j].Count
	})

	unmappedEvents := make([]string, 0, len(unmappedSet))
	for event := range unmappedSet {
		unmappedEvents = append(unmappedEvents, event)
	}
	sort.Strings(unmappedEvents)

	// Generate policy document
	policyDoc := buildPolicyDocument(actions)
	policyJSON, err := json.MarshalIndent(policyDoc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal policy: %w", err)
	}

	return &GenerateResult{
		RoleARN:          role.ARN,
		RoleName:         role.Name,
		AccountID:        role.AccountID,
		TotalActionsUsed: len(actions),
		Actions:          actions,
		UnmappedEvents:   unmappedEvents,
		PolicyJSON:       string(policyJSON),
	}, nil
}

func mapResourceAccessesToActionResources(accesses []models.ResourceAccessItem, actionResourceMap map[string]map[string]bool, accountID string) {
	for _, ra := range accesses {
		iamActions := iamMapper.MapEventToIAMActions(ra.Service, ra.EventName)
		for _, action := range iamActions {
			if actionResourceMap[action] == nil {
				actionResourceMap[action] = make(map[string]bool)
			}
			arn := resourceIdentifierToARN(ra.Resource, accountID)
			actionResourceMap[action][arn] = true
		}
	}
}

func buildPolicyDocument(actions []IAMActionUsage) PolicyDocument {
	if len(actions) == 0 {
		return PolicyDocument{
			Version:   "2012-10-17",
			Statement: []PolicyStatement{},
		}
	}

	// Group actions by their resource set
	type resourceKey string
	groups := make(map[resourceKey][]string)
	groupResources := make(map[resourceKey][]string)

	for _, a := range actions {
		var key resourceKey
		if len(a.Resources) > 0 {
			sorted := make([]string, len(a.Resources))
			copy(sorted, a.Resources)
			sort.Strings(sorted)
			key = resourceKey(strings.Join(sorted, ","))
		} else {
			key = "*"
		}
		groups[key] = append(groups[key], a.Action)
		if len(a.Resources) > 0 {
			groupResources[key] = a.Resources
		}
	}

	statements := make([]PolicyStatement, 0, len(groups))
	for key, groupActions := range groups {
		sort.Strings(groupActions)
		resources := []string{"*"}
		if res, ok := groupResources[key]; ok {
			resources = res
		}
		statements = append(statements, PolicyStatement{
			Effect:   "Allow",
			Action:   groupActions,
			Resource: resources,
		})
	}

	sort.Slice(statements, func(i, j int) bool {
		return statements[i].Action[0] < statements[j].Action[0]
	})

	return PolicyDocument{
		Version:   "2012-10-17",
		Statement: statements,
	}
}

func resourceIdentifierToARN(identifier, accountID string) string {
	parts := strings.SplitN(identifier, ":", 3)
	if len(parts) < 2 {
		return identifier
	}

	service := parts[0]
	resourceType := parts[1]
	var resourceName string
	if len(parts) == 3 {
		resourceName = parts[2]
	}

	switch service {
	case "s3":
		if resourceType == "bucket" && resourceName != "" {
			return fmt.Sprintf("arn:aws:s3:::%s/*", resourceName)
		}
		return "arn:aws:s3:::*"
	case "dynamodb":
		if resourceType == "table" && resourceName != "" {
			return fmt.Sprintf("arn:aws:dynamodb:*:*:table/%s", resourceName)
		}
		return "arn:aws:dynamodb:*:*:table/*"
	case "lambda":
		if resourceType == "function" && resourceName != "" {
			return fmt.Sprintf("arn:aws:lambda:*:*:function:%s", resourceName)
		}
		return "arn:aws:lambda:*:*:function:*"
	case "sqs":
		if resourceName != "" {
			return fmt.Sprintf("arn:aws:sqs:*:*:%s", resourceName)
		}
		return "arn:aws:sqs:*:*:*"
	case "sns":
		if resourceName != "" {
			return fmt.Sprintf("arn:aws:sns:*:*:%s", resourceName)
		}
		return "arn:aws:sns:*:*:*"
	case "secretsmanager":
		if resourceType == "secret" && resourceName != "" {
			if len(resourceName) > 7 && strings.Contains(resourceName, "-") {
				rnParts := strings.Split(resourceName, "-")
				if len(rnParts) > 1 && len(rnParts[len(rnParts)-1]) == 6 {
					resourceName = strings.Join(rnParts[:len(rnParts)-1], "-") + "-*"
				}
			}
			return fmt.Sprintf("arn:aws:secretsmanager:*:*:secret:%s", resourceName)
		}
		return "arn:aws:secretsmanager:*:*:secret:*"
	case "kms":
		if resourceType == "key" && resourceName != "" {
			return fmt.Sprintf("arn:aws:kms:*:*:key/%s", resourceName)
		}
		return "arn:aws:kms:*:*:key/*"
	case "logs":
		if resourceType == "log-group" && resourceName != "" {
			return fmt.Sprintf("arn:aws:logs:*:*:log-group:%s:*", resourceName)
		}
		return "arn:aws:logs:*:*:log-group:*"
	default:
		if resourceName != "" {
			return fmt.Sprintf("arn:aws:%s:*:*:%s/%s", service, resourceType, resourceName)
		}
		return fmt.Sprintf("arn:aws:%s:*:*:*", service)
	}
}
