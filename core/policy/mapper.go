package policy

import (
	"fmt"
	"strings"
)

// IAMActionMapper maps CloudTrail events to IAM actions
type IAMActionMapper struct {
	mappings map[string][]string
}

// NewIAMActionMapper creates a new mapper with comprehensive AWS service mappings
func NewIAMActionMapper() *IAMActionMapper {
	m := &IAMActionMapper{
		mappings: make(map[string][]string),
	}
	m.loadDatasetMappings()
	m.initializeSpecialCases()
	return m
}

// MapEventToIAMActions maps a CloudTrail event to IAM actions
func (m *IAMActionMapper) MapEventToIAMActions(eventSource, eventName string) []string {
	if eventSource == "" || eventName == "" {
		return []string{}
	}

	service := m.normalizeEventSource(eventSource)
	normalizedEventName := m.normalizeEventName(eventName)

	key := fmt.Sprintf("%s:%s", service, normalizedEventName)
	if actions, exists := m.mappings[key]; exists {
		return actions
	}

	wildcardKey := fmt.Sprintf("%s:*", service)
	if actions, exists := m.mappings[wildcardKey]; exists {
		return actions
	}

	return []string{fmt.Sprintf("%s:%s", service, normalizedEventName)}
}

func (m *IAMActionMapper) normalizeEventSource(eventSource string) string {
	service := strings.TrimSuffix(eventSource, ".amazonaws.com")
	switch service {
	case "monitoring":
		return "cloudwatch"
	case "logs":
		return "cloudwatchlogs"
	default:
		return service
	}
}

func (m *IAMActionMapper) normalizeEventName(eventName string) string {
	if len(eventName) > 8 {
		suffix := eventName[len(eventName)-8:]
		allDigits := true
		for _, c := range suffix {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return eventName[:len(eventName)-8]
		}
	}
	return eventName
}

func (m *IAMActionMapper) addMapping(key string, actions ...string) {
	m.mappings[key] = actions
}

func (m *IAMActionMapper) initializeSpecialCases() {
	m.addMapping("cloudformation:CreateStack", "cloudformation:CreateStack", "iam:PassRole")
	m.addMapping("cloudformation:UpdateStack", "cloudformation:UpdateStack", "iam:PassRole")
	m.addMapping("cloudformation:ExecuteChangeSet", "cloudformation:ExecuteChangeSet", "iam:PassRole")
	m.addMapping("s3:HeadBucket", "s3:ListBucket")
	m.addMapping("s3:HeadObject", "s3:GetObject")
}
