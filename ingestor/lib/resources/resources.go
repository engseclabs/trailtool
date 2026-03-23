// Package resources contains functions for extracting resource identifiers from CloudTrail events
// and classifying AWS services.
package resources

import (
	"fmt"
	"log"
	"strings"

	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

// ExtractResources normalizes resources from an event
func ExtractResources(event types.CloudTrailRecord) []string {
	var resources []string
	seen := make(map[string]bool)

	switch event.EventSource {
	case "s3.amazonaws.com":
		if bucket := extractS3Bucket(event.RequestParameters); bucket != "" {
			key := fmt.Sprintf("s3:bucket:%s", bucket)
			resources = append(resources, key)
			seen[key] = true
		}
	case "lambda.amazonaws.com":
		if function := extractLambdaFunction(event.RequestParameters); function != "" {
			key := fmt.Sprintf("lambda:function:%s", function)
			resources = append(resources, key)
			seen[key] = true
		}
	case "dynamodb.amazonaws.com":
		if table := extractDynamoTable(event.RequestParameters); table != "" {
			key := fmt.Sprintf("dynamodb:table:%s", table)
			resources = append(resources, key)
			seen[key] = true
		}
	case "ec2.amazonaws.com":
		if instance := extractEC2Instance(event.RequestParameters); instance != "" {
			key := fmt.Sprintf("ec2:instance:%s", instance)
			resources = append(resources, key)
			seen[key] = true
		}
	case "iam.amazonaws.com":
		resource := extractIAMResource(event.RequestParameters, event.EventName)
		log.Printf("DEBUG_IAM: eventName=%s resource=%q params=%+v", event.EventName, resource, event.RequestParameters)
		if resource != "" {
			resources = append(resources, resource)
			seen[resource] = true
		}
	case "cloudformation.amazonaws.com":
		if stack := extractCloudFormationStack(event.RequestParameters); stack != "" {
			key := fmt.Sprintf("cloudformation:stack:%s", stack)
			resources = append(resources, key)
			seen[key] = true
		}
	case "controltower.amazonaws.com":
		if res := extractControlTowerResource(event.RequestParameters); res != "" {
			resources = append(resources, res)
			seen[res] = true
		}
	case "rds.amazonaws.com":
		if res := extractRDSResource(event.RequestParameters); res != "" {
			key := fmt.Sprintf("rds:%s", res)
			resources = append(resources, key)
			seen[key] = true
		}
	case "ecr.amazonaws.com":
		if repo := extractECRRepository(event.RequestParameters); repo != "" {
			key := fmt.Sprintf("ecr:repository:%s", repo)
			resources = append(resources, key)
			seen[key] = true
		}
	case "ecs.amazonaws.com":
		if res := extractECSResource(event.RequestParameters); res != "" {
			resources = append(resources, res)
			seen[res] = true
		}
	case "sqs.amazonaws.com":
		if queue := extractSQSQueue(event.RequestParameters); queue != "" {
			key := fmt.Sprintf("sqs:queue:%s", queue)
			resources = append(resources, key)
			seen[key] = true
		}
	case "sns.amazonaws.com":
		if topic := extractSNSTopic(event.RequestParameters); topic != "" {
			resources = append(resources, topic)
			seen[topic] = true
		}
	case "kms.amazonaws.com":
		if key := extractKMSKey(event.RequestParameters); key != "" {
			resources = append(resources, key)
			seen[key] = true
		}
	case "secretsmanager.amazonaws.com":
		if secret := extractSecret(event.RequestParameters); secret != "" {
			key := fmt.Sprintf("secretsmanager:secret:%s", secret)
			resources = append(resources, key)
			seen[key] = true
		}
	case "logs.amazonaws.com":
		if log := extractLogGroup(event.RequestParameters); log != "" {
			key := fmt.Sprintf("logs:log-group:%s", log)
			resources = append(resources, key)
			seen[key] = true
		}
	case "events.amazonaws.com":
		if rule := extractEventRule(event.RequestParameters); rule != "" {
			key := fmt.Sprintf("events:rule:%s", rule)
			resources = append(resources, key)
			seen[key] = true
		}
	case "states.amazonaws.com":
		if sm := extractStateMachine(event.RequestParameters); sm != "" {
			key := fmt.Sprintf("states:state-machine:%s", sm)
			resources = append(resources, key)
			seen[key] = true
		}
	case "apigateway.amazonaws.com":
		if api := extractRestApi(event.RequestParameters); api != "" {
			key := fmt.Sprintf("apigateway:rest-api:%s", api)
			resources = append(resources, key)
			seen[key] = true
		}
	case "route53.amazonaws.com":
		if zone := extractHostedZone(event.RequestParameters); zone != "" {
			key := fmt.Sprintf("route53:hosted-zone:%s", zone)
			resources = append(resources, key)
			seen[key] = true
		}
	case "cloudfront.amazonaws.com":
		if dist := extractCloudFrontDistribution(event.RequestParameters); dist != "" {
			key := fmt.Sprintf("cloudfront:distribution:%s", dist)
			resources = append(resources, key)
			seen[key] = true
		}
	}

	// Services that are already handled explicitly above — skip their ARNs in the fallback
	// to avoid creating duplicate resource entries with different identifier formats.
	handledServices := map[string]bool{
		"s3": true, "lambda": true, "dynamodb": true, "ec2": true, "iam": true,
		"cloudformation": true, "controltower": true, "rds": true, "ecr": true,
		"ecs": true, "sqs": true, "sns": true, "kms": true, "secretsmanager": true,
		"logs": true, "events": true, "states": true, "apigateway": true,
		"route53": true, "cloudfront": true,
	}

	// Fallback: include resources array from CloudTrail to capture services we don't explicitly parse
	for _, r := range event.Resources {
		if r.ARN != "" {
			// Skip ARNs for services we already extract explicitly
			arnParts := strings.SplitN(r.ARN, ":", 6)
			if len(arnParts) >= 3 && handledServices[arnParts[2]] {
				continue
			}
			norm := NormalizeResourceFromARN(r.ARN)
			if !seen[norm] {
				resources = append(resources, norm)
				seen[norm] = true
			}
			continue
		}
		if r.Type != "" {
			candidate := strings.ToLower(r.Type)
			if !seen[candidate] {
				resources = append(resources, candidate)
				seen[candidate] = true
			}
		}
	}

	return resources
}

// NormalizeResourceFromARN creates a stable identifier from an ARN
func NormalizeResourceFromARN(arnStr string) string {
	parts := strings.SplitN(arnStr, ":", 6)
	if len(parts) < 6 {
		return arnStr
	}
	service := parts[2]
	resourcePart := parts[5]
	segments := strings.Split(resourcePart, "/")
	if len(segments) >= 2 {
		// Include resource type and name: service:type:name
		return fmt.Sprintf("%s:%s:%s", service, segments[0], segments[1])
	}
	if len(segments) == 1 {
		return fmt.Sprintf("%s:%s", service, segments[0])
	}
	return arnStr
}

// extractS3Bucket extracts bucket name from S3 operations
func extractS3Bucket(params interface{}) string {
	if params == nil {
		return ""
	}

	paramMap, ok := params.(map[string]interface{})
	if !ok {
		return ""
	}

	if bucketName, exists := paramMap["bucketName"]; exists {
		if bucket, ok := bucketName.(string); ok {
			return bucket
		}
	}

	return ""
}

// extractLambdaFunction extracts function name from Lambda operations
func extractLambdaFunction(params interface{}) string {
	if params == nil {
		return ""
	}

	paramMap, ok := params.(map[string]interface{})
	if !ok {
		return ""
	}

	if functionName, exists := paramMap["functionName"]; exists {
		if function, ok := functionName.(string); ok {
			// If it's an ARN, extract just the function name
			// Format: arn:aws:lambda:region:account:function:function-name
			if strings.HasPrefix(function, "arn:aws:lambda:") {
				parts := strings.Split(function, ":")
				if len(parts) >= 7 {
					// Function name is after "function:" prefix
					return parts[6]
				}
			}
			return function
		}
	}

	return ""
}

// extractDynamoTable extracts table name from DynamoDB operations
func extractDynamoTable(params interface{}) string {
	if params == nil {
		return ""
	}

	paramMap, ok := params.(map[string]interface{})
	if !ok {
		return ""
	}

	if tableName, exists := paramMap["tableName"]; exists {
		if table, ok := tableName.(string); ok {
			return table
		}
	}

	return ""
}

// extractEC2Instance extracts instance ID from EC2 operations
func extractEC2Instance(params interface{}) string {
	if params == nil {
		return ""
	}

	paramMap, ok := params.(map[string]interface{})
	if !ok {
		return ""
	}

	// Check for instanceId in various forms
	if instanceId, exists := paramMap["instanceId"]; exists {
		if instance, ok := instanceId.(string); ok {
			return instance
		}
	}

	// Check for instancesSet (array)
	if instancesSet, exists := paramMap["instancesSet"]; exists {
		if instances, ok := instancesSet.(map[string]interface{}); ok {
			if items, exists := instances["items"]; exists {
				if itemsList, ok := items.([]interface{}); ok && len(itemsList) > 0 {
					if firstInstance, ok := itemsList[0].(map[string]interface{}); ok {
						if instanceId, exists := firstInstance["instanceId"]; exists {
							if instance, ok := instanceId.(string); ok {
								return instance
							}
						}
					}
				}
			}
		}
	}

	return ""
}

// extractIAMResource extracts IAM resource from operations
func extractIAMResource(params interface{}, eventName string) string {
	if params == nil {
		return ""
	}

	paramMap, ok := params.(map[string]interface{})
	if !ok {
		return ""
	}

	// Handle different IAM resource types based on event name
	switch {
	case strings.Contains(eventName, "User"):
		if userName, exists := paramMap["userName"]; exists {
			if user, ok := userName.(string); ok {
				return fmt.Sprintf("iam:user:%s", user)
			}
		}
	case strings.Contains(eventName, "Group"):
		if groupName, exists := paramMap["groupName"]; exists {
			if group, ok := groupName.(string); ok {
				return fmt.Sprintf("iam:group:%s", group)
			}
		}
	case strings.Contains(eventName, "Role"):
		if roleName, exists := paramMap["roleName"]; exists {
			if role, ok := roleName.(string); ok {
				return fmt.Sprintf("iam:role:%s", role)
			}
		}
	case strings.Contains(eventName, "Policy"):
		// Check policyName first (used by CreatePolicy, etc.)
		if policyName, exists := paramMap["policyName"]; exists {
			if policy, ok := policyName.(string); ok {
				return fmt.Sprintf("iam:policy:%s", policy)
			}
		}
		// Fall back to policyArn (used by DeletePolicy, GetPolicy, etc.)
		if policyArn, exists := paramMap["policyArn"]; exists {
			if arn, ok := policyArn.(string); ok {
				// Extract policy name from ARN: arn:aws:iam::123456789012:policy/PolicyName
				parts := strings.Split(arn, "/")
				if len(parts) >= 2 {
					return fmt.Sprintf("iam:policy:%s", parts[len(parts)-1])
				}
			}
		}
	}

	return ""
}

// extractCloudFormationStack extracts stack name from CloudFormation operations
func extractCloudFormationStack(params interface{}) string {
	if params == nil {
		return ""
	}

	paramMap, ok := params.(map[string]interface{})
	if !ok {
		return ""
	}

	// CloudFormation uses "stackName" in most operations
	if stackName, exists := paramMap["stackName"]; exists {
		if stack, ok := stackName.(string); ok {
			return stack
		}
	}

	// Some operations might use "stackId" (ARN format)
	if stackId, exists := paramMap["stackId"]; exists {
		if stack, ok := stackId.(string); ok {
			// If it's an ARN, extract the stack name
			// Format: arn:aws:cloudformation:region:account:stack/stack-name/guid
			if strings.HasPrefix(stack, "arn:aws:cloudformation:") {
				parts := strings.Split(stack, "/")
				if len(parts) >= 2 {
					return parts[1] // Stack name is the second part
				}
			}
			return stack
		}
	}

	return ""
}

// extractControlTowerResource extracts Control Tower resource identifiers
func extractControlTowerResource(params interface{}) string {
	if params == nil {
		return ""
	}

	paramMap, ok := params.(map[string]interface{})
	if !ok {
		return ""
	}

	// Managed account identifiers
	accountKeys := []string{"accountId", "managedAccountId", "targetAccountId"}
	for _, key := range accountKeys {
		if val, exists := paramMap[key]; exists {
			if acct, ok := val.(string); ok && acct != "" {
				return fmt.Sprintf("controltower:account:%s", acct)
			}
		}
	}

	// Landing zone identifiers
	lzKeys := []string{"landingZoneId", "landingZoneIdentifier"}
	for _, key := range lzKeys {
		if val, exists := paramMap[key]; exists {
			if lz, ok := val.(string); ok && lz != "" {
				return fmt.Sprintf("controltower:landing-zone:%s", lz)
			}
		}
	}

	// ARNs if provided
	arnKeys := []string{"controlTowerArn", "managedAccountArn"}
	for _, key := range arnKeys {
		if val, exists := paramMap[key]; exists {
			if arnStr, ok := val.(string); ok && arnStr != "" {
				return NormalizeResourceFromARN(arnStr)
			}
		}
	}

	return ""
}

// extractRDSResource extracts identifiers for RDS instances or clusters
func extractRDSResource(params interface{}) string {
	paramMap, ok := params.(map[string]interface{})
	if !ok || params == nil {
		return ""
	}

	keys := []string{"dBInstanceIdentifier", "dbInstanceIdentifier", "dBClusterIdentifier", "dbClusterIdentifier"}
	for _, key := range keys {
		if val, exists := paramMap[key]; exists {
			if name, ok := val.(string); ok && name != "" {
				return name
			}
		}
	}

	return ""
}

// extractECRRepository extracts ECR repository name
func extractECRRepository(params interface{}) string {
	paramMap, ok := params.(map[string]interface{})
	if !ok || params == nil {
		return ""
	}

	if repo, exists := paramMap["repositoryName"]; exists {
		if name, ok := repo.(string); ok && name != "" {
			return name
		}
	}

	return ""
}

// extractECSResource extracts ECS cluster/service/task identifiers
func extractECSResource(params interface{}) string {
	paramMap, ok := params.(map[string]interface{})
	if !ok || params == nil {
		return ""
	}

	if cluster, exists := paramMap["cluster"]; exists {
		if name, ok := cluster.(string); ok && name != "" {
			return fmt.Sprintf("ecs:cluster:%s", name)
		}
	}
	if service, exists := paramMap["service"]; exists {
		if name, ok := service.(string); ok && name != "" {
			return fmt.Sprintf("ecs:service:%s", name)
		}
	}
	if taskDef, exists := paramMap["taskDefinition"]; exists {
		if name, ok := taskDef.(string); ok && name != "" {
			return fmt.Sprintf("ecs:task-definition:%s", name)
		}
	}

	return ""
}

// extractSQSQueue extracts queue name (or last segment of queue URL)
func extractSQSQueue(params interface{}) string {
	paramMap, ok := params.(map[string]interface{})
	if !ok || params == nil {
		return ""
	}

	if queueName, exists := paramMap["queueName"]; exists {
		if q, ok := queueName.(string); ok && q != "" {
			return q
		}
	}
	if queueURL, exists := paramMap["queueUrl"]; exists {
		if urlStr, ok := queueURL.(string); ok && urlStr != "" {
			parts := strings.Split(urlStr, "/")
			if len(parts) > 0 {
				return parts[len(parts)-1]
			}
		}
	}

	return ""
}

// extractSNSTopic extracts SNS topic identifier
func extractSNSTopic(params interface{}) string {
	paramMap, ok := params.(map[string]interface{})
	if !ok || params == nil {
		return ""
	}

	if topicArn, exists := paramMap["topicArn"]; exists {
		if arnStr, ok := topicArn.(string); ok && arnStr != "" {
			return NormalizeResourceFromARN(arnStr)
		}
	}
	if name, exists := paramMap["name"]; exists {
		if topic, ok := name.(string); ok && topic != "" {
			return fmt.Sprintf("sns:topic:%s", topic)
		}
	}

	return ""
}

// extractKMSKey extracts KMS key or alias
func extractKMSKey(params interface{}) string {
	paramMap, ok := params.(map[string]interface{})
	if !ok || params == nil {
		return ""
	}

	if keyID, exists := paramMap["keyId"]; exists {
		if key, ok := keyID.(string); ok && key != "" {
			if strings.HasPrefix(key, "arn:aws:kms:") {
				return NormalizeResourceFromARN(key)
			}
			return fmt.Sprintf("kms:key:%s", key)
		}
	}
	if aliasName, exists := paramMap["aliasName"]; exists {
		if alias, ok := aliasName.(string); ok && alias != "" {
			return fmt.Sprintf("kms:alias:%s", alias)
		}
	}

	return ""
}

// extractSecret extracts Secrets Manager secret name/ARN
func extractSecret(params interface{}) string {
	paramMap, ok := params.(map[string]interface{})
	if !ok || params == nil {
		return ""
	}

	if secretID, exists := paramMap["secretId"]; exists {
		if sec, ok := secretID.(string); ok && sec != "" {
			if strings.HasPrefix(sec, "arn:aws:secretsmanager:") {
				return NormalizeResourceFromARN(sec)
			}
			return sec
		}
	}

	return ""
}

// extractLogGroup extracts CloudWatch Logs log group name
func extractLogGroup(params interface{}) string {
	paramMap, ok := params.(map[string]interface{})
	if !ok || params == nil {
		return ""
	}

	if group, exists := paramMap["logGroupName"]; exists {
		if name, ok := group.(string); ok && name != "" {
			return name
		}
	}

	return ""
}

// extractEventRule extracts EventBridge rule name
func extractEventRule(params interface{}) string {
	paramMap, ok := params.(map[string]interface{})
	if !ok || params == nil {
		return ""
	}

	if rule, exists := paramMap["name"]; exists {
		if r, ok := rule.(string); ok && r != "" {
			return r
		}
	}
	if ruleArn, exists := paramMap["ruleArn"]; exists {
		if arnStr, ok := ruleArn.(string); ok && arnStr != "" {
			return NormalizeResourceFromARN(arnStr)
		}
	}

	return ""
}

// extractStateMachine extracts Step Functions state machine name
func extractStateMachine(params interface{}) string {
	paramMap, ok := params.(map[string]interface{})
	if !ok || params == nil {
		return ""
	}

	if smArn, exists := paramMap["stateMachineArn"]; exists {
		if arnStr, ok := smArn.(string); ok && arnStr != "" {
			return NormalizeResourceFromARN(arnStr)
		}
	}
	if name, exists := paramMap["name"]; exists {
		if sm, ok := name.(string); ok && sm != "" {
			return sm
		}
	}

	return ""
}

// extractRestApi extracts API Gateway REST API id
func extractRestApi(params interface{}) string {
	paramMap, ok := params.(map[string]interface{})
	if !ok || params == nil {
		return ""
	}

	if apiID, exists := paramMap["restApiId"]; exists {
		if id, ok := apiID.(string); ok && id != "" {
			return id
		}
	}
	if apiID, exists := paramMap["apiId"]; exists {
		if id, ok := apiID.(string); ok && id != "" {
			return id
		}
	}

	return ""
}

// extractHostedZone extracts Route53 hosted zone id
func extractHostedZone(params interface{}) string {
	paramMap, ok := params.(map[string]interface{})
	if !ok || params == nil {
		return ""
	}

	if zoneID, exists := paramMap["hostedZoneId"]; exists {
		if id, ok := zoneID.(string); ok && id != "" {
			return id
		}
	}

	return ""
}

// extractCloudFrontDistribution extracts distribution id
func extractCloudFrontDistribution(params interface{}) string {
	paramMap, ok := params.(map[string]interface{})
	if !ok || params == nil {
		return ""
	}

	if distID, exists := paramMap["id"]; exists {
		if id, ok := distID.(string); ok && id != "" {
			return id
		}
	}

	return ""
}

// GetServiceDisplayName returns a friendly name for AWS services
func GetServiceDisplayName(eventSource string) string {
	serviceNames := map[string]string{
		"lambda.amazonaws.com":               "AWS Lambda",
		"s3.amazonaws.com":                   "Amazon S3",
		"dynamodb.amazonaws.com":             "Amazon DynamoDB",
		"ec2.amazonaws.com":                  "Amazon EC2",
		"iam.amazonaws.com":                  "AWS IAM",
		"sts.amazonaws.com":                  "AWS STS",
		"cloudtrail.amazonaws.com":           "AWS CloudTrail",
		"rds.amazonaws.com":                  "Amazon RDS",
		"cloudformation.amazonaws.com":       "AWS CloudFormation",
		"apigateway.amazonaws.com":           "Amazon API Gateway",
		"ssm.amazonaws.com":                  "AWS Systems Manager",
		"kms.amazonaws.com":                  "AWS KMS",
		"logs.amazonaws.com":                 "Amazon CloudWatch Logs",
		"monitoring.amazonaws.com":           "Amazon CloudWatch",
		"autoscaling.amazonaws.com":          "Amazon EC2 Auto Scaling",
		"elasticloadbalancing.amazonaws.com": "Elastic Load Balancing",
		"route53.amazonaws.com":              "Amazon Route 53",
		"sns.amazonaws.com":                  "Amazon SNS",
		"sqs.amazonaws.com":                  "Amazon SQS",
	}

	if displayName, exists := serviceNames[eventSource]; exists {
		return displayName
	}

	// Fallback: convert "lambda.amazonaws.com" to "Lambda"
	if strings.HasSuffix(eventSource, ".amazonaws.com") {
		service := strings.TrimSuffix(eventSource, ".amazonaws.com")
		if len(service) > 0 {
			return strings.Title(service)
		}
	}

	return eventSource
}

// GetServiceCategory returns the category for an AWS service
func GetServiceCategory(eventSource string) string {
	categories := map[string]string{
		"lambda.amazonaws.com":               "Compute",
		"s3.amazonaws.com":                   "Storage",
		"dynamodb.amazonaws.com":             "Database",
		"ec2.amazonaws.com":                  "Compute",
		"iam.amazonaws.com":                  "Security",
		"sts.amazonaws.com":                  "Security",
		"cloudtrail.amazonaws.com":           "Management",
		"rds.amazonaws.com":                  "Database",
		"cloudformation.amazonaws.com":       "Management",
		"apigateway.amazonaws.com":           "Networking",
		"ssm.amazonaws.com":                  "Management",
		"kms.amazonaws.com":                  "Security",
		"logs.amazonaws.com":                 "Management",
		"monitoring.amazonaws.com":           "Management",
		"autoscaling.amazonaws.com":          "Compute",
		"elasticloadbalancing.amazonaws.com": "Networking",
		"route53.amazonaws.com":              "Networking",
		"sns.amazonaws.com":                  "Messaging",
		"sqs.amazonaws.com":                  "Messaging",
	}

	if category, exists := categories[eventSource]; exists {
		return category
	}

	return "Other"
}
