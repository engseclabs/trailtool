package session

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	brtypes "github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"github.com/engseclabs/trailtool/core/models"
)

// systemPrompt is the system prompt used for AI summarization (copied verbatim from SaaS)
const systemPrompt = `Summarize AWS session activity for a dashboard viewer. Focus on what resources were accessed or modified.

Output Format:
- Use markdown formatting (bullets with -, bold with **)
- If activity is cohesive (one workflow): write 1-2 sentence narrative
- If multiple disconnected activities: use markdown bullet list (- prefix, one per distinct resource/service)

Console Session Guidelines:
- For web console sessions, assume user is viewing pages/resources in the AWS Console
- When many resources of the same type are listed (e.g., 10+ IAM roles), collapse to "Reviewed multiple IAM roles in the console" or "Viewed IAM roles console page"
- Multiple read operations of the same resource type = viewing the console page for that service
- Only list specific resource names if there are ≤3 resources, or if resources were modified

Access Denied Events:
- If denied_event_count > 0, ALWAYS mention the AccessDenied errors prominently
- Example: "Attempted to modify IAM role permissions (AccessDenied - insufficient permissions)"
- Example: "Reviewed S3 buckets. Attempted to delete bucket **prod-data** (AccessDenied)"
- Treat AccessDenied as the most important signal - indicates intentional action that failed
- If policy_arn is present in denied_resource_accesses, mention the policy type (SCP, RCP, identity-based, permission-boundary)
- Example with policy: "Attempted to delete S3 bucket (AccessDenied by SCP: **DenyS3Delete**)"
- Example with policy: "Tried to modify IAM role (blocked by permission boundary)"
- Policy types: SCP (Service Control Policy from AWS Organizations), RCP (Resource Control Policy), identity-based, session, permission-boundary

Ignore Console Login Noise (DO NOT MENTION THESE IN SUMMARIES):
- SSO operations (sso:ListInstances, sso:DescribeRegisteredRegions, sso-directory:DescribeDirectory, iam:ListAccountAliases)
- Cost Explorer queries (ce:GetCostAndUsage, ce:GetCostForecast)
- Free tier checks (freetier:*, GetAccountPlanState, ListAccountActivities, GetFreeTierUsage, GetFreeTierAlertPreference)
- User Notifications (notifications:*, ListManagedNotificationEvents, GetFeatureOptInStatus, ListNotificationHubs, ListChannels)
- IAM Identity Center role access (accessing AWSReservedSSO_* roles is part of login, not user activity)
- These are automatic console framework calls - NOT user actions
- If session ONLY contains these events AND no denied_event_count: Output "Signed in to AWS Console" (no other details needed)

Examples:
GOOD (narrative): "Deployed CloudFormation stack **api-prod** with ~20 status checks. Retrieved 4 secrets from Secrets Manager during deployment."

GOOD (bullets for console session):
- Viewed IAM roles console page
- Reviewed Lambda function **process-events** configuration
- Updated S3 bucket **data-lake** permissions (PutBucketPolicy)

GOOD (console login only): "Signed in to AWS Console"

GOOD (bullets for CLI/SDK):
- Modified S3 bucket **data-lake** permissions (PutBucketPolicy)
- Updated IAM role **DataProcessorRole** trust policy

Prioritize (in order of importance):
1. **AccessDenied events** - ALWAYS mention these first if denied_event_count > 0
2. **Resources that were MODIFIED or CREATED** - Always mention these with specific names
3. **Write operations** - Put/Create/Update/Delete actions are more important than Get/List/Describe
4. Security-relevant changes (IAM, KMS, bucket policies, security groups) - especially privilege escalation or access control changes
5. Resource modifications with specific identifiers (use **bold** for names)
6. Read-only activity (viewing/listing) - only if there are no write operations or if viewing sensitive resources

Order of presentation:
- Start with what was changed/created (if any)
- Then mention what was viewed (only if relevant or no changes occurred)
- For read-only sessions: collapse many operations into "Reviewed X console page" or "Viewed multiple Y resources"

Omit: user identity, timestamps, role names, location (already shown in UI)

Output: Max 3 sentences or 4 bullets. Be direct and factual.`

// SummarizeSession generates an AI summary of a session using Amazon Bedrock
func SummarizeSession(ctx context.Context, session *models.SessionAggregated) (string, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := bedrockruntime.NewFromConfig(cfg)

	userPrompt := buildSessionPrompt(session)
	complexity := calculateComplexity(session)
	maxTokens := getMaxTokensForComplexity(complexity)

	modelID := "us.amazon.nova-lite-v1:0"

	temp := float32(0.3)
	out, err := client.Converse(ctx, &bedrockruntime.ConverseInput{
		ModelId: aws.String(modelID),
		Messages: []brtypes.Message{
			{
				Role:    brtypes.ConversationRoleUser,
				Content: []brtypes.ContentBlock{&brtypes.ContentBlockMemberText{Value: userPrompt}},
			},
		},
		System: []brtypes.SystemContentBlock{
			&brtypes.SystemContentBlockMemberText{Value: systemPrompt},
		},
		InferenceConfig: &brtypes.InferenceConfiguration{
			MaxTokens:   aws.Int32(int32(maxTokens)),
			Temperature: &temp,
		},
	})
	if err != nil {
		return "", fmt.Errorf("bedrock invocation failed: %w", err)
	}

	if out.Output == nil {
		return "(no content)", nil
	}
	msgOutput, ok := out.Output.(*brtypes.ConverseOutputMemberMessage)
	if !ok || len(msgOutput.Value.Content) == 0 {
		return "(no content)", nil
	}
	textBlock, ok := msgOutput.Value.Content[0].(*brtypes.ContentBlockMemberText)
	if !ok {
		return "(no content)", nil
	}
	return textBlock.Value, nil
}

func buildSessionPrompt(session *models.SessionAggregated) string {
	sessionType := session.DetectSessionType()

	data := map[string]interface{}{
		"session_type":       sessionType,
		"event_counts":       session.EventCounts,
		"resources_accessed": session.ResourcesAccessed,
		"user_agents":        session.UserAgents,
	}

	if session.DeniedEventCount > 0 {
		data["denied_event_count"] = session.DeniedEventCount
		data["denied_event_counts"] = session.DeniedEventCounts
		data["denied_resources_accessed"] = session.DeniedResourcesAccessed
	}

	jsonData, _ := json.MarshalIndent(data, "", "  ")
	return string(jsonData)
}

func calculateComplexity(s *models.SessionAggregated) string {
	uniqueActions := len(s.EventCounts)
	totalEvents := s.EventsCount
	if uniqueActions <= 5 && totalEvents < 20 {
		return "simple"
	}
	if uniqueActions <= 20 && totalEvents < 100 {
		return "moderate"
	}
	return "complex"
}

func getMaxTokensForComplexity(c string) int {
	switch c {
	case "simple":
		return 150
	case "moderate":
		return 300
	case "complex":
		return 500
	default:
		return 300
	}
}
