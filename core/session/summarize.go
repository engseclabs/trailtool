package session

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	brtypes "github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"github.com/engseclabs/trailtool/core/models"
)

const SummaryModelID = "us.amazon.nova-lite-v1:0"

// SummaryResult is the generated summary and the metadata persisted with it.
type SummaryResult struct {
	Summary     string `json:"summary"`
	GeneratedAt string `json:"generated_at"`
	Model       string `json:"model"`
	TokensUsed  int    `json:"tokens_used"`
	InputDigest string `json:"input_digest"`
}

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

// SummarizeSession generates an AI summary of a session using Amazon Bedrock.
func SummarizeSession(ctx context.Context, session *models.Session) (*SummaryResult, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := bedrockruntime.NewFromConfig(cfg)

	userPrompt := buildSessionPrompt(session)
	complexity := calculateComplexity(session)
	maxTokens := getMaxTokensForComplexity(complexity)

	temp := float32(0.3)
	out, err := client.Converse(ctx, &bedrockruntime.ConverseInput{
		ModelId: aws.String(SummaryModelID),
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
		return nil, fmt.Errorf("bedrock invocation failed: %w", err)
	}

	summary := "(no content)"
	if out.Output == nil {
		return summaryResult(summary, out, userPrompt), nil
	}
	msgOutput, ok := out.Output.(*brtypes.ConverseOutputMemberMessage)
	if ok && len(msgOutput.Value.Content) > 0 {
		if textBlock, textOK := msgOutput.Value.Content[0].(*brtypes.ContentBlockMemberText); textOK {
			summary = textBlock.Value
		}
	}
	return summaryResult(summary, out, userPrompt), nil
}

func summaryResult(summary string, out *bedrockruntime.ConverseOutput, prompt string) *SummaryResult {
	tokensUsed := 0
	if out.Usage != nil {
		tokensUsed = int(aws.ToInt32(out.Usage.TotalTokens))
	}
	return &SummaryResult{
		Summary:     summary,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Model:       SummaryModelID,
		TokensUsed:  tokensUsed,
		InputDigest: summaryDigest(prompt),
	}
}

// SummaryInputDigest returns the digest for the current canonical prompt input.
func SummaryInputDigest(session *models.Session) string {
	return summaryDigest(buildSessionPrompt(session))
}

// SummaryIsCurrent reports whether the persisted summary describes the current
// session data. Historical summaries without a digest are stale.
func SummaryIsCurrent(session *models.Session) bool {
	return session.Summary != "" &&
		session.SummaryInputDigest != "" &&
		session.SummaryInputDigest == SummaryInputDigest(session)
}

func summaryDigest(prompt string) string {
	sum := sha256.Sum256([]byte(prompt))
	return fmt.Sprintf("%x", sum)
}

func buildSessionPrompt(session *models.Session) string {
	sessionType := session.DetectSessionType()

	data := map[string]interface{}{
		"schema_version":           1,
		"session_type":             sessionType,
		"event_counts":             session.EventCounts,
		"resource_accesses":        sortedResourceAccesses(session.ResourceAccesses),
		"denied_event_count":       session.DeniedEventCount,
		"denied_event_counts":      session.DeniedEventCounts,
		"denied_resource_accesses": sortedResourceAccesses(session.DeniedResourceAccesses),
		"denied_event_accesses":    sortedEventAccesses(session.DeniedEventAccesses),
		"clients":                  summarizeClients(session.Clients),
		"clickops_event_count":     session.ClickOpsEventCount,
		"clickops_event_counts":    session.ClickOpsEventCounts,
	}

	jsonData, _ := json.MarshalIndent(data, "", "  ")
	return string(jsonData)
}

func sortedResourceAccesses(accesses []models.ResourceAccess) []models.ResourceAccess {
	out := append([]models.ResourceAccess{}, accesses...)
	sort.Slice(out, func(i, j int) bool {
		left, right := out[i], out[j]
		if left.Service != right.Service {
			return left.Service < right.Service
		}
		if left.EventName != right.EventName {
			return left.EventName < right.EventName
		}
		if left.ResourceAccountID != right.ResourceAccountID {
			return left.ResourceAccountID < right.ResourceAccountID
		}
		if left.Resource != right.Resource {
			return left.Resource < right.Resource
		}
		if left.PolicyARN != right.PolicyARN {
			return left.PolicyARN < right.PolicyARN
		}
		if left.PolicyType != right.PolicyType {
			return left.PolicyType < right.PolicyType
		}
		return left.ErrorMessage < right.ErrorMessage
	})
	return out
}

func sortedEventAccesses(accesses []models.EventAccess) []models.EventAccess {
	out := append([]models.EventAccess{}, accesses...)
	sort.Slice(out, func(i, j int) bool {
		left, right := out[i], out[j]
		if left.Service != right.Service {
			return left.Service < right.Service
		}
		if left.EventName != right.EventName {
			return left.EventName < right.EventName
		}
		if left.PolicyARN != right.PolicyARN {
			return left.PolicyARN < right.PolicyARN
		}
		if left.PolicyType != right.PolicyType {
			return left.PolicyType < right.PolicyType
		}
		return left.ErrorMessage < right.ErrorMessage
	})
	return out
}

// summarizeClients projects the per-client aggregates down to the identity the
// summarizer cares about (name/version/platform + event count), dropping the
// bulky fields (raw samples, per-command maps) that would just spend tokens.
func summarizeClients(clients []models.ClientAggregate) []map[string]interface{} {
	sorted := append([]models.ClientAggregate{}, clients...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Key < sorted[j].Key
	})
	out := make([]map[string]interface{}, 0, len(sorted))
	for _, c := range sorted {
		entry := map[string]interface{}{
			"category": c.Category,
			"name":     c.Name,
			"events":   c.TotalEventCount,
		}
		if c.Version != "" {
			entry["version"] = c.Version
		}
		if c.OS != "" {
			entry["os"] = c.OS
		}
		out = append(out, entry)
	}
	return out
}

func calculateComplexity(s *models.Session) string {
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
