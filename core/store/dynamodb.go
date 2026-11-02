package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/engseclabs/trailtool/core/models"
)

const (
	PeopleTableName    = "trailtool-people"
	SessionsTableName  = "trailtool-sessions"
	RolesTableName     = "trailtool-roles"
	ResourcesTableName = "trailtool-resources"
	AccountsTableName  = "trailtool-accounts"
	ServicesTableName  = "trailtool-services"

	// legacySessionsTableName identifies a pre-1.0 stack. Detection is by table
	// name only — no version markers are stored anywhere.
	legacySessionsTableName = "trailtool-sessions-aggregated"
)

// Store wraps the DynamoDB client
type Store struct {
	client *dynamodb.Client
}

// NewStore creates a new Store with default AWS config
func NewStore(ctx context.Context) (*Store, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}
	return NewStoreFromConfig(cfg), nil
}

// NewStoreFromConfig creates a Store from an already-loaded AWS config.
func NewStoreFromConfig(cfg aws.Config) *Store {
	return &Store{client: dynamodb.NewFromConfig(cfg)}
}

// explainError wraps a DynamoDB error: when a 1.0 table is missing because the
// deployed stack is still pre-1.0, say exactly that instead of surfacing a raw
// AWS error.
func (s *Store) explainError(ctx context.Context, err error, action string) error {
	var rnf *types.ResourceNotFoundException
	if errors.As(err, &rnf) {
		if _, derr := s.client.DescribeTable(ctx, &dynamodb.DescribeTableInput{
			TableName: aws.String(legacySessionsTableName),
		}); derr == nil {
			return fmt.Errorf(`this version of trailtool requires the 1.0 ingestor stack.
Redeploy it:  cd ingestor && make deploy
Note: redeploying deletes the pre-1.0 tables — existing aggregated
data is not migrated. History rebuilds from CloudTrail going forward`)
		}
	}
	return fmt.Errorf("failed to %s: %w", action, err)
}

// ListPeople returns all people for a customer
func (s *Store) ListPeople(ctx context.Context, customerID string) ([]models.Person, error) {
	var people []models.Person
	var lastKey map[string]types.AttributeValue

	for {
		input := &dynamodb.QueryInput{
			TableName:              aws.String(PeopleTableName),
			KeyConditionExpression: aws.String("customerId = :customerId"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":customerId": &types.AttributeValueMemberS{Value: customerID},
			},
			ExclusiveStartKey: lastKey,
		}

		result, err := s.client.Query(ctx, input)
		if err != nil {
			return nil, s.explainError(ctx, err, "query people")
		}

		var page []models.Person
		if err := attributevalue.UnmarshalListOfMaps(result.Items, &page); err != nil {
			return nil, fmt.Errorf("failed to unmarshal people: %w", err)
		}
		people = append(people, page...)

		if result.LastEvaluatedKey == nil {
			break
		}
		lastKey = result.LastEvaluatedKey
	}

	if err := s.enrichPeopleRelationshipCounts(ctx, customerID, people); err != nil {
		return nil, err
	}
	sortPeople(people)
	return people, nil
}

// ListRoles returns all roles for a customer
func (s *Store) ListRoles(ctx context.Context, customerID string) ([]models.Role, error) {
	var roles []models.Role
	var lastKey map[string]types.AttributeValue

	for {
		input := &dynamodb.QueryInput{
			TableName:              aws.String(RolesTableName),
			KeyConditionExpression: aws.String("customerId = :customerId"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":customerId": &types.AttributeValueMemberS{Value: customerID},
			},
			ExclusiveStartKey: lastKey,
		}

		result, err := s.client.Query(ctx, input)
		if err != nil {
			return nil, s.explainError(ctx, err, "query roles")
		}

		var page []models.Role
		if err := attributevalue.UnmarshalListOfMaps(result.Items, &page); err != nil {
			return nil, fmt.Errorf("failed to unmarshal roles: %w", err)
		}
		roles = append(roles, page...)

		if result.LastEvaluatedKey == nil {
			break
		}
		lastKey = result.LastEvaluatedKey
	}

	if err := s.enrichRoleRelationshipCounts(ctx, customerID, roles); err != nil {
		return nil, err
	}
	sortRoles(roles)
	return roles, nil
}

// GetRole fetches a role by ARN
func (s *Store) GetRole(ctx context.Context, customerID, roleARN string) (*models.Role, error) {
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(RolesTableName),
		Key: map[string]types.AttributeValue{
			"customerId": &types.AttributeValueMemberS{Value: customerID},
			"arn":        &types.AttributeValueMemberS{Value: roleARN},
		},
	})
	if err != nil {
		return nil, s.explainError(ctx, err, "get role")
	}
	if result.Item == nil {
		return nil, nil
	}

	var role models.Role
	if err := attributevalue.UnmarshalMap(result.Item, &role); err != nil {
		return nil, fmt.Errorf("failed to unmarshal role: %w", err)
	}
	role.RoleSelector = role.RoleID()
	return &role, nil
}

// FindRolesByRoleIDPrefix returns roles whose derived role ID starts with
// prefix. Role IDs are read-side selectors, so resolution scans the customer's
// role partition rather than requiring a derived-ID index.
func (s *Store) FindRolesByRoleIDPrefix(ctx context.Context, customerID, prefix string) ([]models.Role, error) {
	if prefix == "" {
		return nil, fmt.Errorf("empty role id prefix")
	}
	roles, err := s.ListRoles(ctx, customerID)
	if err != nil {
		return nil, err
	}
	return rolesByRoleIDPrefix(roles, prefix), nil
}

// GetRoleByName finds a role by name (searches all roles for the customer).
// If accountID is non-empty, results are scoped to that account.
// Returns an error if multiple roles match (ambiguous name).
func (s *Store) GetRoleByName(ctx context.Context, customerID, roleName, accountID string) (*models.Role, error) {
	roles, err := s.ListRoles(ctx, customerID)
	if err != nil {
		return nil, err
	}

	matches := rolesByExactName(roles, roleName, accountID)

	switch len(matches) {
	case 0:
		return nil, nil
	case 1:
		return &matches[0], nil
	default:
		msg := fmt.Sprintf("role name %q is ambiguous: found %d matches:\n", roleName, len(matches))
		for _, m := range matches {
			msg += fmt.Sprintf("  %s (account %s)\n", m.ARN, m.AccountID)
		}
		msg += "Use the role ID, full ARN, or --account to disambiguate."
		return nil, fmt.Errorf("%s", msg)
	}
}

// SessionFilter controls which sessions are returned by ListSessions
type SessionFilter struct {
	Days        int    // Filter to last N days
	RoleARN     string // Exact canonical role ARN
	AccountID   string // Exact AWS account ID
	After       string // Only sessions starting at or after this time (RFC3339)
	Before      string // Only sessions starting before this time (RFC3339)
	SessionType string // Exact session type: cli, web, agent, or login
	HasDenied   bool   // Only sessions with denied activity

	// Limit caps how many sessions an indexed path returns. The role, account,
	// and recency indexes apply it server-side. The per-user path ignores it and
	// relies on the client-side cap. 0 means no limit.
	Limit int
}

func (f SessionFilter) normalize() (SessionFilter, error) {
	if f.Days < 0 {
		return SessionFilter{}, fmt.Errorf("--days must be at least 0")
	}
	if f.Days > 0 && f.After != "" {
		return SessionFilter{}, fmt.Errorf("--days and --after are mutually exclusive")
	}
	if f.Days > 0 {
		f.After = time.Now().UTC().AddDate(0, 0, -f.Days).Format(time.RFC3339)
		f.Days = 0
	}
	var after, before time.Time
	var err error
	if f.After != "" {
		after, err = time.Parse(time.RFC3339, f.After)
		if err != nil {
			return SessionFilter{}, fmt.Errorf("invalid --after %q: use RFC3339", f.After)
		}
		f.After = after.UTC().Format(time.RFC3339)
	}
	if f.Before != "" {
		before, err = time.Parse(time.RFC3339, f.Before)
		if err != nil {
			return SessionFilter{}, fmt.Errorf("invalid --before %q: use RFC3339", f.Before)
		}
		f.Before = before.UTC().Format(time.RFC3339)
	}
	if !after.IsZero() && !before.IsZero() && !after.Before(before) {
		return SessionFilter{}, fmt.Errorf("--after must be earlier than --before")
	}
	switch f.SessionType {
	case "", "cli", "web", "agent", "login":
		return f, nil
	default:
		return SessionFilter{}, fmt.Errorf("invalid --type %q: use cli, web, agent, or login", f.SessionType)
	}
}

func (f SessionFilter) Validate() error {
	_, err := f.normalize()
	return err
}

// nonTimeFilter renders the stored predicates (everything that is not a
// start_time bound) as a filter expression. Indexed paths put the time
// bounds on the index key condition instead, so it needs the rest separately.
func (f SessionFilter) nonTimeFilter(vals map[string]types.AttributeValue) string {
	var filters []string
	if f.AccountID != "" {
		filters = append(filters, "account_id = :accountId")
		vals[":accountId"] = &types.AttributeValueMemberS{Value: f.AccountID}
	}
	if f.RoleARN != "" {
		filters = append(filters, "role_arn = :roleArn")
		vals[":roleArn"] = &types.AttributeValueMemberS{Value: f.RoleARN}
	}
	if f.SessionType != "" {
		filters = append(filters, "session_type = :sessionType")
		vals[":sessionType"] = &types.AttributeValueMemberS{Value: f.SessionType}
	}
	if f.HasDenied {
		filters = append(filters, "denied_event_count > :zero")
		vals[":zero"] = &types.AttributeValueMemberN{Value: "0"}
	}
	return strings.Join(filters, " AND ")
}

// filterValues renders the filter as a DynamoDB filter expression and merges
// its values into vals. Returns "" when no filters apply.
func (f SessionFilter) filterValues(vals map[string]types.AttributeValue) string {
	var filters []string

	// Time range. Validation prevents combining --days with --after.
	if f.After != "" {
		filters = append(filters, "start_time >= :after")
		vals[":after"] = &types.AttributeValueMemberS{Value: f.After}
	}
	if f.Before != "" {
		filters = append(filters, "start_time < :before")
		vals[":before"] = &types.AttributeValueMemberS{Value: f.Before}
	}
	if nt := f.nonTimeFilter(vals); nt != "" {
		filters = append(filters, nt)
	}
	return strings.Join(filters, " AND ")
}

// ResolvePersonKeys maps a --user value to person keys. It accepts the same PID
// prefix as people detail, an exact email, or a canonical person key. One email
// can map to several identities after an offboard/rehire or identity migration.
func (s *Store) ResolvePersonKeys(ctx context.Context, customerID, user string) ([]string, error) {
	if strings.Contains(user, "#") {
		return []string{user}, nil
	}
	if !strings.Contains(user, "@") {
		matches, err := s.FindPeopleByPIDPrefix(ctx, customerID, user)
		if err != nil {
			return nil, err
		}
		switch len(matches) {
		case 0:
			return nil, nil
		case 1:
			return []string{matches[0].PersonKey}, nil
		default:
			return nil, fmt.Errorf("person id %q is ambiguous: use a longer id", user)
		}
	}
	email := strings.ToLower(user)

	var keys []string
	var lastKey map[string]types.AttributeValue
	for {
		result, err := s.client.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(PeopleTableName),
			IndexName:              aws.String("email_index"),
			KeyConditionExpression: aws.String("customerId = :cid AND email = :email"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":cid":   &types.AttributeValueMemberS{Value: customerID},
				":email": &types.AttributeValueMemberS{Value: email},
			},
			ExclusiveStartKey: lastKey,
		})
		if err != nil {
			return nil, s.explainError(ctx, err, "resolve user email")
		}
		var page []models.Person
		if err := attributevalue.UnmarshalListOfMaps(result.Items, &page); err != nil {
			return nil, fmt.Errorf("failed to unmarshal people: %w", err)
		}
		for _, p := range page {
			keys = append(keys, p.PersonKey)
		}
		if result.LastEvaluatedKey == nil {
			break
		}
		lastKey = result.LastEvaluatedKey
	}
	sort.Strings(keys)
	return keys, nil
}

// querySessionPartition returns one person's sessions (a single-partition
// Query on pk = customerId#person_key), with filters applied server-side.
func (s *Store) querySessionPartition(ctx context.Context, customerID, personKey string, filter SessionFilter) ([]models.Session, error) {
	var sessions []models.Session
	var lastKey map[string]types.AttributeValue
	for {
		vals := map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: customerID + "#" + personKey},
		}
		input := &dynamodb.QueryInput{
			TableName:                 aws.String(SessionsTableName),
			KeyConditionExpression:    aws.String("pk = :pk"),
			ExpressionAttributeValues: vals,
			ExclusiveStartKey:         lastKey,
		}
		if expr := filter.filterValues(vals); expr != "" {
			input.FilterExpression = aws.String(expr)
		}

		result, err := s.client.Query(ctx, input)
		if err != nil {
			return nil, s.explainError(ctx, err, "query sessions")
		}
		var page []models.Session
		if err := attributevalue.UnmarshalListOfMaps(result.Items, &page); err != nil {
			return nil, fmt.Errorf("failed to unmarshal sessions: %w", err)
		}
		for i := range page {
			page[i].Normalize()
		}
		sessions = append(sessions, page...)

		if result.LastEvaluatedKey == nil {
			break
		}
		lastKey = result.LastEvaluatedKey
	}
	return sessions, nil
}

func sessionMatchesTimeBounds(session *models.Session, filter SessionFilter) bool {
	return (filter.After == "" || session.StartTime >= filter.After) &&
		(filter.Before == "" || session.StartTime < filter.Before)
}

type sessionIndexQuery struct {
	indexName     string
	partitionName string
	partitionKey  string
	roleIsKey     bool
	accountIsKey  bool
}

func indexedSessionExpressions(index sessionIndexQuery, filter SessionFilter) (keyCond, filterExpr string, vals map[string]types.AttributeValue) {
	keyCond = index.partitionName + " = :partition"
	vals = map[string]types.AttributeValue{
		":partition": &types.AttributeValueMemberS{Value: index.partitionKey},
	}
	switch {
	case filter.After != "" && filter.Before != "":
		keyCond += " AND start_time BETWEEN :after AND :before"
		vals[":after"] = &types.AttributeValueMemberS{Value: filter.After}
		vals[":before"] = &types.AttributeValueMemberS{Value: filter.Before}
	case filter.After != "":
		keyCond += " AND start_time >= :after"
		vals[":after"] = &types.AttributeValueMemberS{Value: filter.After}
	case filter.Before != "":
		keyCond += " AND start_time < :before"
		vals[":before"] = &types.AttributeValueMemberS{Value: filter.Before}
	}

	var filterParts []string
	remaining := filter
	if index.roleIsKey {
		remaining.RoleARN = ""
	}
	if index.accountIsKey {
		remaining.AccountID = ""
	}
	if expression := remaining.nonTimeFilter(vals); expression != "" {
		filterParts = append(filterParts, expression)
	}
	return keyCond, strings.Join(filterParts, " AND "), vals
}

func (s *Store) queryIndexedSessions(ctx context.Context, index sessionIndexQuery, filter SessionFilter) ([]models.Session, error) {
	keyCond, filterExpr, vals := indexedSessionExpressions(index, filter)
	var sessions []models.Session
	var lastKey map[string]types.AttributeValue
	for {
		input := &dynamodb.QueryInput{
			TableName:                 aws.String(SessionsTableName),
			IndexName:                 aws.String(index.indexName),
			KeyConditionExpression:    aws.String(keyCond),
			ExpressionAttributeValues: vals,
			ScanIndexForward:          aws.Bool(false),
			ExclusiveStartKey:         lastKey,
		}
		if filterExpr != "" {
			input.FilterExpression = aws.String(filterExpr)
		}
		if filter.Limit > 0 {
			input.Limit = aws.Int32(int32(filter.Limit))
		}

		result, err := s.client.Query(ctx, input)
		if err != nil {
			return nil, s.explainError(ctx, err, "query session index")
		}
		var page []models.Session
		if err := attributevalue.UnmarshalListOfMaps(result.Items, &page); err != nil {
			return nil, fmt.Errorf("failed to unmarshal sessions: %w", err)
		}
		for i := range page {
			page[i].Normalize()
			if sessionMatchesTimeBounds(&page[i], filter) {
				sessions = append(sessions, page[i])
			}
		}
		if filter.Limit > 0 && len(sessions) >= filter.Limit {
			sessions = sessions[:filter.Limit]
			break
		}
		if result.LastEvaluatedKey == nil {
			break
		}
		lastKey = result.LastEvaluatedKey
	}
	return sessions, nil
}

func sessionIndexForFilter(customerID string, filter SessionFilter) sessionIndexQuery {
	if filter.RoleARN != "" {
		return sessionIndexQuery{
			indexName:     "role_index",
			partitionName: "role_key",
			partitionKey:  customerID + "#" + filter.RoleARN,
			roleIsKey:     true,
		}
	}
	if filter.AccountID != "" {
		return sessionIndexQuery{
			indexName:     "account_index",
			partitionName: "account_key",
			partitionKey:  customerID + "#" + filter.AccountID,
			accountIsKey:  true,
		}
	}
	return sessionIndexQuery{
		indexName:     "recency_index",
		partitionName: "customerId",
		partitionKey:  customerID,
	}
}

// ListSessions returns sessions sorted by start time. With a user (email or
// person key), it queries each matching person's partition; the returned keys
// tell the caller how many identities matched (so the CLI can note a split).
// Role and account filters use their start_time-ordered indexes. The remaining
// cross-everyone path uses recency_index.
func (s *Store) ListSessions(ctx context.Context, customerID, user string, filter SessionFilter) ([]models.Session, []string, error) {
	normalized, err := filter.normalize()
	if err != nil {
		return nil, nil, err
	}
	filter = normalized
	var sessions []models.Session
	var personKeys []string

	if user != "" {
		keys, err := s.ResolvePersonKeys(ctx, customerID, user)
		if err != nil {
			return nil, nil, err
		}
		personKeys = keys
		for _, key := range keys {
			page, err := s.querySessionPartition(ctx, customerID, key, filter)
			if err != nil {
				return nil, nil, err
			}
			sessions = append(sessions, page...)
		}
	} else {
		index := sessionIndexForFilter(customerID, filter)
		var err error
		sessions, err = s.queryIndexedSessions(ctx, index, filter)
		if err != nil {
			return nil, nil, err
		}
	}

	models.SortSessionsForList(sessions, false)
	return sessions, personKeys, nil
}

// SaveSessionSummary persists the generated summary metadata without replacing
// activity fields that the ingestor may be updating concurrently.
func (s *Store) SaveSessionSummary(ctx context.Context, customerID string, session *models.Session) error {
	input, err := sessionSummaryUpdateInput(customerID, session)
	if err != nil {
		return err
	}
	if _, err := s.client.UpdateItem(ctx, input); err != nil {
		return s.explainError(ctx, err, "save session summary")
	}
	return nil
}

func sessionSummaryUpdateInput(customerID string, session *models.Session) (*dynamodb.UpdateItemInput, error) {
	if session.PersonKey == "" || session.SK == "" {
		return nil, fmt.Errorf("session is missing its storage key")
	}
	pk := session.PK
	if pk == "" {
		pk = customerID + "#" + session.PersonKey
	}
	values, err := attributevalue.MarshalMap(map[string]interface{}{
		":summary":      session.Summary,
		":generated_at": session.SummaryGeneratedAt,
		":model":        session.SummaryModel,
		":tokens_used":  session.SummaryTokensUsed,
		":input_digest": session.SummaryInputDigest,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal session summary: %w", err)
	}
	return &dynamodb.UpdateItemInput{
		TableName: aws.String(SessionsTableName),
		Key: map[string]types.AttributeValue{
			"pk": &types.AttributeValueMemberS{Value: pk},
			"sk": &types.AttributeValueMemberS{Value: session.SK},
		},
		UpdateExpression: aws.String(
			"SET #summary = :summary, #generated_at = :generated_at, #model = :model, #tokens_used = :tokens_used, #input_digest = :input_digest",
		),
		ExpressionAttributeNames: map[string]string{
			"#summary":      "summary",
			"#generated_at": "summary_generated_at",
			"#model":        "summary_model",
			"#tokens_used":  "summary_tokens_used",
			"#input_digest": "summary_input_digest",
		},
		ExpressionAttributeValues: values,
	}, nil
}

// ResourceFilter controls which resources are returned by ListResources
type ResourceFilter struct {
	ClickOpsOnly     bool   // Only return resources with ClickOps activity
	ServiceType      string // Filter by service type prefix (e.g. "s3", "iam")
	StartDate        string // Only include resources last seen on or after this date (YYYY-MM-DD)
	EndDate          string // Only include resources last seen before this date (YYYY-MM-DD)
	StartTime        string // Only include ClickOps accesses at or after this time (RFC3339)
	EndTime          string // Only include ClickOps accesses before this time (RFC3339)
	MinClickOpsCount int    // Minimum ClickOps event count (only applies when ClickOpsOnly=true)
}

// ListResources returns resources for a customer, with optional filters
func (s *Store) ListResources(ctx context.Context, customerID string, filter ResourceFilter) ([]models.Resource, error) {
	var resources []models.Resource
	var lastKey map[string]types.AttributeValue

	for {
		input := &dynamodb.QueryInput{
			TableName:              aws.String(ResourcesTableName),
			KeyConditionExpression: aws.String("customerId = :customerId"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":customerId": &types.AttributeValueMemberS{Value: customerID},
			},
			ExclusiveStartKey: lastKey,
		}

		result, err := s.client.Query(ctx, input)
		if err != nil {
			return nil, s.explainError(ctx, err, "query resources")
		}

		for _, item := range result.Items {
			var resource models.Resource
			if err := attributevalue.UnmarshalMap(item, &resource); err != nil {
				continue
			}

			// Filter by service type
			if filter.ServiceType != "" && !strings.HasPrefix(resource.Type, filter.ServiceType+":") {
				continue
			}

			// Time range filter on last_seen (applies to all resources).
			// Compare the date component so legacy date-only values and current
			// RFC3339 timestamps have identical inclusive-day semantics.
			if !resourceSeenInDateRange(resource.LastSeen, filter.StartDate, filter.EndDate) {
				continue
			}

			// ClickOps filters
			if filter.ClickOpsOnly {
				filterClickOpsActivity(&resource, filter.StartTime, filter.EndTime)
				if len(resource.ClickOpsAccesses) == 0 {
					continue
				}
				minCount := filter.MinClickOpsCount
				if minCount < 1 {
					minCount = 1
				}
				if resource.ClickOpsCount < minCount {
					continue
				}
			}

			resources = append(resources, resource)
		}

		if result.LastEvaluatedKey == nil {
			break
		}
		lastKey = result.LastEvaluatedKey
	}

	if err := s.enrichResourceRelationshipCounts(ctx, customerID, resources); err != nil {
		return nil, err
	}
	sortResources(resources)
	return resources, nil
}

func resourceSeenInDateRange(lastSeen, startDate, endDate string) bool {
	seenDate := lastSeen
	if len(seenDate) >= len("YYYY-MM-DD") {
		seenDate = seenDate[:len("YYYY-MM-DD")]
	}
	return (startDate == "" || seenDate >= startDate) &&
		(endDate == "" || seenDate <= endDate)
}

// filterClickOpsActivity makes the time-windowed ClickOps view internally
// consistent: rows and their displayed count describe the same period.
func filterClickOpsActivity(resource *models.Resource, startTime, endTime string) {
	filtered := make([]models.ClickOpsAccess, 0, len(resource.ClickOpsAccesses))
	count := 0
	for _, access := range resource.ClickOpsAccesses {
		if startTime != "" && access.AccessTime < startTime {
			continue
		}
		if endTime != "" && access.AccessTime >= endTime {
			continue
		}
		filtered = append(filtered, access)
		count += access.EventCount
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].AccessTime != filtered[j].AccessTime {
			return filtered[i].AccessTime > filtered[j].AccessTime
		}
		if filtered[i].SessionRef != filtered[j].SessionRef {
			return filtered[i].SessionRef < filtered[j].SessionRef
		}
		return filtered[i].EventName < filtered[j].EventName
	})
	resource.ClickOpsAccesses = filtered
	resource.ClickOpsCount = count
}

// ListAccounts returns all accounts for a customer
func (s *Store) ListAccounts(ctx context.Context, customerID string) ([]models.Account, error) {
	var accounts []models.Account
	var lastKey map[string]types.AttributeValue

	for {
		input := &dynamodb.QueryInput{
			TableName:              aws.String(AccountsTableName),
			KeyConditionExpression: aws.String("customerId = :customerId"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":customerId": &types.AttributeValueMemberS{Value: customerID},
			},
			ExclusiveStartKey: lastKey,
		}

		result, err := s.client.Query(ctx, input)
		if err != nil {
			return nil, s.explainError(ctx, err, "query accounts")
		}

		var page []models.Account
		if err := attributevalue.UnmarshalListOfMaps(result.Items, &page); err != nil {
			return nil, fmt.Errorf("failed to unmarshal accounts: %w", err)
		}
		accounts = append(accounts, page...)

		if result.LastEvaluatedKey == nil {
			break
		}
		lastKey = result.LastEvaluatedKey
	}

	if err := s.enrichAccountRelationshipCounts(ctx, customerID, accounts); err != nil {
		return nil, err
	}
	sortAccounts(accounts)
	return accounts, nil
}

// GetAccount fetches an account by account ID
func (s *Store) GetAccount(ctx context.Context, customerID, accountID string) (*models.Account, error) {
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(AccountsTableName),
		Key: map[string]types.AttributeValue{
			"customerId": &types.AttributeValueMemberS{Value: customerID},
			"account_id": &types.AttributeValueMemberS{Value: accountID},
		},
	})
	if err != nil {
		return nil, s.explainError(ctx, err, "get account")
	}
	if result.Item == nil {
		return nil, nil
	}

	var account models.Account
	if err := attributevalue.UnmarshalMap(result.Item, &account); err != nil {
		return nil, fmt.Errorf("failed to unmarshal account: %w", err)
	}
	return &account, nil
}

// ListServices returns all services for a customer
func (s *Store) ListServices(ctx context.Context, customerID string) ([]models.Service, error) {
	var services []models.Service
	var lastKey map[string]types.AttributeValue

	for {
		input := &dynamodb.QueryInput{
			TableName:              aws.String(ServicesTableName),
			KeyConditionExpression: aws.String("customerId = :customerId"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":customerId": &types.AttributeValueMemberS{Value: customerID},
			},
			ExclusiveStartKey: lastKey,
		}

		result, err := s.client.Query(ctx, input)
		if err != nil {
			return nil, s.explainError(ctx, err, "query services")
		}

		var page []models.Service
		if err := attributevalue.UnmarshalListOfMaps(result.Items, &page); err != nil {
			return nil, fmt.Errorf("failed to unmarshal services: %w", err)
		}
		services = append(services, page...)

		if result.LastEvaluatedKey == nil {
			break
		}
		lastKey = result.LastEvaluatedKey
	}

	if err := s.enrichServiceRelationshipCounts(ctx, customerID, services); err != nil {
		return nil, err
	}
	sortServices(services)
	return services, nil
}

// GetService fetches a service by event source
func (s *Store) GetService(ctx context.Context, customerID, eventSource string) (*models.Service, error) {
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(ServicesTableName),
		Key: map[string]types.AttributeValue{
			"customerId":   &types.AttributeValueMemberS{Value: customerID},
			"event_source": &types.AttributeValueMemberS{Value: eventSource},
		},
	})
	if err != nil {
		return nil, s.explainError(ctx, err, "get service")
	}
	if result.Item == nil {
		return nil, nil
	}

	var service models.Service
	if err := attributevalue.UnmarshalMap(result.Item, &service); err != nil {
		return nil, fmt.Errorf("failed to unmarshal service: %w", err)
	}
	return &service, nil
}

// GetSessionByRef fetches a session by its stable ref ("person_key|sk") — the
// format chained/login/MCP attribution fields use to point at other sessions.
func (s *Store) GetSessionByRef(ctx context.Context, customerID, ref string) (*models.Session, error) {
	personKey, sk, ok := strings.Cut(ref, "|")
	if !ok || personKey == "" || sk == "" {
		return nil, fmt.Errorf("invalid session ref %q (want person_key|sk)", ref)
	}
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(SessionsTableName),
		Key: map[string]types.AttributeValue{
			"pk": &types.AttributeValueMemberS{Value: customerID + "#" + personKey},
			"sk": &types.AttributeValueMemberS{Value: sk},
		},
	})
	if err != nil {
		return nil, s.explainError(ctx, err, "get session")
	}
	if len(result.Item) == 0 {
		return nil, nil
	}

	var session models.Session
	if err := attributevalue.UnmarshalMap(result.Item, &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}
	return session.Normalize(), nil
}

// FindSessionsBySidPrefix returns every session whose sid starts with prefix,
// via a begins_with Query on the sid_index GSI (partition customerId, sort sid).
// Callers pass a short user-typed prefix; 0 matches means not found, 1 is the
// hit, and >1 is an ambiguous prefix the caller should ask to lengthen. Results
// are ordered by sid (the GSI sort key).
func (s *Store) FindSessionsBySidPrefix(ctx context.Context, customerID, prefix string) ([]models.Session, error) {
	if prefix == "" {
		return nil, fmt.Errorf("empty session id prefix")
	}
	var sessions []models.Session
	var lastKey map[string]types.AttributeValue
	for {
		result, err := s.client.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(SessionsTableName),
			IndexName:              aws.String("sid_index"),
			KeyConditionExpression: aws.String("customerId = :cid AND begins_with(sid, :sid)"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":cid": &types.AttributeValueMemberS{Value: customerID},
				":sid": &types.AttributeValueMemberS{Value: prefix},
			},
			ExclusiveStartKey: lastKey,
		})
		if err != nil {
			return nil, s.explainError(ctx, err, "query sessions by sid")
		}
		var page []models.Session
		if err := attributevalue.UnmarshalListOfMaps(result.Items, &page); err != nil {
			return nil, fmt.Errorf("failed to unmarshal sessions: %w", err)
		}
		sessions = append(sessions, page...)
		if result.LastEvaluatedKey == nil {
			break
		}
		lastKey = result.LastEvaluatedKey
	}
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].Sid < sessions[j].Sid
	})
	return sessions, nil
}

func sortPeople(people []models.Person) {
	for i := range people {
		people[i].Pid = people[i].PID()
	}
	sort.Slice(people, func(i, j int) bool {
		if people[i].LastSeen != people[j].LastSeen {
			return people[i].LastSeen > people[j].LastSeen
		}
		return people[i].PersonKey < people[j].PersonKey
	})
}

func sortRoles(roles []models.Role) {
	for i := range roles {
		roles[i].RoleSelector = roles[i].RoleID()
	}
	sort.Slice(roles, func(i, j int) bool {
		if roles[i].LastSeen != roles[j].LastSeen {
			return roles[i].LastSeen > roles[j].LastSeen
		}
		return roles[i].ARN < roles[j].ARN
	})
}

func rolesByRoleIDPrefix(roles []models.Role, prefix string) []models.Role {
	var matches []models.Role
	for i := range roles {
		if strings.HasPrefix(roles[i].RoleID(), prefix) {
			matches = append(matches, roles[i])
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].RoleID() < matches[j].RoleID()
	})
	return matches
}

func rolesByExactName(roles []models.Role, roleName, accountID string) []models.Role {
	var matches []models.Role
	for i := range roles {
		if roles[i].Name != roleName {
			continue
		}
		if accountID != "" && roles[i].AccountID != accountID {
			continue
		}
		matches = append(matches, roles[i])
	}
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].ARN < matches[j].ARN
	})
	return matches
}

func sortResources(resources []models.Resource) {
	for i := range resources {
		resources[i].Rid = resources[i].RID()
	}
	sort.Slice(resources, func(i, j int) bool {
		if resources[i].LastSeen != resources[j].LastSeen {
			return resources[i].LastSeen > resources[j].LastSeen
		}
		if resources[i].AccountID != resources[j].AccountID {
			return resources[i].AccountID < resources[j].AccountID
		}
		return resources[i].Identifier < resources[j].Identifier
	})
}

func sortAccounts(accounts []models.Account) {
	sort.Slice(accounts, func(i, j int) bool {
		if accounts[i].LastSeen != accounts[j].LastSeen {
			return accounts[i].LastSeen > accounts[j].LastSeen
		}
		return accounts[i].AccountID < accounts[j].AccountID
	})
}

func sortServices(services []models.Service) {
	sort.Slice(services, func(i, j int) bool {
		if services[i].LastSeen != services[j].LastSeen {
			return services[i].LastSeen > services[j].LastSeen
		}
		return services[i].EventSource < services[j].EventSource
	})
}
