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
	return &Store{client: dynamodb.NewFromConfig(cfg)}, nil
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
	return &role, nil
}

// GetRoleByName finds a role by name (searches all roles for the customer).
// If accountID is non-empty, results are scoped to that account.
// Returns an error if multiple roles match (ambiguous name).
func (s *Store) GetRoleByName(ctx context.Context, customerID, roleName, accountID string) (*models.Role, error) {
	roles, err := s.ListRoles(ctx, customerID)
	if err != nil {
		return nil, err
	}

	var matches []models.Role
	for i := range roles {
		if roles[i].Name != roleName && !strings.Contains(roles[i].ARN, roleName) {
			continue
		}
		if accountID != "" && roles[i].AccountID != accountID {
			continue
		}
		matches = append(matches, roles[i])
	}

	switch len(matches) {
	case 0:
		return nil, nil
	case 1:
		return &matches[0], nil
	default:
		msg := fmt.Sprintf("role name %q is ambiguous — found %d matches:\n", roleName, len(matches))
		for _, m := range matches {
			msg += fmt.Sprintf("  %s (account %s)\n", m.ARN, m.AccountID)
		}
		msg += "Use the full ARN or --account to disambiguate."
		return nil, fmt.Errorf("%s", msg)
	}
}

// SessionFilter controls which sessions are returned by ListSessions
type SessionFilter struct {
	Days      int    // Filter to last N days (convenience; overridden by After if both set)
	Role      string // Substring match on role_name
	AccountID string // Exact match on account_id
	After     string // Only sessions starting at or after this time (ISO8601/RFC3339)
	Before    string // Only sessions starting before this time (ISO8601/RFC3339)
}

// filterValues renders the filter as a DynamoDB filter expression and merges
// its values into vals. Returns "" when no filters apply.
func (f SessionFilter) filterValues(vals map[string]types.AttributeValue) string {
	var filters []string

	// Time range: --after / --before take precedence over --days
	afterVal := f.After
	if afterVal == "" && f.Days > 0 {
		afterVal = time.Now().AddDate(0, 0, -f.Days).Format(time.RFC3339)
	}
	if afterVal != "" {
		filters = append(filters, "start_time >= :after")
		vals[":after"] = &types.AttributeValueMemberS{Value: afterVal}
	}
	if f.Before != "" {
		filters = append(filters, "start_time < :before")
		vals[":before"] = &types.AttributeValueMemberS{Value: f.Before}
	}
	if f.AccountID != "" {
		filters = append(filters, "account_id = :accountId")
		vals[":accountId"] = &types.AttributeValueMemberS{Value: f.AccountID}
	}
	if f.Role != "" {
		filters = append(filters, "contains(role_name, :role)")
		vals[":role"] = &types.AttributeValueMemberS{Value: f.Role}
	}
	return strings.Join(filters, " AND ")
}

// ResolvePersonKeys maps a --user value to person keys. A value containing "#"
// is already a person key; otherwise it's an email resolved through the people
// email_index — one email can map to several identities (offboard/rehire mints
// a new Identity Center userId; the same human may exist under idc# and email#
// keys across an Identity Center adoption).
func (s *Store) ResolvePersonKeys(ctx context.Context, customerID, user string) ([]string, error) {
	if strings.Contains(user, "#") {
		return []string{user}, nil
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
		sessions = append(sessions, page...)

		if result.LastEvaluatedKey == nil {
			break
		}
		lastKey = result.LastEvaluatedKey
	}
	return sessions, nil
}

// scanSessions returns sessions across every person via a filtered Scan — the
// accepted 1.0 approach for "recent sessions across everyone" (a customerId-
// keyed time GSI would hot-partition under load).
func (s *Store) scanSessions(ctx context.Context, customerID string, filter SessionFilter) ([]models.Session, error) {
	var sessions []models.Session
	var lastKey map[string]types.AttributeValue
	for {
		vals := map[string]types.AttributeValue{
			":cid": &types.AttributeValueMemberS{Value: customerID},
		}
		expr := "customerId = :cid"
		if f := filter.filterValues(vals); f != "" {
			expr += " AND " + f
		}
		result, err := s.client.Scan(ctx, &dynamodb.ScanInput{
			TableName:                 aws.String(SessionsTableName),
			FilterExpression:          aws.String(expr),
			ExpressionAttributeValues: vals,
			ExclusiveStartKey:         lastKey,
		})
		if err != nil {
			return nil, s.explainError(ctx, err, "scan sessions")
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
	return sessions, nil
}

// ListSessions returns sessions sorted by start time. With a user (email or
// person key), it queries each matching person's partition; the returned keys
// tell the caller how many identities matched (so the CLI can note a split).
// Without a user it scans the table.
func (s *Store) ListSessions(ctx context.Context, customerID, user string, filter SessionFilter) ([]models.Session, []string, error) {
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
		var err error
		sessions, err = s.scanSessions(ctx, customerID, filter)
		if err != nil {
			return nil, nil, err
		}
	}

	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].StartTime < sessions[j].StartTime
	})

	return sessions, personKeys, nil
}

// ResourceFilter controls which resources are returned by ListResources
type ResourceFilter struct {
	ClickOpsOnly     bool   // Only return resources with ClickOps activity
	ServiceType      string // Filter by service type prefix (e.g. "s3", "iam")
	StartTime        string // Only include ClickOps accesses after this time (ISO8601)
	EndTime          string // Only include ClickOps accesses before this time (ISO8601)
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

			// Time range filter on last_seen (applies to all resources)
			if filter.StartTime != "" && resource.LastSeen < filter.StartTime {
				continue
			}
			if filter.EndTime != "" && resource.LastSeen > filter.EndTime {
				continue
			}

			// ClickOps filters
			if filter.ClickOpsOnly {
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
				// Time range filter on ClickOps accesses
				if filter.StartTime != "" || filter.EndTime != "" {
					hasMatch := false
					for _, access := range resource.ClickOpsAccesses {
						if filter.StartTime != "" && access.AccessTime < filter.StartTime {
							continue
						}
						if filter.EndTime != "" && access.AccessTime > filter.EndTime {
							continue
						}
						hasMatch = true
						break
					}
					if !hasMatch {
						continue
					}
				}
			}

			resources = append(resources, resource)
		}

		if result.LastEvaluatedKey == nil {
			break
		}
		lastKey = result.LastEvaluatedKey
	}

	return resources, nil
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
	return &session, nil
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
	return sessions, nil
}
