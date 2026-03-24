package store

import (
	"context"
	"fmt"
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
	PeopleTableName    = "trailtool-people-aggregated"
	SessionsTableName  = "trailtool-sessions-aggregated"
	RolesTableName     = "trailtool-roles-aggregated"
	ResourcesTableName = "trailtool-resources-aggregated"
	AccountsTableName  = "trailtool-accounts-aggregated"
	ServicesTableName  = "trailtool-services-aggregated"
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
			return nil, fmt.Errorf("failed to query people: %w", err)
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
			return nil, fmt.Errorf("failed to query roles: %w", err)
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
		return nil, fmt.Errorf("failed to get role: %w", err)
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

// ListSessions returns sessions, optionally filtered by email and additional filters
func (s *Store) ListSessions(ctx context.Context, customerID, email string, filter SessionFilter) ([]models.SessionAggregated, error) {
	var sessions []models.SessionAggregated
	var lastKey map[string]types.AttributeValue

	for {
		var input *dynamodb.QueryInput

		if email != "" {
			input = &dynamodb.QueryInput{
				TableName:              aws.String(SessionsTableName),
				IndexName:              aws.String("person_email_index"),
				KeyConditionExpression: aws.String("customerId = :customerId AND person_email = :email"),
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":customerId": &types.AttributeValueMemberS{Value: customerID},
					":email":      &types.AttributeValueMemberS{Value: email},
				},
				ExclusiveStartKey: lastKey,
			}
		} else {
			input = &dynamodb.QueryInput{
				TableName:              aws.String(SessionsTableName),
				KeyConditionExpression: aws.String("customerId = :customerId"),
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":customerId": &types.AttributeValueMemberS{Value: customerID},
				},
				ExclusiveStartKey: lastKey,
			}
		}

		// Build filter expressions
		var filters []string

		// Time range: --after / --before take precedence over --days
		afterVal := filter.After
		if afterVal == "" && filter.Days > 0 {
			afterVal = time.Now().AddDate(0, 0, -filter.Days).Format(time.RFC3339)
		}
		if afterVal != "" {
			filters = append(filters, "start_time >= :after")
			input.ExpressionAttributeValues[":after"] = &types.AttributeValueMemberS{Value: afterVal}
		}
		if filter.Before != "" {
			filters = append(filters, "start_time < :before")
			input.ExpressionAttributeValues[":before"] = &types.AttributeValueMemberS{Value: filter.Before}
		}

		if filter.AccountID != "" {
			filters = append(filters, "account_id = :accountId")
			input.ExpressionAttributeValues[":accountId"] = &types.AttributeValueMemberS{Value: filter.AccountID}
		}

		if filter.Role != "" {
			filters = append(filters, "contains(role_name, :role)")
			input.ExpressionAttributeValues[":role"] = &types.AttributeValueMemberS{Value: filter.Role}
		}

		if len(filters) > 0 {
			expr := filters[0]
			for _, f := range filters[1:] {
				expr += " AND " + f
			}
			input.FilterExpression = aws.String(expr)
		}

		result, err := s.client.Query(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("failed to query sessions: %w", err)
		}

		var page []models.SessionAggregated
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
			return nil, fmt.Errorf("failed to query resources: %w", err)
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
			return nil, fmt.Errorf("failed to query accounts: %w", err)
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
		return nil, fmt.Errorf("failed to get account: %w", err)
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
			return nil, fmt.Errorf("failed to query services: %w", err)
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
		return nil, fmt.Errorf("failed to get service: %w", err)
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

// GetSession fetches a session by its composite sort key (startTime#sessionID)
func (s *Store) GetSession(ctx context.Context, customerID, sessionStart string) (*models.SessionAggregated, error) {
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(SessionsTableName),
		Key: map[string]types.AttributeValue{
			"customerId":    &types.AttributeValueMemberS{Value: customerID},
			"session_start": &types.AttributeValueMemberS{Value: sessionStart},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}
	if result.Item == nil {
		return nil, nil
	}

	var session models.SessionAggregated
	if err := attributevalue.UnmarshalMap(result.Item, &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}
	return &session, nil
}
