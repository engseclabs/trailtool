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
	PeopleTableName   = "trailtool-people-aggregated"
	SessionsTableName = "trailtool-sessions-aggregated"
	RolesTableName    = "trailtool-roles-aggregated"
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

// GetRoleByName finds a role by name (searches all roles for the customer)
func (s *Store) GetRoleByName(ctx context.Context, customerID, roleName string) (*models.Role, error) {
	roles, err := s.ListRoles(ctx, customerID)
	if err != nil {
		return nil, err
	}

	for i := range roles {
		if roles[i].Name == roleName || strings.Contains(roles[i].ARN, roleName) {
			return &roles[i], nil
		}
	}
	return nil, nil
}

// ListSessions returns sessions, optionally filtered by email and days
func (s *Store) ListSessions(ctx context.Context, customerID, email string, days int) ([]models.SessionAggregated, error) {
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

		if days > 0 {
			cutoff := time.Now().AddDate(0, 0, -days).Format(time.RFC3339)
			input.FilterExpression = aws.String("start_time >= :cutoff")
			input.ExpressionAttributeValues[":cutoff"] = &types.AttributeValueMemberS{Value: cutoff}
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

// GetSession fetches a session by start time
func (s *Store) GetSession(ctx context.Context, customerID, startTime string) (*models.SessionAggregated, error) {
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(SessionsTableName),
		Key: map[string]types.AttributeValue{
			"customerId":    &types.AttributeValueMemberS{Value: customerID},
			"session_start": &types.AttributeValueMemberS{Value: startTime},
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
