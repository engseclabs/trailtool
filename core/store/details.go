package store

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/engseclabs/trailtool/core/models"
)

const (
	RelationsTableName = "trailtool-relations"

	RelationKindPerson   = "person"
	RelationKindSession  = "session"
	RelationKindAccount  = "account"
	RelationKindRole     = "role"
	RelationKindService  = "service"
	RelationKindResource = "resource"
)

type nounRelation struct {
	RelatedKind string `dynamodbav:"related_kind"`
	RelatedID   string `dynamodbav:"related_id"`
	FirstSeen   string `dynamodbav:"first_seen"`
	LastSeen    string `dynamodbav:"last_seen"`
}

// GetPerson fetches a person by canonical person key.
func (s *Store) GetPerson(ctx context.Context, customerID, personKey string) (*models.Person, error) {
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(PeopleTableName),
		Key: map[string]types.AttributeValue{
			"customerId": &types.AttributeValueMemberS{Value: customerID},
			"person_key": &types.AttributeValueMemberS{Value: personKey},
		},
	})
	if err != nil {
		return nil, s.explainError(ctx, err, "get person")
	}
	if len(result.Item) == 0 {
		return nil, nil
	}

	var person models.Person
	if err := attributevalue.UnmarshalMap(result.Item, &person); err != nil {
		return nil, fmt.Errorf("failed to unmarshal person: %w", err)
	}
	person.Pid = person.PID()
	return &person, nil
}

// GetResource fetches a resource by its account-qualified resource key.
func (s *Store) GetResource(ctx context.Context, customerID, resourceKey string) (*models.Resource, error) {
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(ResourcesTableName),
		Key: map[string]types.AttributeValue{
			"customerId":   &types.AttributeValueMemberS{Value: customerID},
			"resource_key": &types.AttributeValueMemberS{Value: resourceKey},
		},
	})
	if err != nil {
		return nil, s.explainError(ctx, err, "get resource")
	}
	if len(result.Item) == 0 {
		return nil, nil
	}

	var resource models.Resource
	if err := attributevalue.UnmarshalMap(result.Item, &resource); err != nil {
		return nil, fmt.Errorf("failed to unmarshal resource: %w", err)
	}
	resource.Rid = resource.RID()
	return &resource, nil
}

// FindPeopleByPIDPrefix performs the customer-partition projection query
// described by the selector contract, then fetches the matching records.
func (s *Store) FindPeopleByPIDPrefix(ctx context.Context, customerID, prefix string) ([]models.Person, error) {
	if prefix == "" {
		return nil, fmt.Errorf("empty person id prefix")
	}

	var projected []models.Person
	var lastKey map[string]types.AttributeValue
	for {
		result, err := s.client.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(PeopleTableName),
			KeyConditionExpression: aws.String("customerId = :customerId"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":customerId": &types.AttributeValueMemberS{Value: customerID},
			},
			ProjectionExpression: aws.String("#personKey"),
			ExpressionAttributeNames: map[string]string{
				"#personKey": "person_key",
			},
			ExclusiveStartKey: lastKey,
		})
		if err != nil {
			return nil, s.explainError(ctx, err, "query people by pid")
		}

		var page []models.Person
		if err := attributevalue.UnmarshalListOfMaps(result.Items, &page); err != nil {
			return nil, fmt.Errorf("failed to unmarshal people: %w", err)
		}
		projected = append(projected, page...)
		if result.LastEvaluatedKey == nil {
			break
		}
		lastKey = result.LastEvaluatedKey
	}

	projected = peopleByPIDPrefix(projected, prefix)
	matches := make([]models.Person, 0, len(projected))
	for i := range projected {
		person, err := s.GetPerson(ctx, customerID, projected[i].PersonKey)
		if err != nil {
			return nil, err
		}
		if person != nil {
			matches = append(matches, *person)
		}
	}
	return matches, nil
}

// FindResourcesByRIDPrefix performs a paginated projection query, then fetches
// the matching account-qualified resource records.
func (s *Store) FindResourcesByRIDPrefix(ctx context.Context, customerID, prefix string) ([]models.Resource, error) {
	if prefix == "" {
		return nil, fmt.Errorf("empty resource id prefix")
	}

	var projected []models.Resource
	var lastKey map[string]types.AttributeValue
	for {
		result, err := s.client.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(ResourcesTableName),
			KeyConditionExpression: aws.String("customerId = :customerId"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":customerId": &types.AttributeValueMemberS{Value: customerID},
			},
			ProjectionExpression: aws.String("#resourceKey, #accountID, #identifier"),
			ExpressionAttributeNames: map[string]string{
				"#resourceKey": "resource_key",
				"#accountID":   "account_id",
				"#identifier":  "identifier",
			},
			ExclusiveStartKey: lastKey,
		})
		if err != nil {
			return nil, s.explainError(ctx, err, "query resources by rid")
		}

		var page []models.Resource
		if err := attributevalue.UnmarshalListOfMaps(result.Items, &page); err != nil {
			return nil, fmt.Errorf("failed to unmarshal resources: %w", err)
		}
		projected = append(projected, page...)
		if result.LastEvaluatedKey == nil {
			break
		}
		lastKey = result.LastEvaluatedKey
	}

	projected = resourcesByRIDPrefix(projected, prefix)
	matches := make([]models.Resource, 0, len(projected))
	for i := range projected {
		resource, err := s.GetResource(ctx, customerID, projected[i].ResourceKey)
		if err != nil {
			return nil, err
		}
		if resource != nil {
			matches = append(matches, *resource)
		}
	}
	return matches, nil
}

func peopleByPIDPrefix(people []models.Person, prefix string) []models.Person {
	matches := make([]models.Person, 0)
	for i := range people {
		people[i].Pid = people[i].PID()
		if strings.HasPrefix(people[i].Pid, prefix) {
			matches = append(matches, people[i])
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Pid < matches[j].Pid
	})
	return matches
}

func resourcesByRIDPrefix(resources []models.Resource, prefix string) []models.Resource {
	matches := make([]models.Resource, 0)
	for i := range resources {
		resources[i].Rid = resources[i].RID()
		if strings.HasPrefix(resources[i].Rid, prefix) {
			matches = append(matches, resources[i])
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Rid < matches[j].Rid
	})
	return matches
}

// LoadRelatedNouns resolves one relation partition into typed detail records.
// limit applies independently to each noun kind; zero means all.
func (s *Store) LoadRelatedNouns(
	ctx context.Context,
	customerID, subjectKind, subjectID string,
	limit int,
) (models.RelatedNouns, error) {
	relations, err := s.listNounRelations(ctx, customerID, subjectKind, subjectID)
	if err != nil {
		return models.RelatedNouns{}, err
	}

	related := models.NewRelatedNouns()
	for _, relation := range relations {
		bounds := models.RelationshipBounds{
			RelationshipFirstSeen: relation.FirstSeen,
			RelationshipLastSeen:  relation.LastSeen,
		}
		switch relation.RelatedKind {
		case RelationKindPerson:
			if reachedLimit(len(related.People), limit) {
				continue
			}
			person, err := s.GetPerson(ctx, customerID, relation.RelatedID)
			if err != nil {
				return models.RelatedNouns{}, err
			}
			if person != nil {
				related.People = append(related.People, models.RelatedPerson{Person: *person, RelationshipBounds: bounds})
			}
		case RelationKindSession:
			if reachedLimit(len(related.Sessions), limit) {
				continue
			}
			session, err := s.GetSessionByRef(ctx, customerID, relation.RelatedID)
			if err != nil {
				return models.RelatedNouns{}, err
			}
			if session != nil {
				related.Sessions = append(related.Sessions, models.RelatedSession{Session: *session, RelationshipBounds: bounds})
			}
		case RelationKindAccount:
			if reachedLimit(len(related.Accounts), limit) {
				continue
			}
			account, err := s.GetAccount(ctx, customerID, relation.RelatedID)
			if err != nil {
				return models.RelatedNouns{}, err
			}
			if account != nil {
				related.Accounts = append(related.Accounts, models.RelatedAccount{Account: *account, RelationshipBounds: bounds})
			}
		case RelationKindRole:
			if reachedLimit(len(related.Roles), limit) {
				continue
			}
			role, err := s.GetRole(ctx, customerID, relation.RelatedID)
			if err != nil {
				return models.RelatedNouns{}, err
			}
			if role != nil {
				related.Roles = append(related.Roles, models.RelatedRole{Role: *role, RelationshipBounds: bounds})
			}
		case RelationKindService:
			if reachedLimit(len(related.Services), limit) {
				continue
			}
			service, err := s.GetService(ctx, customerID, relation.RelatedID)
			if err != nil {
				return models.RelatedNouns{}, err
			}
			if service != nil {
				related.Services = append(related.Services, models.RelatedService{Service: *service, RelationshipBounds: bounds})
			}
		case RelationKindResource:
			if reachedLimit(len(related.Resources), limit) {
				continue
			}
			resource, err := s.GetResource(ctx, customerID, relation.RelatedID)
			if err != nil {
				return models.RelatedNouns{}, err
			}
			if resource != nil {
				related.Resources = append(related.Resources, models.RelatedResource{Resource: *resource, RelationshipBounds: bounds})
			}
		}
	}
	return related, nil
}

func (s *Store) listNounRelations(
	ctx context.Context,
	customerID, subjectKind, subjectID string,
) ([]nounRelation, error) {
	var relations []nounRelation
	var lastKey map[string]types.AttributeValue
	for {
		result, err := s.client.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(RelationsTableName),
			KeyConditionExpression: aws.String("pk = :pk"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk": &types.AttributeValueMemberS{Value: relationPK(customerID, subjectKind, subjectID)},
			},
			ExclusiveStartKey: lastKey,
		})
		if err != nil {
			return nil, s.explainError(ctx, err, "query noun relationships")
		}

		var page []nounRelation
		if err := attributevalue.UnmarshalListOfMaps(result.Items, &page); err != nil {
			return nil, fmt.Errorf("failed to unmarshal noun relationships: %w", err)
		}
		for _, relation := range page {
			if relation.RelatedKind != "" && relation.RelatedID != "" {
				relations = append(relations, relation)
			}
		}
		if result.LastEvaluatedKey == nil {
			break
		}
		lastKey = result.LastEvaluatedKey
	}

	sortNounRelations(relations)
	return relations, nil
}

func sortNounRelations(relations []nounRelation) {
	sort.Slice(relations, func(i, j int) bool {
		if relations[i].LastSeen != relations[j].LastSeen {
			return relations[i].LastSeen > relations[j].LastSeen
		}
		if relations[i].RelatedKind != relations[j].RelatedKind {
			return relations[i].RelatedKind < relations[j].RelatedKind
		}
		return relations[i].RelatedID < relations[j].RelatedID
	})
}

func relationPK(customerID, kind, id string) string {
	return customerID + "#" + kind + "#" + base64.RawURLEncoding.EncodeToString([]byte(id))
}

func reachedLimit(current, limit int) bool {
	return limit > 0 && current >= limit
}
