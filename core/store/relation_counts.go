package store

import (
	"context"
	"fmt"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/engseclabs/trailtool/core/models"
)

const (
	relationSummarySK       = "_summary"
	relationBatchSize       = 100
	relationBatchMaxRetries = 3
)

type relationSubject struct {
	Kind string
	ID   string
}

type relationSummaryRecord struct {
	PK     string                    `dynamodbav:"pk"`
	SK     string                    `dynamodbav:"sk"`
	Counts models.RelationshipCounts `dynamodbav:"counts"`
}

type relationCountsBatchGetter interface {
	BatchGetItem(
		context.Context,
		*dynamodb.BatchGetItemInput,
		...func(*dynamodb.Options),
	) (*dynamodb.BatchGetItemOutput, error)
}

func (s *Store) relationshipCountsForSubjects(
	ctx context.Context,
	customerID string,
	subjects []relationSubject,
) (map[string]models.RelationshipCounts, error) {
	counts, err := batchGetRelationshipCounts(ctx, s.client, customerID, subjects)
	if err != nil {
		return nil, s.explainError(ctx, err, "load relationship counts")
	}
	return counts, nil
}

func batchGetRelationshipCounts(
	ctx context.Context,
	client relationCountsBatchGetter,
	customerID string,
	subjects []relationSubject,
) (map[string]models.RelationshipCounts, error) {
	keysByPK := make(map[string]map[string]types.AttributeValue, len(subjects))
	for _, subject := range subjects {
		if subject.Kind == "" || subject.ID == "" {
			continue
		}
		pk := relationPK(customerID, subject.Kind, subject.ID)
		keysByPK[pk] = map[string]types.AttributeValue{
			"pk": &types.AttributeValueMemberS{Value: pk},
			"sk": &types.AttributeValueMemberS{Value: relationSummarySK},
		}
	}
	pks := make([]string, 0, len(keysByPK))
	for pk := range keysByPK {
		pks = append(pks, pk)
	}
	sort.Strings(pks)

	counts := make(map[string]models.RelationshipCounts, len(pks))
	for start := 0; start < len(pks); start += relationBatchSize {
		end := min(start+relationBatchSize, len(pks))
		pending := make([]map[string]types.AttributeValue, 0, end-start)
		for _, pk := range pks[start:end] {
			pending = append(pending, keysByPK[pk])
		}

		for attempt := 0; len(pending) > 0; attempt++ {
			if attempt > relationBatchMaxRetries {
				return nil, fmt.Errorf("relationship count batch did not complete after %d retries", relationBatchMaxRetries)
			}
			result, err := client.BatchGetItem(ctx, &dynamodb.BatchGetItemInput{
				RequestItems: map[string]types.KeysAndAttributes{
					RelationsTableName: {
						Keys:           pending,
						ConsistentRead: aws.Bool(true),
					},
				},
			})
			if err != nil {
				return nil, err
			}

			var summaries []relationSummaryRecord
			if err := attributevalue.UnmarshalListOfMaps(result.Responses[RelationsTableName], &summaries); err != nil {
				return nil, fmt.Errorf("unmarshal relationship counts: %w", err)
			}
			for _, summary := range summaries {
				if summary.PK == "" || summary.SK != relationSummarySK {
					continue
				}
				summary.Counts.Exact = true
				counts[summary.PK] = summary.Counts
			}

			pending = nil
			if unprocessed, ok := result.UnprocessedKeys[RelationsTableName]; ok {
				pending = unprocessed.Keys
			}
		}
	}
	return counts, nil
}

func (s *Store) enrichPeopleRelationshipCounts(ctx context.Context, customerID string, people []models.Person) error {
	subjects := make([]relationSubject, len(people))
	for i := range people {
		subjects[i] = relationSubject{Kind: RelationKindPerson, ID: people[i].PersonKey}
	}
	counts, err := s.relationshipCountsForSubjects(ctx, customerID, subjects)
	if err != nil {
		return err
	}
	for i := range people {
		people[i].ApplyRelationshipCounts(counts[relationPK(customerID, RelationKindPerson, people[i].PersonKey)])
	}
	return nil
}

func (s *Store) enrichRoleRelationshipCounts(ctx context.Context, customerID string, roles []models.Role) error {
	subjects := make([]relationSubject, len(roles))
	for i := range roles {
		subjects[i] = relationSubject{Kind: RelationKindRole, ID: roles[i].ARN}
	}
	counts, err := s.relationshipCountsForSubjects(ctx, customerID, subjects)
	if err != nil {
		return err
	}
	for i := range roles {
		roles[i].ApplyRelationshipCounts(counts[relationPK(customerID, RelationKindRole, roles[i].ARN)])
	}
	return nil
}

func (s *Store) enrichResourceRelationshipCounts(ctx context.Context, customerID string, resources []models.Resource) error {
	subjects := make([]relationSubject, len(resources))
	for i := range resources {
		subjects[i] = relationSubject{Kind: RelationKindResource, ID: resources[i].ResourceKey}
	}
	counts, err := s.relationshipCountsForSubjects(ctx, customerID, subjects)
	if err != nil {
		return err
	}
	for i := range resources {
		resources[i].ApplyRelationshipCounts(counts[relationPK(customerID, RelationKindResource, resources[i].ResourceKey)])
	}
	return nil
}

func (s *Store) enrichAccountRelationshipCounts(ctx context.Context, customerID string, accounts []models.Account) error {
	subjects := make([]relationSubject, len(accounts))
	for i := range accounts {
		subjects[i] = relationSubject{Kind: RelationKindAccount, ID: accounts[i].AccountID}
	}
	counts, err := s.relationshipCountsForSubjects(ctx, customerID, subjects)
	if err != nil {
		return err
	}
	for i := range accounts {
		accounts[i].ApplyRelationshipCounts(counts[relationPK(customerID, RelationKindAccount, accounts[i].AccountID)])
	}
	return nil
}

func (s *Store) enrichServiceRelationshipCounts(ctx context.Context, customerID string, services []models.Service) error {
	subjects := make([]relationSubject, len(services))
	for i := range services {
		subjects[i] = relationSubject{Kind: RelationKindService, ID: services[i].EventSource}
	}
	counts, err := s.relationshipCountsForSubjects(ctx, customerID, subjects)
	if err != nil {
		return err
	}
	for i := range services {
		services[i].ApplyRelationshipCounts(counts[relationPK(customerID, RelationKindService, services[i].EventSource)])
	}
	return nil
}
