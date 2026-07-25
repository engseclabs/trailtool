// Person records: read-merge-write on (customerId, person_key).
package dynamodb

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

// WritePersonToDynamoDB writes or updates a person in DynamoDB using a
// read-merge-write on (customerId, person_key).
func WritePersonToDynamoDB(ctx context.Context, ddbClient SessionStore, tableName string, person *types.DynamoDBPerson) error {
	getResult, err := ddbClient.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(tableName),
		Key: map[string]ddbtypes.AttributeValue{
			"customerId": &ddbtypes.AttributeValueMemberS{Value: person.CustomerID},
			"person_key": &ddbtypes.AttributeValueMemberS{Value: person.PersonKey},
		},
	})
	if err != nil {
		log.Printf("WARNING: Failed to get existing person: %v", err)
	} else if len(getResult.Item) > 0 {
		var existing types.DynamoDBPerson
		if err := attributevalue.UnmarshalMap(getResult.Item, &existing); err != nil {
			log.Printf("WARNING: Failed to unmarshal existing person: %v", err)
		} else {
			person = MergePerson(&existing, person)
		}
	}

	item, err := attributevalue.MarshalMap(person)
	if err != nil {
		return fmt.Errorf("failed to marshal person: %w", err)
	}

	_, err = ddbClient.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(tableName),
		Item:      item,
	})

	return err
}

// MergePerson merges an incoming per-batch person record into the stored one.
// EventsCount accumulates; the per-batch unique counts (sessions, roles, …) keep
// the larger of the two values — an approximation until they're recomputed from
// the aggregate tables.
func MergePerson(existing, incoming *types.DynamoDBPerson) *types.DynamoDBPerson {
	merged := *incoming
	if existing.FirstSeen != "" && (merged.FirstSeen == "" || existing.FirstSeen < merged.FirstSeen) {
		merged.FirstSeen = existing.FirstSeen
	}
	if existing.LastSeen > merged.LastSeen {
		merged.LastSeen = existing.LastSeen
	}
	// Lower tier number == more authoritative (1 = Identity Center, 5 = root).
	// A later credential-linked record (TierLink) must not demote a stored
	// tier-1 idc# person just because it arrived second.
	if existing.Tier != 0 && (merged.Tier == 0 || existing.Tier < merged.Tier) {
		merged.Tier = existing.Tier
	}
	merged.Email = firstNonEmpty(existing.Email, incoming.Email)
	merged.DisplayName = firstNonEmpty(existing.DisplayName, incoming.DisplayName)
	merged.EmailsSeen = MergeUniqueStrings(existing.EmailsSeen, incoming.EmailsSeen)
	merged.EventsCount = existing.EventsCount + incoming.EventsCount
	merged.DeniedEventCount = existing.DeniedEventCount + incoming.DeniedEventCount
	merged.TopDeniedEventNames = MergeIntMaps(existing.TopDeniedEventNames, incoming.TopDeniedEventNames)
	merged.SessionsCount = maxInt(existing.SessionsCount, incoming.SessionsCount)
	merged.AccountsCount = maxInt(existing.AccountsCount, incoming.AccountsCount)
	merged.RolesCount = maxInt(existing.RolesCount, incoming.RolesCount)
	merged.ServicesCount = maxInt(existing.ServicesCount, incoming.ServicesCount)
	merged.ResourcesCount = maxInt(existing.ResourcesCount, incoming.ResourcesCount)
	return &merged
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
