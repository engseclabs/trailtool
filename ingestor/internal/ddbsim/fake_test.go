package ddbsim

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func s(v string) ddbtypes.AttributeValue { return &ddbtypes.AttributeValueMemberS{Value: v} }
func n(v string) ddbtypes.AttributeValue { return &ddbtypes.AttributeValueMemberN{Value: v} }

func TestMeteringFollowsDynamoDBBilling(t *testing.T) {
	ctx := context.Background()
	store := New(map[string]KeySchema{"t": {Hash: "pk", Range: "sk"}})
	key := map[string]ddbtypes.AttributeValue{"pk": s("a"), "sk": s("b")}
	big := map[string]ddbtypes.AttributeValue{"pk": s("a"), "sk": s("b"), "blob": s(strings.Repeat("x", 3000))}
	if _, err := store.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String("t"), Item: big}); err != nil {
		t.Fatal(err)
	}
	if got := store.Stats()["t"].WriteUnits; got != 3 {
		t.Fatalf("3 KB put = %v WCU", got)
	}

	// An ADD on a 3 KB item still costs 3 units: billing uses the larger of
	// the before and after sizes.
	store.ResetMeters()
	_, err := store.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String("t"), Key: key,
		UpdateExpression:          aws.String("ADD #c :one SET #f = if_not_exists(#f, :v)"),
		ExpressionAttributeNames:  map[string]string{"#c": "count", "#f": "first"},
		ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{":one": n("1"), ":v": s("x")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := store.Stats()["t"].WriteUnits; got != 3 {
		t.Fatalf("update on 3 KB item = %v WCU", got)
	}

	// A failed condition is billed too.
	store.ResetMeters()
	_, err = store.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String("t"), Key: key,
		UpdateExpression:          aws.String("SET #f = :v"),
		ConditionExpression:       aws.String("attribute_not_exists(#f) OR #f < :v"),
		ExpressionAttributeNames:  map[string]string{"#f": "first"},
		ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{":v": s("a")},
	})
	var ccf *ddbtypes.ConditionalCheckFailedException
	if !errors.As(err, &ccf) {
		t.Fatalf("err = %v", err)
	}
	if got := store.Stats()["t"].WriteUnits; got != 3 {
		t.Fatalf("failed condition = %v WCU", got)
	}

	// Reading a missing item costs the minimum.
	store.ResetMeters()
	if _, err := store.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String("t"), Key: map[string]ddbtypes.AttributeValue{"pk": s("z"), "sk": s("z")}}); err != nil {
		t.Fatal(err)
	}
	if got := store.Stats()["t"].ReadUnits; got != 0.5 {
		t.Fatalf("missing eventually consistent read = %v RCU", got)
	}
}

func TestItemLimitIsEnforced(t *testing.T) {
	store := New(map[string]KeySchema{"t": {Hash: "pk"}})
	_, err := store.PutItem(context.Background(), &dynamodb.PutItemInput{
		TableName: aws.String("t"),
		Item:      map[string]ddbtypes.AttributeValue{"pk": s("a"), "blob": s(strings.Repeat("x", MaxItemSize))},
	})
	if err == nil || !strings.Contains(err.Error(), "Item size has exceeded") {
		t.Fatalf("err = %v", err)
	}
	if store.Stats()["t"].FailedWrites != 1 {
		t.Fatal("failed write not counted")
	}
}
