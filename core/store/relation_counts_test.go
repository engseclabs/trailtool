package store

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/engseclabs/trailtool/core/models"
)

type fakeRelationCountsBatchGetter struct {
	inputs  []*dynamodb.BatchGetItemInput
	outputs []*dynamodb.BatchGetItemOutput
}

func (f *fakeRelationCountsBatchGetter) BatchGetItem(
	_ context.Context,
	input *dynamodb.BatchGetItemInput,
	_ ...func(*dynamodb.Options),
) (*dynamodb.BatchGetItemOutput, error) {
	f.inputs = append(f.inputs, input)
	index := len(f.inputs) - 1
	if index < len(f.outputs) {
		return f.outputs[index], nil
	}
	return &dynamodb.BatchGetItemOutput{}, nil
}

func TestBatchGetRelationshipCountsReadsExactSummary(t *testing.T) {
	pk := relationPK("default", RelationKindAccount, "123456789012")
	item, err := attributevalue.MarshalMap(relationSummaryRecord{
		PK: pk,
		SK: relationSummarySK,
		Counts: models.RelationshipCounts{
			People: 7, Sessions: 8, Roles: 3, Services: 4, Resources: 5,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	client := &fakeRelationCountsBatchGetter{
		outputs: []*dynamodb.BatchGetItemOutput{{
			Responses: map[string][]map[string]types.AttributeValue{
				RelationsTableName: {item},
			},
		}},
	}

	got, err := batchGetRelationshipCounts(
		context.Background(),
		client,
		"default",
		[]relationSubject{{Kind: RelationKindAccount, ID: "123456789012"}},
	)
	if err != nil {
		t.Fatalf("batchGetRelationshipCounts() error = %v", err)
	}
	counts, ok := got[pk]
	if !ok || !counts.Exact || counts.People != 7 || counts.Sessions != 8 || counts.Resources != 5 {
		t.Fatalf("counts = %#v", counts)
	}
	if len(client.inputs) != 1 {
		t.Fatalf("BatchGetItem calls = %d, want 1", len(client.inputs))
	}
	request := client.inputs[0].RequestItems[RelationsTableName]
	if request.ConsistentRead == nil || !*request.ConsistentRead || len(request.Keys) != 1 {
		t.Fatalf("request = %#v", request)
	}
}

func TestBatchGetRelationshipCountsChunksAtDynamoDBLimit(t *testing.T) {
	subjects := make([]relationSubject, 101)
	for i := range subjects {
		subjects[i] = relationSubject{Kind: RelationKindPerson, ID: string(rune(i + 1))}
	}
	client := &fakeRelationCountsBatchGetter{}
	if _, err := batchGetRelationshipCounts(context.Background(), client, "default", subjects); err != nil {
		t.Fatalf("batchGetRelationshipCounts() error = %v", err)
	}
	if len(client.inputs) != 2 {
		t.Fatalf("BatchGetItem calls = %d, want 2", len(client.inputs))
	}
	if got := len(client.inputs[0].RequestItems[RelationsTableName].Keys); got != 100 {
		t.Fatalf("first batch size = %d, want 100", got)
	}
	if got := len(client.inputs[1].RequestItems[RelationsTableName].Keys); got != 1 {
		t.Fatalf("second batch size = %d, want 1", got)
	}
}
