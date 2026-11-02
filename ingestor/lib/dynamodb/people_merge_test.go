package dynamodb

import (
	"testing"

	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

func TestMergePersonPreservesDeniedActivity(t *testing.T) {
	got := MergePerson(
		&types.DynamoDBPerson{
			PersonKey:           "email#test-user@example.invalid",
			DeniedEventCount:    1,
			TopDeniedEventNames: map[string]int{"s3.amazonaws.com:GetObject": 1},
		},
		&types.DynamoDBPerson{
			PersonKey:           "email#test-user@example.invalid",
			DeniedEventCount:    2,
			TopDeniedEventNames: map[string]int{"s3.amazonaws.com:GetObject": 2},
		},
	)
	if got.DeniedEventCount != 3 || got.TopDeniedEventNames["s3.amazonaws.com:GetObject"] != 3 {
		t.Fatalf("merged person denied activity = %+v", got)
	}
}
