package aggregator

import (
	"reflect"
	"testing"

	"github.com/engseclabs/trailtool/ingestor/lib/identity"
	"github.com/engseclabs/trailtool/ingestor/lib/resources"
	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

func TestProcessServiceEventTracksResources(t *testing.T) {
	services := make(map[string]*types.DynamoDBService)
	event := types.CloudTrailRecord{
		EventSource: "s3.amazonaws.com",
		EventName:   "GetObject",
	}

	processServiceEvent(
		services,
		event,
		"arn:aws:iam::111111111111:role/reader",
		[]types.ResourceIdentity{
			{Identifier: "s3:bucket:one", AccountID: "111111111111"},
			{Identifier: "s3:bucket:one", AccountID: "111111111111"},
			{Identifier: "s3:bucket:two", AccountID: "111111111111"},
		},
		"2026-07-24",
	)

	got := services[event.EventSource]
	if got == nil {
		t.Fatal("service was not created")
	}
	want := []string{"s3:bucket:one", "s3:bucket:two"}
	if !reflect.DeepEqual(got.ResourcesUsed, want) {
		t.Fatalf("resources = %v, want %v", got.ResourcesUsed, want)
	}
}

func TestProcessPersonAndAccountEventsTrackMissingAggregates(t *testing.T) {
	people := make(map[string]*types.DynamoDBPerson)
	accounts := make(map[string]*types.DynamoDBAccount)
	person := identity.Person{Key: "email#alex@example.com", Tier: identity.TierEmail}
	success := types.CloudTrailRecord{
		EventSource: "s3.amazonaws.com",
		EventName:   "CreateBucket",
	}
	denied := types.CloudTrailRecord{
		EventSource: "s3.amazonaws.com",
		EventName:   "DeleteBucket",
		ErrorCode:   "AccessDenied",
	}

	processPersonEvent(people, person, success, "2026-07-24")
	processPersonEvent(people, person, denied, "2026-07-24")
	processAccountEvent(accounts, "111111111111", success, "2026-07-24", true)
	processAccountEvent(accounts, "111111111111", denied, "2026-07-24", false)

	gotPerson := people[person.Key]
	if gotPerson.EventsCount != 2 || gotPerson.DeniedEventCount != 1 {
		t.Fatalf("person events = %d/%d, want 2/1", gotPerson.EventsCount, gotPerson.DeniedEventCount)
	}
	if gotPerson.TopDeniedEventNames["s3.amazonaws.com:DeleteBucket"] != 1 {
		t.Fatalf("person denied map = %v", gotPerson.TopDeniedEventNames)
	}

	gotAccount := accounts["111111111111"]
	if gotAccount.EventsCount != 2 || gotAccount.TotalDeniedEvents != 1 || gotAccount.ClickOpsCount != 1 {
		t.Fatalf("account events = %d/%d clickops=%d, want 2/1/1",
			gotAccount.EventsCount, gotAccount.TotalDeniedEvents, gotAccount.ClickOpsCount)
	}
	if gotAccount.TopEventNames["s3.amazonaws.com:CreateBucket"] != 1 {
		t.Fatalf("account successful map = %v", gotAccount.TopEventNames)
	}
	if gotAccount.TopDeniedEventNames["s3.amazonaws.com:DeleteBucket"] != 1 {
		t.Fatalf("account denied map = %v", gotAccount.TopDeniedEventNames)
	}
}

func TestProcessResourceEventQualifiesIdentityByAccount(t *testing.T) {
	resourceMap := make(map[string]*types.DynamoDBResource)
	event := types.CloudTrailRecord{
		EventSource: "lambda.amazonaws.com",
		EventName:   "Invoke",
	}
	identifier := "lambda:function:shared-function"
	first := types.ResourceIdentity{
		Identifier: identifier,
		AccountID:  "111111111111",
		Type:       "lambda:function",
		Name:       "shared-function",
	}
	second := first
	second.AccountID = "222222222222"

	processResourceEvent(resourceMap, event, first, "2026-07-24")
	processResourceEvent(resourceMap, event, second, "2026-07-24")

	if len(resourceMap) != 2 {
		t.Fatalf("resource map has %d entries, want 2", len(resourceMap))
	}
	for _, resource := range []types.ResourceIdentity{first, second} {
		key := resources.ResourceKey(resource.AccountID, identifier)
		got := resourceMap[key]
		if got == nil || got.ResourceKey != key || got.AccountID != resource.AccountID {
			t.Fatalf("resource %q = %#v", key, got)
		}
	}
}

func TestDetailedAccessesKeepResourceAccountsDistinct(t *testing.T) {
	identifier := "lambda:function:shared-function"
	resourceList := []types.ResourceIdentity{
		{Identifier: identifier, AccountID: "111111111111"},
		{Identifier: identifier, AccountID: "222222222222"},
	}
	event := types.CloudTrailRecord{
		EventTime:   "2026-07-24T12:00:00Z",
		EventSource: "lambda.amazonaws.com",
		EventName:   "Invoke",
	}

	roles := make(map[string]*types.DynamoDBRole)
	processRoleEvent(
		roles,
		event,
		"arn:aws:iam::111111111111:role/caller",
		resourceList,
		"2026-07-24",
	)
	if got := len(roles["arn:aws:iam::111111111111:role/caller"].ResourceAccesses); got != 2 {
		t.Fatalf("role resource accesses = %d, want 2", got)
	}

	sess := newSession("test", "email#alex@example.com", "key#ASIAEXAMPLE", "key#ASIAEXAMPLE", SessionTypeCLI, "", "", "111111111111")
	accumulateSessionEvent(sess, event, resourceList)
	if got := len(sess.ResourceAccesses); got != 2 {
		t.Fatalf("session resource accesses = %d, want 2", got)
	}
}
