package session

import (
	"strings"
	"testing"

	"github.com/engseclabs/trailtool/core/models"
)

func summaryFixture() *models.Session {
	return &models.Session{
		SessionType: "web",
		EventCounts: map[string]int{
			"s3.amazonaws.com:PutBucketPolicy": 2,
		},
		ResourceAccesses: []models.ResourceAccess{{
			Resource:  "s3:bucket:prod-data",
			Service:   "s3.amazonaws.com",
			EventName: "PutBucketPolicy",
			Count:     2,
		}},
		DeniedEventCount: 1,
		DeniedEventCounts: map[string]int{
			"s3.amazonaws.com:DeleteBucket": 1,
		},
		DeniedResourceAccesses: []models.ResourceAccess{{
			Resource:     "s3:bucket:prod-data",
			Service:      "s3.amazonaws.com",
			EventName:    "DeleteBucket",
			Count:        1,
			PolicyARN:    "arn:aws:organizations::111111111111:policy/o-example/service_control_policy/p-deny",
			PolicyType:   "SCP",
			ErrorMessage: "blocked",
		}},
		Clients: []models.ClientAggregate{{
			Key: "console", Category: "console", Name: "AWS Console", TotalEventCount: 3,
		}},
		ClickOpsEventCount: 2,
		ClickOpsEventCounts: map[string]int{
			"PutBucketPolicy": 2,
		},
	}
}

func TestBuildSessionPromptIncludesCompleteActivityContext(t *testing.T) {
	prompt := buildSessionPrompt(summaryFixture())
	for _, want := range []string{
		`"event_counts"`,
		`"resource_accesses"`,
		`"denied_event_accesses"`,
		`"denied_resource_accesses"`,
		`"policy_arn"`,
		`"policy_type"`,
		`"clients"`,
		`"clickops_event_counts"`,
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("prompt missing %s:\n%s", want, prompt)
		}
	}
}

func TestSummaryDigestTracksCanonicalInput(t *testing.T) {
	sess := summaryFixture()
	digest := SummaryInputDigest(sess)
	sess.Summary = "Changed the bucket policy."
	sess.SummaryInputDigest = digest
	if !SummaryIsCurrent(sess) {
		t.Fatal("matching summary digest is stale")
	}

	// Slice order is not semantic and must not invalidate a summary.
	sess.ResourceAccesses = append(sess.ResourceAccesses, models.ResourceAccess{
		Resource: "s3:bucket:archive", Service: "s3.amazonaws.com", EventName: "GetBucketPolicy", Count: 1,
	})
	first := SummaryInputDigest(sess)
	sess.ResourceAccesses[0], sess.ResourceAccesses[1] = sess.ResourceAccesses[1], sess.ResourceAccesses[0]
	if got := SummaryInputDigest(sess); got != first {
		t.Fatalf("digest changed with input ordering: %s != %s", got, first)
	}

	sess.EventCounts["s3.amazonaws.com:PutBucketPolicy"]++
	if SummaryIsCurrent(sess) {
		t.Fatal("later activity did not invalidate the cached summary")
	}
}
