package aggregator

// Write-cost study: replays a synthetic AWS-organization CloudTrail fixture
// through the aggregator twice, once with the previous role, service, and
// relation write paths (legacy_writers_test.go) and once with the current
// ones, against a metering in-memory
// DynamoDB, and reports per-table item sizes and capacity units per file.
//
// The default size keeps CI fast. For the numbers in the PR description:
//
//	WRITECOST_ACCOUNTS=30 WRITECOST_WARM_SLOTS=24 WRITECOST_SLOTS=12 \
//	  go test ./lib/aggregator -run TestWriteCost -v -timeout 2h
//
// Each slot is five minutes of the organization: one file per account and
// region, as CloudTrail delivers them.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	ddbfake "github.com/engseclabs/trailtool/ingestor/internal/ddbsim"
	ddblib "github.com/engseclabs/trailtool/ingestor/lib/dynamodb"
	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

var costTables = Tables{
	Roles:         "trailtool-roles",
	Services:      "trailtool-services",
	Resources:     "trailtool-resources",
	People:        "trailtool-people",
	Sessions:      "trailtool-sessions",
	Accounts:      "trailtool-accounts",
	Relations:     "trailtool-relations",
	IdentityLinks: "trailtool-identity-links",
}

func newCostStore() *ddbfake.Store {
	return ddbfake.New(map[string]ddbfake.KeySchema{
		costTables.Roles:         {Hash: "customerId", Range: "arn"},
		costTables.Services:      {Hash: "customerId", Range: "event_source"},
		costTables.Resources:     {Hash: "customerId", Range: "resource_key"},
		costTables.People:        {Hash: "customerId", Range: "person_key"},
		costTables.Sessions:      {Hash: "pk", Range: "sk"},
		costTables.Accounts:      {Hash: "customerId", Range: "account_id"},
		costTables.Relations:     {Hash: "pk", Range: "sk"},
		costTables.IdentityLinks: {Hash: "pk"},
	})
}

// useLegacyWriters swaps in the previous write paths until the returned
// function restores the current ones.
func useLegacyWriters() func() {
	saved := writers
	writers.role = func(ctx context.Context, c ddblib.NounStore, t string, r *types.DynamoDBRole) error {
		return legacyWriteRole(ctx, c.(ddblib.EntityStore), t, r)
	}
	writers.service = func(ctx context.Context, c ddblib.NounStore, t string, s *types.DynamoDBService) error {
		return legacyWriteService(ctx, c.(ddblib.EntityStore), t, s)
	}
	writers.relations = legacyWriteRelations
	return func() { writers = saved }
}

// orgFixture generates CloudTrail files for a synthetic organization. It is
// deterministic for a given seed.
type orgFixture struct {
	accounts      []string
	regions       []string
	rolesPer      int
	eventsPerFile int
	start         time.Time
	rng           *rand.Rand
	eventSeq      int
}

type svcSpec struct {
	source string
	weight int
	reads  []string
	writes []string
	param  func(f *orgFixture, account string) map[string]interface{}
}

var orgServices = []svcSpec{
	{"sts.amazonaws.com", 10, []string{"GetCallerIdentity"}, []string{"AssumeRole"}, nil},
	{"s3.amazonaws.com", 22, []string{"GetObject", "HeadObject", "ListObjects", "GetBucketLocation", "GetBucketAcl", "GetBucketPolicy"}, []string{"PutObject", "DeleteObject", "PutBucketTagging"},
		func(f *orgFixture, a string) map[string]interface{} {
			return map[string]interface{}{"bucketName": fmt.Sprintf("%s-data-%03d", a, f.zipf(400))}
		}},
	{"dynamodb.amazonaws.com", 12, []string{"GetItem", "Query", "DescribeTable", "Scan"}, []string{"PutItem", "UpdateItem", "BatchWriteItem"},
		func(f *orgFixture, a string) map[string]interface{} {
			return map[string]interface{}{"tableName": fmt.Sprintf("table-%03d", f.zipf(150))}
		}},
	{"kms.amazonaws.com", 14, []string{"Decrypt", "GenerateDataKey", "DescribeKey"}, []string{"Encrypt", "ReEncrypt"},
		func(f *orgFixture, a string) map[string]interface{} {
			return map[string]interface{}{"keyId": fmt.Sprintf("arn:aws:kms:us-east-1:%s:key/%s", a, uuidish("key", a, f.zipf(60)))}
		}},
	{"lambda.amazonaws.com", 7, []string{"GetFunction", "ListFunctions", "GetFunctionConfiguration"}, []string{"Invoke", "UpdateFunctionCode", "UpdateFunctionConfiguration"},
		func(f *orgFixture, a string) map[string]interface{} {
			return map[string]interface{}{"functionName": fmt.Sprintf("svc-%03d-handler", f.zipf(300))}
		}},
	{"ec2.amazonaws.com", 12, []string{"DescribeInstances", "DescribeVolumes", "DescribeSecurityGroups", "DescribeSubnets", "DescribeNetworkInterfaces", "DescribeImages", "DescribeTags", "DescribeInstanceStatus"}, []string{"CreateTags", "RunInstances", "TerminateInstances", "CreateNetworkInterface", "DeleteNetworkInterface"},
		func(f *orgFixture, a string) map[string]interface{} {
			// Instances churn: autoscaling keeps replacing a long tail.
			return map[string]interface{}{"instanceId": fmt.Sprintf("i-%017x", f.zipf(5000))}
		}},
	{"sqs.amazonaws.com", 7, []string{"ReceiveMessage", "GetQueueAttributes"}, []string{"SendMessage", "DeleteMessage", "ChangeMessageVisibility"},
		func(f *orgFixture, a string) map[string]interface{} {
			return map[string]interface{}{"queueUrl": fmt.Sprintf("https://sqs.us-east-1.amazonaws.com/%s/queue-%03d", a, f.zipf(120))}
		}},
	{"logs.amazonaws.com", 6, []string{"DescribeLogGroups", "DescribeLogStreams", "GetLogEvents", "FilterLogEvents"}, []string{"CreateLogStream", "PutRetentionPolicy"}, nil},
	{"ecs.amazonaws.com", 4, []string{"DescribeServices", "DescribeTasks", "ListTasks", "DescribeTaskDefinition"}, []string{"UpdateService", "RunTask", "RegisterTaskDefinition"},
		func(f *orgFixture, a string) map[string]interface{} {
			return map[string]interface{}{"cluster": fmt.Sprintf("cluster-%02d", f.zipf(20)), "service": fmt.Sprintf("svc-%03d", f.zipf(200))}
		}},
	{"monitoring.amazonaws.com", 4, []string{"GetMetricData", "DescribeAlarms", "ListMetrics"}, []string{"PutMetricAlarm", "PutMetricData"}, nil},
	{"iam.amazonaws.com", 2, []string{"GetRole", "ListRoles", "GetPolicy", "ListAttachedRolePolicies"}, []string{"PassRole", "TagRole"}, nil},
}

func uuidish(parts ...interface{}) string {
	sum := sha256.Sum256([]byte(fmt.Sprint(parts...)))
	h := hex.EncodeToString(sum[:16])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func newOrgFixture(accounts, rolesPer, eventsPerFile int) *orgFixture {
	f := &orgFixture{
		regions:       []string{"us-east-1", "us-west-2", "eu-west-1"},
		rolesPer:      rolesPer,
		eventsPerFile: eventsPerFile,
		start:         time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		rng:           rand.New(rand.NewSource(1)),
	}
	for i := 0; i < accounts; i++ {
		f.accounts = append(f.accounts, fmt.Sprintf("%012d", 100000000000+i*7919))
	}
	return f
}

// zipf picks an index in [0, n) with a heavy head, like real usage.
func (f *orgFixture) zipf(n int) int {
	return int(math.Floor(math.Pow(float64(n+1), f.rng.Float64()))) - 1
}

func (f *orgFixture) pickService() svcSpec {
	total := 0
	for _, s := range orgServices {
		total += s.weight
	}
	r := f.rng.Intn(total)
	for _, s := range orgServices {
		if r < s.weight {
			return s
		}
		r -= s.weight
	}
	return orgServices[0]
}

// file generates one CloudTrail file: one account and region over five
// minutes of slot.
func (f *orgFixture) file(slot, accountIdx, regionIdx int) []types.CloudTrailRecord {
	account := f.accounts[accountIdx]
	region := f.regions[regionIdx]
	windowStart := f.start.Add(time.Duration(slot) * 5 * time.Minute)
	n := f.eventsPerFile/2 + f.rng.Intn(f.eventsPerFile)
	records := make([]types.CloudTrailRecord, 0, n)
	for i := 0; i < n; i++ {
		f.eventSeq++
		at := windowStart.Add(time.Duration(f.rng.Intn(300)) * time.Second)
		svc := f.pickService()
		var name string
		write := f.rng.Intn(5) == 0
		if write {
			name = svc.writes[f.zipf(len(svc.writes))]
		} else {
			name = svc.reads[f.zipf(len(svc.reads))]
		}
		readOnly := !write

		roleIdx := f.zipf(f.rolesPer)
		human := roleIdx < 3 && f.rng.Intn(3) == 0
		roleName := fmt.Sprintf("workload-%03d-role", roleIdx)
		sessionName := fmt.Sprintf("session-%d", roleIdx)
		if human {
			roleName = []string{"AWSReservedSSO_AdministratorAccess_1a2b3c", "AWSReservedSSO_ReadOnly_4d5e6f", "AWSReservedSSO_PowerUser_7a8b9c"}[roleIdx]
			sessionName = fmt.Sprintf("user%02d@example.com", f.zipf(80))
		}
		roleARN := fmt.Sprintf("arn:aws:iam::%s:role/%s", account, roleName)
		roleID := "AROA" + strings.ToUpper(uuidish("role", account, roleName)[:17])
		roleID = strings.ReplaceAll(roleID, "-", "")
		hour := at.Truncate(time.Hour)
		creation := hour.Format(time.RFC3339)
		accessKey := "ASIA" + strings.ToUpper(strings.ReplaceAll(uuidish("ak", roleARN, sessionName, creation), "-", "")[:16])

		rec := types.CloudTrailRecord{
			EventVersion:       "1.09",
			EventID:            uuidish("evt", f.eventSeq),
			EventTime:          at.Format(time.RFC3339),
			EventName:          name,
			EventSource:        svc.source,
			EventType:          "AwsApiCall",
			AwsRegion:          region,
			RecipientAccountID: account,
			SourceIPAddress:    "10.0.0.1",
			UserAgent:          "aws-sdk-go-v2/1.30.0 os/linux lang/go#1.22 md/GOOS#linux",
			ReadOnly:           &readOnly,
			UserIdentity: types.UserIdentity{
				Type:        "AssumedRole",
				PrincipalID: roleID + ":" + sessionName,
				ARN:         fmt.Sprintf("arn:aws:sts::%s:assumed-role/%s/%s", account, roleName, sessionName),
				AccountID:   account,
				AccessKeyID: accessKey,
			},
		}
		sc := &types.SessionContext{}
		sc.Attributes.CreationDate = creation
		sc.Attributes.MfaAuthenticated = "false"
		sc.SessionIssuer.Type = "Role"
		sc.SessionIssuer.PrincipalID = roleID
		sc.SessionIssuer.ARN = roleARN
		sc.SessionIssuer.AccountID = account
		sc.SessionIssuer.UserName = roleName
		rec.UserIdentity.SessionContext = sc
		if human && f.rng.Intn(2) == 0 {
			rec.SessionCredentialFromConsole = "true"
			rec.UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
		}
		if svc.param != nil {
			rec.RequestParameters = svc.param(f, account)
		}
		if f.rng.Intn(25) == 0 {
			rec.ErrorCode = "AccessDenied"
			rec.ErrorMessage = fmt.Sprintf("User: %s is not authorized to perform: %s:%s with an explicit deny in a service control policy: arn:aws:organizations::999999999999:policy/o-abc123/service_control_policy/p-%d",
				rec.UserIdentity.ARN, strings.TrimSuffix(svc.source, ".amazonaws.com"), name, f.zipf(4))
		} else if f.rng.Intn(40) == 0 {
			rec.ErrorCode = "ThrottlingException"
			rec.ErrorMessage = "Rate exceeded"
		}
		records = append(records, rec)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].EventTime < records[j].EventTime })
	return records
}

type costRun struct {
	files int
	stats map[string]ddbfake.TableStats
}

func envInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil && v > 0 {
		return v
	}
	return def
}

// runCost ingests warm slots, resets the meters, then ingests measured slots.
func runCost(t *testing.T, legacy bool, warm, measured int) costRun {
	t.Helper()
	if legacy {
		defer useLegacyWriters()()
	}
	ctx := context.Background()
	store := newCostStore()
	f := newOrgFixture(envInt("WRITECOST_ACCOUNTS", 10), envInt("WRITECOST_ROLES", 150), envInt("WRITECOST_EVENTS", 200))
	files := 0
	for slot := 0; slot < warm+measured; slot++ {
		if slot == warm {
			store.ResetMeters()
		}
		for a := range f.accounts {
			for r := range f.regions {
				records := f.file(slot, a, r)
				if _, err := processWithStore(ctx, store, Config{Tables: costTables}, records); err != nil {
					t.Fatalf("slot %d account %d region %d: %v", slot, a, r, err)
				}
				if slot >= warm {
					files++
				}
			}
		}
	}
	return costRun{files: files, stats: store.Stats()}
}

func TestWriteCost(t *testing.T) {
	if testing.Short() {
		t.Skip("write-cost measurement skipped in -short mode")
	}
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	warm := envInt("WRITECOST_WARM_SLOTS", 3)
	measured := envInt("WRITECOST_SLOTS", 1)
	before := runCost(t, true, warm, measured)
	after := runCost(t, false, warm, measured)

	tables := []string{costTables.Relations, costTables.Services, costTables.Roles, costTables.Accounts, costTables.Resources, costTables.Sessions, costTables.People, costTables.IdentityLinks}
	var b strings.Builder
	fmt.Fprintf(&b, "\n%d warm-up slots, %d measured slots (%d files measured)\n\n", warm, measured, after.files)
	fmt.Fprintf(&b, "| Table | Max item before | Max item after | WCU/file before | WCU/file after | RCU/file before | RCU/file after | Failed writes before | Failed writes after |\n")
	fmt.Fprintf(&b, "|---|---:|---:|---:|---:|---:|---:|---:|---:|\n")
	var totalBefore, totalAfter, readBefore, readAfter float64
	for _, name := range tables {
		bs, as := before.stats[name], after.stats[name]
		wb, wa := bs.WriteUnits/float64(before.files), as.WriteUnits/float64(after.files)
		rb, ra := bs.ReadUnits/float64(before.files), as.ReadUnits/float64(after.files)
		totalBefore += wb
		totalAfter += wa
		readBefore += rb
		readAfter += ra
		fmt.Fprintf(&b, "| %s | %s | %s | %.1f | %.1f | %.1f | %.1f | %d | %d |\n",
			strings.TrimPrefix(name, "trailtool-"), kb(bs.MaxItemSize), kb(as.MaxItemSize), wb, wa, rb, ra, bs.FailedWrites, as.FailedWrites)
	}
	fmt.Fprintf(&b, "| **total** | | | **%.1f** | **%.1f** | **%.1f** | **%.1f** | | |\n", totalBefore, totalAfter, readBefore, readAfter)
	t.Log(b.String())

	for _, name := range []string{costTables.Roles, costTables.Services} {
		if size := after.stats[name].MaxItemSize; size > 4*1024 {
			t.Errorf("%s: largest item is %s, want every item under 4 KB", name, kb(size))
		}
		if failed := after.stats[name].FailedWrites; failed > 0 {
			t.Errorf("%s: %d writes failed", name, failed)
		}
	}
	if totalAfter >= totalBefore {
		t.Errorf("write units per file did not drop: before %.1f, after %.1f", totalBefore, totalAfter)
	}
}

func kb(n int) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.1f KB", float64(n)/1024)
}
