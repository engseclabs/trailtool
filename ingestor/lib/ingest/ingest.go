// Package ingest handles Lambda event parsing, S3 download, CloudTrail log
// decompression, and delegates to the aggregator for processing.
package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/engseclabs/trailtool/ingestor/lib/aggregator"
	ddblib "github.com/engseclabs/trailtool/ingestor/lib/dynamodb"
	tevents "github.com/engseclabs/trailtool/ingestor/lib/events"
	"github.com/engseclabs/trailtool/ingestor/lib/parser"
	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

// ResolveNamespace is called with the source account ID (from EventBridge) to
// determine the aggregator namespace. Return "" to use the default namespace.
type ResolveNamespace func(ctx context.Context, ddbClient *dynamodb.Client, sourceAccount string) string

// Config controls the ingest pipeline.
type Config struct {
	Tables aggregator.Tables

	// IngestedFiles is the file-marker table for redelivery idempotency.
	// Empty disables the marker check.
	IngestedFiles string

	// IdleGap overrides the windowed-fallback idle gap (default 30m).
	IdleGap time.Duration

	// ResolveNS is called when an EventBridge event includes a source account.
	// If nil, the default namespace is used for all events.
	ResolveNS ResolveNamespace

	// Publisher and ActivityEventBusArn turn on change events; emission needs
	// both. Delivery is best-effort and never fails ingestion.
	Publisher           tevents.Publisher
	ActivityEventBusArn string

	// SuppressEmission turns change events off for one invocation. Replays
	// always set it through their payload marker.
	SuppressEmission bool
}

// invocationMarker is the "trailtool" key `trailtool replay` adds to its
// synthetic S3 events (core/replay LambdaInvoker).
type invocationMarker struct {
	TrailTool struct {
		Replay bool `json:"replay"`
	} `json:"trailtool"`
}

// suppressForReplay reports whether a raw event is a replay. Change events feed
// live audit systems, so replayed history never publishes them.
func suppressForReplay(rawEvent json.RawMessage) bool {
	var marker invocationMarker
	if err := json.Unmarshal(rawEvent, &marker); err != nil {
		return false
	}
	return marker.TrailTool.Replay
}

// GetEnvOrDefault returns the environment variable value or the default.
func GetEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// TablesFromEnv builds a Tables struct from standard environment variables.
func TablesFromEnv(prefix string) aggregator.Tables {
	return aggregator.Tables{
		Roles:         GetEnvOrDefault("ROLES_TABLE", prefix+"-roles"),
		Services:      GetEnvOrDefault("SERVICES_TABLE", prefix+"-services"),
		Resources:     GetEnvOrDefault("RESOURCES_TABLE", prefix+"-resources"),
		People:        GetEnvOrDefault("PEOPLE_TABLE", prefix+"-people"),
		Sessions:      GetEnvOrDefault("SESSIONS_TABLE", prefix+"-sessions"),
		Accounts:      GetEnvOrDefault("ACCOUNTS_TABLE", prefix+"-accounts"),
		Relations:     GetEnvOrDefault("RELATIONS_TABLE", prefix+"-relations"),
		IdentityLinks: GetEnvOrDefault("IDENTITY_LINKS_TABLE", prefix+"-identity-links"),
	}
}

// IngestedFilesTableFromEnv returns the ingestion-marker table name.
func IngestedFilesTableFromEnv(prefix string) string {
	return GetEnvOrDefault("INGESTED_FILES_TABLE", prefix+"-ingested-files")
}

// ActivityEventBusArnFromEnv returns the bus change events go to; empty
// disables them.
func ActivityEventBusArnFromEnv() string {
	return os.Getenv("ACTIVITY_EVENT_BUS_ARN")
}

// IdleGapFromEnv parses the IDLE_GAP environment variable (a Go duration,
// e.g. "30m"). Zero means "use the default".
func IdleGapFromEnv() time.Duration {
	raw := os.Getenv("IDLE_GAP")
	if raw == "" {
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		log.Printf("WARNING: ignoring invalid IDLE_GAP %q: %v", raw, err)
		return 0
	}
	return d
}

// HandleLambdaEvent parses the raw Lambda event (S3 or EventBridge) and
// processes all CloudTrail records found.
func HandleLambdaEvent(ctx context.Context, ddbClient *dynamodb.Client, s3Client *s3.Client, cfg Config, rawEvent json.RawMessage) error {
	log.Printf("FULL_EVENT_RECEIVED: %s", string(rawEvent))

	if suppressForReplay(rawEvent) {
		log.Printf("REPLAY: change events suppressed for this invocation")
		cfg.SuppressEmission = true
	}

	// Try direct S3 event
	var s3Event events.S3Event
	if err := json.Unmarshal(rawEvent, &s3Event); err == nil && len(s3Event.Records) > 0 {
		log.Printf("Processing direct S3 event with %d records", len(s3Event.Records))
		return processS3Records(ctx, ddbClient, s3Client, cfg, s3Event, "")
	}

	// Try EventBridge event
	var ebEvent types.EventBridgeS3Event
	if err := json.Unmarshal(rawEvent, &ebEvent); err == nil && ebEvent.Source == "aws.s3" {
		log.Printf("Processing EventBridge S3 event: detail-type=%s", ebEvent.DetailType)

		bucket, _ := ebEvent.Detail["bucket"].(map[string]interface{})
		bucketName, _ := bucket["name"].(string)

		object, _ := ebEvent.Detail["object"].(map[string]interface{})
		objectKey, _ := object["key"].(string)

		log.Printf("EventBridge S3 event: bucket=%s, key=%s, sourceAccount=%s", bucketName, objectKey, ebEvent.Account)

		s3Event := events.S3Event{
			Records: []events.S3EventRecord{
				{
					AWSRegion: ebEvent.Region,
					S3: events.S3Entity{
						Bucket: events.S3Bucket{
							Name: bucketName,
						},
						Object: events.S3Object{
							Key: objectKey,
						},
					},
				},
			},
		}

		return processS3Records(ctx, ddbClient, s3Client, cfg, s3Event, ebEvent.Account)
	}

	log.Printf("Unknown event format, skipping")
	return nil
}

func processS3Records(ctx context.Context, ddbClient *dynamodb.Client, s3Client *s3.Client, cfg Config, event events.S3Event, sourceAccount string) error {
	// Resolve namespace
	var namespace string
	if sourceAccount != "" && cfg.ResolveNS != nil {
		namespace = cfg.ResolveNS(ctx, ddbClient, sourceAccount)
	}

	for _, record := range event.Records {
		bucket := record.S3.Bucket.Name
		key := record.S3.Object.Key

		log.Printf("S3 event: bucket=%s, key=%s", bucket, key)

		if strings.Contains(key, "/CloudTrail-Insight/") ||
			strings.Contains(key, "/CloudTrail-Digest/") ||
			strings.Contains(key, "/CloudTrail-Aggregated/") {
			log.Printf("Skipping non-event CloudTrail file: %s", key)
			continue
		}

		// File-level idempotency: S3/EventBridge can redeliver an object; a
		// marker written after successful processing prevents double counts.
		// (A crash mid-batch can still double-write a partial batch — accepted.)
		if cfg.IngestedFiles != "" && ddbClient != nil {
			ingested, err := ddblib.IsFileIngested(ctx, ddbClient, cfg.IngestedFiles, key)
			if err != nil {
				log.Printf("WARNING: ingested-file check failed for %s: %v", key, err)
			} else if ingested {
				log.Printf("SKIP_REDELIVERY: %s already ingested", key)
				continue
			}
		}

		result, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		})
		if err != nil {
			return fmt.Errorf("failed to get S3 object: %w", err)
		}
		defer result.Body.Close()

		cloudTrailLog, err := parser.ParseCloudTrailLog(result.Body)
		if err != nil {
			return err
		}

		log.Printf("Processing %d CloudTrail events from S3: %s/%s", len(cloudTrailLog.Records), bucket, key)

		res, err := aggregator.ProcessWithResult(ctx, ddbClient, aggregator.Config{
			Tables:       cfg.Tables,
			Namespace:    namespace,
			IdleGap:      cfg.IdleGap,
			RecordWrites: cfg.emitting(),
		}, cloudTrailLog.Records)
		// Emit before the error check: nouns and edges created before a failure
		// will not be reported by the retry. Session Activity waits for a clean
		// run, since the retry merges and reports the sessions again.
		emitChangeEvents(ctx, ddbClient, cfg, fileFromKey(key, cloudTrailLog.Records), res, err == nil)
		if err != nil {
			return fmt.Errorf("failed to process CloudTrail events: %w", err)
		}

		if cfg.IngestedFiles != "" && ddbClient != nil {
			if err := ddblib.MarkFileIngested(ctx, ddbClient, cfg.IngestedFiles, key, time.Now()); err != nil {
				log.Printf("WARNING: failed to mark %s ingested: %v", key, err)
			}
		}

		log.Printf("SUCCESS: Processed %d events from S3", len(cloudTrailLog.Records))
	}

	return nil
}

// emitChangeEvents publishes the batch's change events when emission is on.
// complete is false when the batch failed partway; only created nouns and
// edges go out then.
func emitChangeEvents(ctx context.Context, ddbClient *dynamodb.Client, cfg Config, file tevents.File, res *aggregator.Result, complete bool) {
	if !cfg.emitting() || res == nil {
		return
	}
	ctx, cancel := emitContext(ctx)
	defer cancel()
	if ctx.Err() != nil {
		log.Printf("EMIT_FAILED: no time left before the Lambda deadline; skipped %s", file.Key)
		return
	}
	var counts tevents.CountsFunc
	if ddbClient != nil && cfg.Tables.Relations != "" {
		counts = func(ctx context.Context, pk string) (map[string]int, error) {
			return ddblib.GetRelationSummaryCounts(ctx, ddbClient, cfg.Tables.Relations, pk)
		}
	}
	env := tevents.NewEnvelope(res.Namespace, file)
	evs := tevents.BuildCreated(ctx, env, res, counts)
	if complete {
		evs = append(evs, tevents.BuildSessionActivity(env, res)...)
	}
	tevents.Emit(ctx, cfg.Publisher, cfg.ActivityEventBusArn, evs)
}

// emitting reports whether this invocation publishes change events.
func (c Config) emitting() bool {
	return c.Publisher != nil && c.ActivityEventBusArn != "" && !c.SuppressEmission
}

const (
	// emitBudget caps how long one file's emission may take.
	emitBudget = 30 * time.Second
	// emitDeadlineMargin is left for MarkFileIngested after emission. A Lambda
	// that times out is redelivered and double-merges its sessions.
	emitDeadlineMargin = 10 * time.Second
)

// emitContext bounds emission so it can never run the Lambda past its deadline.
func emitContext(ctx context.Context) (context.Context, context.CancelFunc) {
	budget := emitBudget
	if deadline, ok := ctx.Deadline(); ok {
		budget = min(budget, time.Until(deadline)-emitDeadlineMargin)
	}
	return context.WithTimeout(ctx, budget)
}

// fileFromKey names a CloudTrail object, reading account and region from the
// standard .../<account>/CloudTrail/<region>/... layout and falling back to
// the first record.
func fileFromKey(key string, records []types.CloudTrailRecord) tevents.File {
	file := tevents.File{Key: key}
	parts := strings.Split(key, "/")
	for i := 1; i+1 < len(parts); i++ {
		if parts[i] == "CloudTrail" {
			file.AccountID, file.Region = parts[i-1], parts[i+1]
			break
		}
	}
	if len(records) > 0 {
		if file.AccountID == "" {
			file.AccountID = records[0].RecipientAccountID
		}
		if file.Region == "" {
			file.Region = records[0].AwsRegion
		}
	}
	return file
}
