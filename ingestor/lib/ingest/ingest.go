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

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/engseclabs/trailtool/ingestor/lib/aggregator"
	"github.com/engseclabs/trailtool/ingestor/lib/parser"
	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

// ResolveNamespace is called with the source account ID (from EventBridge) to
// determine the aggregator namespace. Return "" to use the default namespace.
type ResolveNamespace func(ctx context.Context, ddbClient *dynamodb.Client, sourceAccount string) string

// Config controls the ingest pipeline.
type Config struct {
	Tables aggregator.Tables

	// ResolveNS is called when an EventBridge event includes a source account.
	// If nil, the default namespace is used for all events.
	ResolveNS ResolveNamespace
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
		Roles:      GetEnvOrDefault("ROLES_AGGREGATED_TABLE", prefix+"-roles-aggregated"),
		Services:   GetEnvOrDefault("SERVICES_AGGREGATED_TABLE", prefix+"-services-aggregated"),
		Resources:  GetEnvOrDefault("RESOURCES_AGGREGATED_TABLE", prefix+"-resources-aggregated"),
		People:     GetEnvOrDefault("PEOPLE_AGGREGATED_TABLE", prefix+"-people-aggregated"),
		Sessions:   GetEnvOrDefault("SESSIONS_AGGREGATED_TABLE", prefix+"-sessions-aggregated"),
		Accounts:   GetEnvOrDefault("ACCOUNTS_AGGREGATED_TABLE", prefix+"-accounts-aggregated"),
		ChainLinks: GetEnvOrDefault("CHAIN_LINKS_TABLE", prefix+"-chain-links"),
	}
}

// HandleLambdaEvent parses the raw Lambda event (S3 or EventBridge) and
// processes all CloudTrail records found.
func HandleLambdaEvent(ctx context.Context, ddbClient *dynamodb.Client, s3Client *s3.Client, cfg Config, rawEvent json.RawMessage) error {
	log.Printf("FULL_EVENT_RECEIVED: %s", string(rawEvent))

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

		if err := aggregator.Process(ctx, ddbClient, aggregator.Config{
			Tables:    cfg.Tables,
			Namespace: namespace,
		}, cloudTrailLog.Records); err != nil {
			return fmt.Errorf("failed to process CloudTrail events: %w", err)
		}

		log.Printf("SUCCESS: Processed %d events from S3", len(cloudTrailLog.Records))
	}

	return nil
}
