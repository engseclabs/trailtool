package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/engseclabs/trailtool/ingestor/lib/ingest"
)

func handler(ctx context.Context, event json.RawMessage) error {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	ingestCfg := ingest.Config{
		Tables:              ingest.TablesFromEnv("trailtool"),
		IngestedFiles:       ingest.IngestedFilesTableFromEnv("trailtool"),
		IdleGap:             ingest.IdleGapFromEnv(),
		ActivityEventBusArn: ingest.ActivityEventBusArnFromEnv(),
	}
	if ingestCfg.ActivityEventBusArn != "" {
		ingestCfg.Publisher = eventbridge.NewFromConfig(cfg)
	}

	return ingest.HandleLambdaEvent(ctx,
		dynamodb.NewFromConfig(cfg),
		s3.NewFromConfig(cfg),
		ingestCfg,
		event,
	)
}

func main() {
	lambda.Start(handler)
}
