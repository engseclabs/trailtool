// Command otlpforwarder is the trailtool-otlp-forwarder Lambda. It receives
// TrailTool change events from an EventBridge rule and sends each one to an
// OTLP/HTTP logs endpoint as a log record. See docs/design/otlp-forwarder.md.
package main

import (
	"context"
	"log"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/engseclabs/trailtool/ingestor/lib/otlp"
)

// version is the application version, set at build time.
var version = "dev"

func main() {
	endpoint := os.Getenv("OTLP_LOGS_ENDPOINT")
	secretArn := os.Getenv("OTLP_HEADERS_SECRET_ARN")
	if endpoint == "" || secretArn == "" {
		log.Fatal("OTLP_LOGS_ENDPOINT and OTLP_HEADERS_SECRET_ARN must be set")
	}
	serviceName := os.Getenv("SERVICE_NAME")
	if serviceName == "" {
		serviceName = "trailtool"
	}

	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Fatalf("load AWS config: %v", err)
	}
	forwarder := &otlp.Forwarder{
		Exporter: otlp.NewExporter(endpoint, nil, secretsmanager.NewFromConfig(cfg), secretArn),
		Resource: otlp.Resource{ServiceName: serviceName, ScopeVersion: version},
	}
	lambda.Start(forwarder.Handle)
}
