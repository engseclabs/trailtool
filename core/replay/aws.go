package replay

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3Lister pages ListObjectsV2 under a prefix and returns keys in the order S3
// yields them (ascending, hence chronological for CloudTrail's date-partitioned
// layout).
type S3Lister struct {
	Client *s3.Client
	Bucket string
}

func (l S3Lister) ListKeys(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	p := s3.NewListObjectsV2Paginator(l.Client, &s3.ListObjectsV2Input{
		Bucket: aws.String(l.Bucket),
		Prefix: aws.String(prefix),
	})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, obj := range page.Contents {
			keys = append(keys, aws.ToString(obj.Key))
		}
	}
	return keys, nil
}

// LambdaInvoker invokes the ingestor function synchronously with a synthetic S3
// event, the same shape EventBridge/S3 delivers live (ingest.go's first
// unmarshal branch). Synchronous invocation lets the driver observe per-object
// success and apply backpressure.
type LambdaInvoker struct {
	Client   *lambda.Client
	Function string
}

func (i LambdaInvoker) Invoke(ctx context.Context, bucket, key string) error {
	payload, err := json.Marshal(events.S3Event{
		Records: []events.S3EventRecord{{
			S3: events.S3Entity{
				Bucket: events.S3Bucket{Name: bucket},
				Object: events.S3Object{Key: key},
			},
		}},
	})
	if err != nil {
		return fmt.Errorf("marshal synthetic S3 event: %w", err)
	}

	out, err := i.Client.Invoke(ctx, &lambda.InvokeInput{
		FunctionName: aws.String(i.Function),
		Payload:      payload,
	})
	if err != nil {
		return err
	}
	// A handler error surfaces as FunctionError with the message in the payload,
	// not as a transport error, so it must be checked explicitly.
	if out.FunctionError != nil {
		return fmt.Errorf("ingestor error (%s): %s", aws.ToString(out.FunctionError), string(out.Payload))
	}
	return nil
}
