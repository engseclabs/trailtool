package otlp

import (
	"context"
	"fmt"
	"log"
	"time"

	lambdaevents "github.com/aws/aws-lambda-go/events"
	"google.golang.org/protobuf/proto"
)

// Forwarder handles one EventBridge event per invocation.
type Forwarder struct {
	Exporter *Exporter
	Resource Resource
	// Now is the clock for observed times; nil means time.Now.
	Now func() time.Time
}

// Handle maps the event to a log record and exports it. An error makes the
// invocation fail, so Lambda retries it and then sends it to the dead-letter
// queue. Logs carry the event id, detail-type, HTTP status, and rejected
// count, never header values or the request body.
func (f *Forwarder) Handle(ctx context.Context, ev lambdaevents.EventBridgeEvent) error {
	now := time.Now
	if f.Now != nil {
		now = f.Now
	}
	body, err := proto.Marshal(BuildLogs(ev, f.Resource, now()))
	if err != nil {
		log.Printf("OTLP_FAILED: id=%s detail_type=%q error=%q", ev.ID, ev.DetailType, err)
		return fmt.Errorf("marshal log record: %w", err)
	}
	res, err := f.Exporter.Export(ctx, body)
	if err != nil {
		log.Printf("OTLP_FAILED: id=%s detail_type=%q status=%d rejected=%d error=%q", ev.ID, ev.DetailType, res.Status, res.Rejected, err)
		return err
	}
	log.Printf("OTLP_OK: id=%s detail_type=%q status=%d rejected=%d", ev.ID, ev.DetailType, res.Status, res.Rejected)
	return nil
}
