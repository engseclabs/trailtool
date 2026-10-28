package replay

import (
	"encoding/json"
	"testing"
)

func TestInvokePayloadMarksReplay(t *testing.T) {
	for _, emit := range []bool{false, true} {
		raw, err := InvokePayload("trail-bucket", "AWSLogs/111111111111/CloudTrail/us-east-1/2026/10/01/f.json.gz", emit)
		if err != nil {
			t.Fatalf("payload: %v", err)
		}
		var got struct {
			Records []struct {
				S3 struct {
					Object struct {
						Key string `json:"key"`
					} `json:"object"`
				} `json:"s3"`
			} `json:"Records"`
			TrailTool ReplayMarker `json:"trailtool"`
		}
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(got.Records) != 1 || got.Records[0].S3.Object.Key == "" {
			t.Fatalf("payload lost the S3 record: %s", raw)
		}
		if !got.TrailTool.Replay || got.TrailTool.EmitEvents != emit {
			t.Fatalf("marker = %+v, want replay with emit_events=%v", got.TrailTool, emit)
		}
	}
}
