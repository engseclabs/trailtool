package replay

import (
	"context"
	"path/filepath"
	"testing"
)

func TestFileCursorRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.cursor")
	c := FileCursor{Path: path}
	ctx := context.Background()

	// Missing file loads as empty, not an error.
	got, err := c.Load(ctx)
	if err != nil || got != "" {
		t.Fatalf("initial load = %q, err %v; want empty", got, err)
	}

	if err := c.Save(ctx, "AWSLogs/1/CloudTrail/us-east-1/2026/07/25/x.json.gz"); err != nil {
		t.Fatal(err)
	}
	got, err = c.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got != "AWSLogs/1/CloudTrail/us-east-1/2026/07/25/x.json.gz" {
		t.Fatalf("loaded %q after save", got)
	}

	// Overwrite advances the cursor.
	if err := c.Save(ctx, "later.json.gz"); err != nil {
		t.Fatal(err)
	}
	if got, _ := c.Load(ctx); got != "later.json.gz" {
		t.Fatalf("loaded %q after second save", got)
	}
}

func TestNopCursorNeverResumes(t *testing.T) {
	c := NopCursor{}
	if got, err := c.Load(context.Background()); err != nil || got != "" {
		t.Fatalf("NopCursor.Load = %q, %v", got, err)
	}
	if err := c.Save(context.Background(), "x"); err != nil {
		t.Fatalf("NopCursor.Save error: %v", err)
	}
}
