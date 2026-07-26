package replay

import (
	"context"
	"os"
	"strings"
)

// FileCursor persists the resume high-water key in a local file. It has no TTL,
// so "did I already replay this range" survives independently of the
// ingested-files marker (docs/design/cloudtrail-replay.md §8). One file per
// replay target keeps concurrent replays of different ranges from colliding.
type FileCursor struct {
	Path string
}

func (c FileCursor) Load(ctx context.Context) (string, error) {
	data, err := os.ReadFile(c.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func (c FileCursor) Save(ctx context.Context, key string) error {
	// Write-and-rename so an interrupted save cannot leave a truncated cursor
	// that resumes from the wrong place.
	tmp := c.Path + ".tmp"
	if err := os.WriteFile(tmp, []byte(key+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, c.Path)
}

// NopCursor disables resume: every run starts from the beginning of the range.
type NopCursor struct{}

func (NopCursor) Load(context.Context) (string, error) { return "", nil }
func (NopCursor) Save(context.Context, string) error   { return nil }
