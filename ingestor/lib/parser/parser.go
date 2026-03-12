// Package parser contains CloudTrail log parsing functions.
package parser

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"

	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

// ParseCloudTrailLog reads a gzip-compressed CloudTrail log from the provided reader
// and returns the parsed CloudTrailLog structure.
// The reader should provide gzip-compressed JSON data in CloudTrail format.
func ParseCloudTrailLog(reader io.Reader) (*types.CloudTrailLog, error) {
	// Create gzip reader
	gzReader, err := gzip.NewReader(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	// Read all decompressed data
	data, err := io.ReadAll(gzReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read gzip data: %w", err)
	}

	// Parse JSON into CloudTrailLog structure
	var cloudTrailLog types.CloudTrailLog
	if err := json.Unmarshal(data, &cloudTrailLog); err != nil {
		return nil, fmt.Errorf("failed to parse CloudTrail log: %w", err)
	}

	return &cloudTrailLog, nil
}
