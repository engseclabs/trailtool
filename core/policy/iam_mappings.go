package policy

import (
	"bufio"
	"bytes"
	_ "embed"
	"fmt"
	"strings"
)

//go:generate go run ../../scripts/generate_iam_mappings.go -out iam_mappings.tsv

//go:embed iam_mappings.tsv
var serviceAuthorizationMappings []byte

func (m *IAMActionMapper) loadServiceAuthorizationMappings() {
	mappings, err := parseServiceAuthorizationMappings(serviceAuthorizationMappings)
	if err != nil {
		panic(fmt.Sprintf("load embedded AWS service authorization mappings: %v", err))
	}
	m.mappings = mappings
}

func parseServiceAuthorizationMappings(data []byte) (map[string][]string, error) {
	mappings := make(map[string][]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, "\t", 2)
		if len(fields) != 2 || fields[0] == "" || fields[1] == "" {
			return nil, fmt.Errorf("line %d: expected mapping key and actions", lineNumber)
		}
		mappings[fields[0]] = strings.Split(fields[1], ",")
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(mappings) == 0 {
		return nil, fmt.Errorf("mapping file is empty")
	}
	return mappings, nil
}
