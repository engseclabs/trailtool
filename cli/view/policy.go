package view

import (
	"encoding/json"
)

// PrettyJSON re-indents a JSON string. Returns an error if input is not valid JSON.
func PrettyJSON(raw string) (string, error) {
	var v interface{}
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
