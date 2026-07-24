package view

import (
	"strings"
)

// ShortPersonKey trims the noisy middle out of person keys for display:
// "email#alice@x.com" → "alice@x.com" stays readable via labels; idc# keys
// keep their tier prefix plus the trailing userId segment.
func ShortPersonKey(key string) string {
	if rest, ok := strings.CutPrefix(key, "idc#"); ok {
		if idx := strings.LastIndex(rest, "#"); idx >= 0 {
			return "idc#…" + rest[idx:]
		}
	}
	return key
}

// RefPersonKey returns the person-key half of a session ref ("person_key|sk").
func RefPersonKey(ref string) string {
	if personKey, _, ok := strings.Cut(ref, "|"); ok {
		return personKey
	}
	return ref
}
