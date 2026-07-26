package view

import (
	"strings"

	"github.com/engseclabs/trailtool/core/models"
)

// ShortPersonKey trims the noisy middle out of person keys for display:
// "email#alice@x.com" → "alice@x.com" stays readable via labels; idc# keys
// keep their tier prefix plus the trailing userId segment.
func ShortPersonKey(key string) string {
	return models.DisplayPersonKey(key)
}

// RefPersonKey returns the person-key half of a session ref ("person_key|sk").
func RefPersonKey(ref string) string {
	if personKey, _, ok := strings.Cut(ref, "|"); ok {
		return personKey
	}
	return ref
}
