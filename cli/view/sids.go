package view

import (
	"github.com/engseclabs/trailtool/core/models"
)

// sid display/lookup constants, mirrored from ingestor identity.Sid.
const (
	sidDisplayMin = 6
	sidFullLen    = 16
)

// SidDisplayWidth returns the shortest prefix length (≥ sidDisplayMin) at
// which every session's sid stays unique within the given list, so every SID the
// CLI prints is copy-pasteable and unambiguous against what's on screen. Sessions
// without a stored sid (pre-sid records) are ignored for width purposes.
func SidDisplayWidth(sessions []models.Session) int {
	width := sidDisplayMin
	for {
		seen := make(map[string]bool, len(sessions))
		clash := false
		for i := range sessions {
			sid := sessions[i].Sid
			if sid == "" {
				continue
			}
			p := sid[:min(len(sid), width)]
			if seen[p] {
				clash = true
				break
			}
			seen[p] = true
		}
		if !clash || width >= sidFullLen {
			return width
		}
		width++
	}
}

// ShortSid renders a session's sid at the given display width, or a placeholder
// when the record predates sids.
func ShortSid(sess *models.Session, width int) string {
	if sess.Sid == "" {
		return "-"
	}
	return sess.Sid[:min(len(sess.Sid), width)]
}

// SidForRefShort renders the display-width sid for a session ref (person_key|sk),
// for drilldown hints that point at another session without fetching it.
func SidForRefShort(ref string) string {
	return models.SidForRef(ref)[:sidDisplayMin]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
