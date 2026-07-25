package models

import "sort"

// SortSessionsForList applies the session list contract: start time in the
// requested direction, then SID ascending for deterministic ties.
func SortSessionsForList(sessions []Session, reverse bool) {
	sort.Slice(sessions, func(i, j int) bool {
		if sessions[i].StartTime != sessions[j].StartTime {
			if reverse {
				return sessions[i].StartTime > sessions[j].StartTime
			}
			return sessions[i].StartTime < sessions[j].StartTime
		}
		return sessions[i].Sid < sessions[j].Sid
	})
}
