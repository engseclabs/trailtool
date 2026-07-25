package view

import "github.com/engseclabs/trailtool/core/models"

const (
	nounIDDisplayMin = 6
	nounIDFullLen    = 16
)

// PersonIDDisplayWidth returns the shortest prefix that identifies every
// person in the list.
func PersonIDDisplayWidth(people []models.Person) int {
	ids := make([]string, len(people))
	for i := range people {
		ids[i] = people[i].PID()
	}
	return uniqueIDWidth(ids)
}

// RoleIDDisplayWidth returns the shortest prefix that identifies every role in
// the list.
func RoleIDDisplayWidth(roles []models.Role) int {
	ids := make([]string, len(roles))
	for i := range roles {
		ids[i] = roles[i].RoleID()
	}
	return uniqueIDWidth(ids)
}

// ResourceIDDisplayWidth returns the shortest prefix that identifies every
// resource in the list.
func ResourceIDDisplayWidth(resources []models.Resource) int {
	ids := make([]string, len(resources))
	for i := range resources {
		ids[i] = resources[i].RID()
	}
	return uniqueIDWidth(ids)
}

// ShortRoleID renders a role ID at the requested unambiguous display width.
func ShortRoleID(role *models.Role, width int) string {
	return shortID(role.RoleID(), width)
}

func uniqueIDWidth(ids []string) int {
	for width := nounIDDisplayMin; width <= nounIDFullLen; width++ {
		seen := make(map[string]bool, len(ids))
		unique := true
		for _, id := range ids {
			prefix := shortID(id, width)
			if seen[prefix] {
				unique = false
				break
			}
			seen[prefix] = true
		}
		if unique {
			return width
		}
	}
	return nounIDFullLen
}

func shortID(id string, width int) string {
	return id[:min(len(id), width)]
}
