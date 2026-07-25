package models

// RelationshipCounts is the exact distinct noun count stored in one relation
// partition's _summary item. Exact is set by the read path when that item
// exists; aggregate-item counts remain a fallback for missing summaries.
type RelationshipCounts struct {
	Exact     bool `json:"exact" dynamodbav:"-"`
	People    int  `json:"people" dynamodbav:"people"`
	Sessions  int  `json:"sessions" dynamodbav:"sessions"`
	Accounts  int  `json:"accounts" dynamodbav:"accounts"`
	Roles     int  `json:"roles" dynamodbav:"roles"`
	Services  int  `json:"services" dynamodbav:"services"`
	Resources int  `json:"resources" dynamodbav:"resources"`
}

// ApplyRelationshipCounts replaces fallback cross-noun counts when an exact
// relation summary is available.
func (p *Person) ApplyRelationshipCounts(counts RelationshipCounts) {
	if !counts.Exact {
		return
	}
	p.SessionsCount = counts.Sessions
	p.AccountsCount = counts.Accounts
	p.RolesCount = counts.Roles
	p.ServicesCount = counts.Services
	p.ResourcesCount = counts.Resources
}

func (s *Session) ApplyRelationshipCounts(counts RelationshipCounts) {
	if !counts.Exact {
		return
	}
	s.ServicesCount = counts.Services
	s.ResourcesCount = counts.Resources
}

func (r *Role) ApplyRelationshipCounts(counts RelationshipCounts) {
	if !counts.Exact {
		return
	}
	r.PeopleCount = counts.People
	r.SessionsCount = counts.Sessions
	r.AccountsCount = counts.Accounts
}

func (r *Resource) ApplyRelationshipCounts(counts RelationshipCounts) {
	if !counts.Exact {
		return
	}
	r.RolesCount = counts.Roles
	r.PeopleCount = counts.People
	r.SessionsCount = counts.Sessions
}

func (a *Account) ApplyRelationshipCounts(counts RelationshipCounts) {
	if !counts.Exact {
		return
	}
	a.PeopleCount = counts.People
	a.SessionsCount = counts.Sessions
	a.RolesCount = counts.Roles
	a.ServicesCount = counts.Services
	a.ResourcesCount = counts.Resources
}

func (s *Service) ApplyRelationshipCounts(counts RelationshipCounts) {
	if !counts.Exact {
		return
	}
	s.RolesCount = counts.Roles
	s.ResourcesCount = counts.Resources
	s.PeopleCount = counts.People
	s.SessionsCount = counts.Sessions
	s.AccountsCount = counts.Accounts
}
