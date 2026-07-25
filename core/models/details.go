package models

// RelatedNouns is the common detail payload for noun relationships. Every
// field is initialized to an empty slice so detail JSON uses [] instead of null.
type RelatedNouns struct {
	Counts    RelationshipCounts `json:"counts"`
	People    []RelatedPerson    `json:"people"`
	Sessions  []RelatedSession   `json:"sessions"`
	Accounts  []RelatedAccount   `json:"accounts"`
	Roles     []RelatedRole      `json:"roles"`
	Services  []RelatedService   `json:"services"`
	Resources []RelatedResource  `json:"resources"`
}

// NewRelatedNouns returns an empty, JSON-stable relationship payload.
func NewRelatedNouns() RelatedNouns {
	return RelatedNouns{
		People:    []RelatedPerson{},
		Sessions:  []RelatedSession{},
		Accounts:  []RelatedAccount{},
		Roles:     []RelatedRole{},
		Services:  []RelatedService{},
		Resources: []RelatedResource{},
	}
}

// RelationshipBounds records when a relationship was first and last observed.
type RelationshipBounds struct {
	RelationshipFirstSeen string `json:"relationship_first_seen"`
	RelationshipLastSeen  string `json:"relationship_last_seen"`
}

type RelatedPerson struct {
	Person
	RelationshipBounds
}

type RelatedSession struct {
	Session
	RelationshipBounds
}

type RelatedAccount struct {
	Account
	RelationshipBounds
}

type RelatedRole struct {
	Role
	RelationshipBounds
}

type RelatedService struct {
	Service
	RelationshipBounds
}

type RelatedResource struct {
	Resource
	RelationshipBounds
}

// PersonDetail keeps the stored person fields at the top level and adds the
// relationships used by the human detail view.
type PersonDetail struct {
	Person
	Related RelatedNouns `json:"related"`
}

// ResourceDetail keeps the stored resource fields at the top level and adds the
// relationships used by the human detail view.
type ResourceDetail struct {
	Resource
	Related RelatedNouns `json:"related"`
}

// AccountDetail enriches the stored account with exact noun relationships.
type AccountDetail struct {
	Account
	Related RelatedNouns `json:"related"`
}

// RoleDetail enriches the stored role with exact noun relationships.
type RoleDetail struct {
	Role
	Related RelatedNouns `json:"related"`
}

// ServiceDetail enriches the stored service with exact noun relationships.
type ServiceDetail struct {
	Service
	Related RelatedNouns `json:"related"`
}

// SessionDetail enriches the stored session with exact noun relationships.
type SessionDetail struct {
	Session
	Related RelatedNouns `json:"related"`
}
