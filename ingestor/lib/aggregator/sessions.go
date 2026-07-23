// Session records: type derivation, construction, and per-event
// accumulation into the in-memory session map.
package aggregator

import (
	"log"
	"strings"

	"github.com/engseclabs/trailtool/ingestor/lib/session"
	"github.com/engseclabs/trailtool/ingestor/lib/types"
)

// Session types. Anchored sessions are typed by construction (anchor keyspace
// plus link matches); user-agent classification survives only as the windowed
// fallback's channel label.
const (
	SessionTypeCLI   = "cli"
	SessionTypeWeb   = "web"
	SessionTypeAgent = "agent"
	SessionTypeLogin = "login"
)

// anchoredSessionType types an anchored session by construction (§3.1): agent
// requires an mcp# link match — never mere presence of a signInSessionArn, which
// AWS is rolling out to ordinary sessions. login applies to sis#/key# anchors
// only: a web# session matching a login# link is the *authorizing* console
// session (it shares the roleID+creationDate the link is keyed on), not the
// vended one.
func anchoredSessionType(anchor string, mcpL, loginL *link) string {
	if mcpL != nil {
		return SessionTypeAgent
	}
	if strings.HasPrefix(anchor, "web#") {
		return SessionTypeWeb
	}
	if loginL != nil {
		return SessionTypeLogin
	}
	return SessionTypeCLI
}

// newSession initializes a session record for the (person, roleID, anchor) key.
func newSession(ns, personKey, sk, anchor, sessionType, roleARN, roleID, accountID string) *types.DynamoDBSession {
	return &types.DynamoDBSession{
		PK:                      ns + "#" + personKey,
		SK:                      sk,
		CustomerID:              ns,
		PersonKey:               personKey,
		Anchor:                  anchor,
		SessionType:             sessionType,
		RoleARN:                 roleARN,
		RoleID:                  roleID,
		RoleName:                session.ExtractRoleNameFromARN(roleARN),
		AccountID:               accountID,
		RoleKey:                 ns + "#" + roleID,
		AccountKey:              ns + "#" + accountID,
		Version:                 1,
		SourceIPs:               []string{},
		Clients:                 []types.ClientAggregate{},
		EventCounts:             make(map[string]int),
		ResourcesAccessed:       make(map[string]int),
		ResourceAccesses:        []types.ResourceAccess{},
		DeniedEventCounts:       make(map[string]int),
		DeniedResourcesAccessed: make(map[string]int),
		DeniedResourceAccesses:  []types.ResourceAccess{},
		DeniedEventAccesses:     []types.EventAccess{},
	}
}

// accumulateSessionEvent folds one event into its session record.
func accumulateSessionEvent(sess *types.DynamoDBSession, event types.CloudTrailRecord, resourceList []string) {
	eventTime := event.EventTime
	if sess.StartTime == "" || eventTime < sess.StartTime {
		sess.StartTime = eventTime
	}
	if eventTime > sess.EndTime {
		sess.EndTime = eventTime
	}

	// Forward-access sessions: an AWS service calling with the human's
	// credentials. Included in the session, counted separately, never ClickOps.
	serviceDriven := event.UserIdentity.InvokedBy != ""
	if serviceDriven {
		sess.ServiceDrivenEventCount++
	}

	isAccessDenied := session.IsAccessDeniedError(event.ErrorCode)
	eventKey := event.EventSource + ":" + event.EventName

	if isAccessDenied {
		policyInfo := session.ExtractPolicyInfo(event.ErrorMessage)
		log.Printf("ACCESS_DENIED: session=%s event=%s errorCode=%s policy_arn=%s errorMessage=%q",
			sess.SK, eventKey, event.ErrorCode, policyInfo.PolicyARN, event.ErrorMessage)
		sess.DeniedEventCount++
		sess.DeniedEventCounts[eventKey]++

		if len(resourceList) > 0 {
			for _, resource := range resourceList {
				sess.DeniedResourcesAccessed[resource]++
				found := false
				for i := range sess.DeniedResourceAccesses {
					if sess.DeniedResourceAccesses[i].Resource == resource &&
						sess.DeniedResourceAccesses[i].Service == event.EventSource &&
						sess.DeniedResourceAccesses[i].EventName == event.EventName &&
						sess.DeniedResourceAccesses[i].PolicyARN == policyInfo.PolicyARN {
						sess.DeniedResourceAccesses[i].Count++
						found = true
						break
					}
				}
				if !found {
					sess.DeniedResourceAccesses = append(sess.DeniedResourceAccesses, types.ResourceAccess{
						Resource:     resource,
						Service:      event.EventSource,
						EventName:    event.EventName,
						Count:        1,
						PolicyARN:    policyInfo.PolicyARN,
						PolicyType:   policyInfo.PolicyType,
						ErrorMessage: event.ErrorMessage,
					})
				}
			}
		} else {
			found := false
			for i := range sess.DeniedEventAccesses {
				if sess.DeniedEventAccesses[i].Service == event.EventSource &&
					sess.DeniedEventAccesses[i].EventName == event.EventName &&
					sess.DeniedEventAccesses[i].PolicyARN == policyInfo.PolicyARN {
					sess.DeniedEventAccesses[i].Count++
					found = true
					break
				}
			}
			if !found {
				sess.DeniedEventAccesses = append(sess.DeniedEventAccesses, types.EventAccess{
					Service:      event.EventSource,
					EventName:    event.EventName,
					Count:        1,
					PolicyARN:    policyInfo.PolicyARN,
					PolicyType:   policyInfo.PolicyType,
					ErrorMessage: event.ErrorMessage,
				})
			}
		}
	} else {
		sess.EventsCount++
		sess.EventCounts[eventKey]++
		for _, resource := range resourceList {
			sess.ResourcesAccessed[resource]++
			found := false
			for i := range sess.ResourceAccesses {
				if sess.ResourceAccesses[i].Resource == resource &&
					sess.ResourceAccesses[i].Service == event.EventSource &&
					sess.ResourceAccesses[i].EventName == event.EventName {
					sess.ResourceAccesses[i].Count++
					found = true
					break
				}
			}
			if !found {
				sess.ResourceAccesses = append(sess.ResourceAccesses, types.ResourceAccess{
					Resource:  resource,
					Service:   event.EventSource,
					EventName: event.EventName,
					Count:     1,
				})
			}
		}
	}

	if !isAccessDenied && !serviceDriven && sess.SessionType == SessionTypeWeb && session.IsClickOpsOperation(event.EventName) {
		sess.ClickOpsEventCount++
		if sess.ClickOpsEventCounts == nil {
			sess.ClickOpsEventCounts = make(map[string]int)
		}
		sess.ClickOpsEventCounts[event.EventName]++
	}

	if sourceIP := event.SourceIPAddress; sourceIP != "" && session.IsValidSourceIP(sourceIP) {
		appendUnique(&sess.SourceIPs, sourceIP)
	}
	if ua := session.NormalizeUserAgent(event.UserAgent); ua != "" && session.IsValidUserAgent(ua) {
		foldClient(sess, ua, event, isAccessDenied, serviceDriven)
	}
	if sess.SignInSessionArn == "" {
		if sc := event.UserIdentity.SessionContext; sc != nil && sc.SignInSessionArn != "" {
			sess.SignInSessionArn = sc.SignInSessionArn
		}
	}
}

// maxRawUASamples bounds how many distinct raw user-agent strings each
// ClientAggregate retains (DynamoDB item-size hygiene). The parsed fields carry
// the signal; the samples are only an escape hatch to the literal string.
const maxRawUASamples = 5

// foldClient parses one event's user-agent and folds it into the session's
// per-client aggregates, creating the ClientAggregate on first sight of its Key
// and updating counts, seen-times, commands, components, and raw samples.
func foldClient(sess *types.DynamoDBSession, ua string, event types.CloudTrailRecord, isAccessDenied, serviceDriven bool) {
	pc := session.ParseUserAgent(ua)
	key := pc.Key()

	// Find-or-create the aggregate for this client key.
	var c *types.ClientAggregate
	for i := range sess.Clients {
		if sess.Clients[i].Key == key {
			c = &sess.Clients[i]
			break
		}
	}
	if c == nil {
		sess.Clients = append(sess.Clients, types.ClientAggregate{
			Key:          key,
			Category:     pc.Category,
			Name:         pc.Name,
			Version:      pc.Version,
			OS:           pc.OS,
			OSVersion:    pc.OSVersion,
			Architecture: pc.Arch,
			Runtime:      pc.Runtime,
			Commands:     map[string]int{},
		})
		c = &sess.Clients[len(sess.Clients)-1]
	}

	// Counts. TotalEventCount tracks every event this client made (denied or not),
	// mirroring how the UI wants to attribute activity to a client.
	c.TotalEventCount++
	if isAccessDenied {
		c.DeniedEventCount++
	}
	if serviceDriven {
		c.ServiceDrivenEventCount++
	}

	// Seen-times: RFC3339 UTC compares lexicographically.
	et := event.EventTime
	if c.FirstSeen == "" || et < c.FirstSeen {
		c.FirstSeen = et
	}
	if et > c.LastSeen {
		c.LastSeen = et
	}

	// Commands: bare eventName always; "ua:"-prefixed userAgent command token when present.
	if event.EventName != "" {
		c.Commands[event.EventName]++
	}
	if pc.Command != "" {
		c.Commands["ua:"+pc.Command]++
	}

	// Components: last non-empty write wins (stable single-valued facts).
	for k, v := range pc.Components {
		if v != "" {
			if c.Components == nil {
				c.Components = map[string]string{}
			}
			c.Components[k] = v
		}
	}

	// Raw samples: distinct, capped.
	if len(c.RawUserAgentSamples) < maxRawUASamples && !containsString(c.RawUserAgentSamples, pc.Raw) {
		c.RawUserAgentSamples = append(c.RawUserAgentSamples, pc.Raw)
	}
}

// containsString reports whether value is already in slice.
func containsString(slice []string, value string) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}

// appendUnique appends value to the slice if not already present.
func appendUnique(slice *[]string, value string) {
	for _, v := range *slice {
		if v == value {
			return
		}
	}
	*slice = append(*slice, value)
}

// sessionNameOf returns the role-session-name half of an assumed-role
// principalId ("AROA…:name" → "name"), or "".
func sessionNameOf(principalID string) string {
	if idx := strings.Index(principalID, ":"); idx >= 0 {
		return principalID[idx+1:]
	}
	return ""
}
