# TrailTool 1.0 — Identity-First Session Model

For status and rollout see https://github.com/engseclabs/trailtool/issues/12

## 1. Summary

Pre-1.0 TrailTool has no stable identifier for a human across credential refreshes, so it keys sessions on time hacks — a 4-hour window for CLI/SDK, exact `sessionContext.creationDate` for web — and bolts on a TTL'd `chain-links` table to attribute assumed-role, `aws login`, and MCP-agent traffic to a person. 1.0 rebuilds the model on two separated axes: **who** acted, and **which session** the action belongs to.

- **Who** — identity resolves per *credential group* (events sharing one credential) through five fallback tiers headed by `userIdentity.onBehalfOf` (§3).
- **Which session** — a session is the lifetime of one credential or sign-in, resolved *deterministically* from fields AWS stamps on the events: sign-in session ARN, console session creation date, or the temporary access key itself. Idle-gap windowing survives only as the last-resort fallback for principals with no credential boundary at all — long-lived IAM keys and root (§4).
- **CLI refresh = new session.** Refreshing a credential mints a new access key, and that is a new session. Each session represents exactly one credential's blast radius; the CLI reads adjacent refreshes naturally (same person, same role, back-to-back).
- **Deterministic where AWS gives us a boundary.** Because anchors are deterministic, cross-batch session assembly is a plain additive merge onto a known key. Read-extend-merge and optimistic locking are confined to the windowed fallback (§4.2).
- **Hard cutover, no migration.** Deploying the 1.0 ingestor destructively replaces the `trailtool-*-aggregated` tables with clean-named tables; pre-1.0 data is deleted and history rebuilds from CloudTrail (§6, §7).

## 2. AWS constraints

Three facts, verified against AWS docs and a live probe (evidence in §10), constrain the design. They are stated up front because they shape every later section.

- **C1 — `onBehalfOf` is per-service, not per-session.** One human session can emit some events with it and some without. Identity therefore resolves per credential group, never per event (§3). The same discipline applies to `signInSessionArn`: any event in a group carrying it decides the whole group's anchor (§4).
- **C2 — `onBehalfOf` does not survive plain role chaining.** A plain `aws sts assume-role` from an SSO session yields a child session with no `onBehalfOf`. A correlation layer (slimmed but load-bearing) survives to attribute these (§5).
- **C3 — there is no deterministic join from an SSO portal sign-in to the credentials it vends.** The `GetRoleCredentials` CloudTrail event redacts the vended credentials (`responseElements` are `HIDDEN_DUE_TO_SECURITY_REASONS`/null), so CLI sessions can't be keyed to the portal sign-in. They are keyed to the vended credential itself (`key#accessKeyId`), which needs no correlation. Portal-sign-in parentage is an optional later enrichment, not a 1.0 dependency (§8).

## 3. Identity resolution

### 3.1 Credential group

The atomic unit of resolution — for identity here *and* for session anchors in §4 — is the **credential group**: all events sharing one credential. A group is a logical set keyed on the credential; each ingested batch contributes whatever fragment of that group appears in its S3 file, and §3.3 stitches fragments that span files.

```
cred_group_key(event):
  if sessionCredentialFromConsole == "true"
     or (accessKeyId == "" and creationDate != "")
                                               → "rc#" + principalId + "#" + creationDate
  elif userIdentity.accessKeyId != ""          → "ak#" + accessKeyId
  else                                         → "ev#" + eventID          # ungroupable, resolves alone
```

Console-ness is checked *before* the access key: the console mints a fresh access key per request, so keying console events on `accessKeyId` would shatter one console session into single-event groups — defeating the "any event in the group resolves the group" C1 mitigation, since a per-request key never recurs for a `cred#` link to catch. The stable console credential is `creationDate`. The `rc#` key uses the full `principalId` (roleID:sessionName), not bare roleID: grouping runs before identity is known, so two humans on the same role in the same second must not share a group.

### 3.2 Person tiers

One `person_key` per credential group, first tier that matches *any event in the group* (the C1 mitigation):

| Tier | Condition (any event in group) | person_key | Who this covers |
|---|---|---|---|
| 1 | `onBehalfOf` present | `idc#<identityStoreArn>#<userId>` | Identity Center humans (CLI, console, agents) |
| 2 | chain/login/MCP/cred link resolves (§5) | parent link's `person_key` | chained roles, `aws login`, MCP agents, cross-batch C1 |
| 3 | principalId session name contains `@` | `email#<lowercased-email>` | direct SAML federation, any role session named with an email |
| 4 | `type == "IAMUser"` | `iamuser#<userIdentity.arn>` | humans on long-lived keys — pre-1.0 silently dropped these |
| 5 | `type == "Root"` | `root#<accountId>` | root usage — always worth a session |
| — | none of the above | no person, no session | service-internal traffic; still aggregated into roles/services/resources |

Tier 1 keys on `identityStoreArn#userId`, never `userId` alone (evidence in §10). Tiers are disjoint prefixes so a person can never merge across tiers by accident. Tier 3 is not a legacy edge case: for a customer on direct SAML federation it is 100% of traffic. A direct-SAML shop whose session names are not emails resolves to no person (events still hit role/service/resource aggregates); this is an accepted limitation (§8), addressable with a later `saml#` tier.

### 3.3 Credential→person links (cross-batch C1 mitigation)

A credential group can span S3 files: batch A has the `onBehalfOf`-bearing events, batch B (same `accessKeyId`) has none. A link record in `trailtool-identity-links` (§6.3) is written whenever a group resolves at tier 1:

```
PK "cred#<accessKeyId>"                → { person_key, role_arn, anchor, ttl: +12h }   # CLI/SDK groups
PK "cred#<principalId>#<creationDate>" → same                                          # console groups
```

The `anchor` attribute carries the group's resolved session anchor so a later batch of the same credential lands in the same session even if the fields that decided the anchor (e.g. `signInSessionArn`) don't appear in that batch — the C1 discipline applied to session identity (§4.1).

## 4. Session boundaries

### 4.1 The anchor cascade

A **Session** is all events sharing one `(person_key, roleID, anchor)`. The anchor is resolved *per credential group*, first rule where any event in the group matches:

```
anchor(group):
  if any event has signInSessionArn            → "sis#" + signInSessionArn
      # a literal AWS sign-in session: MCP agents, aws login, and AWS's ongoing
      # rollout to ordinary sessions. Survives credential rotation underneath.
  elif any event has sessionCredentialFromConsole == "true"
       or (accessKeyId == "" and creationDate != "")
                                               → "web#" + roleID + "#" + creationDate
      # one console sign-in = one stable creationDate across its per-request keys
  elif accessKeyId starts with "ASIA"          → "key#" + accessKeyId
      # one temporary credential = one session: CLI/SDK, chained roles, SAML
  else                                         → windowed fallback (§4.2)
      # AKIA long-lived keys, root, credential-less events
```

Three points about the cascade are non-obvious:

- **OAuth grants are excluded.** Only `sessionContext.signInSessionArn` marks an event as made *under* a sign-in session. A `CreateOAuth2Token` grant is excluded from anchor consideration outright — its ARN names the session it *mints*, not the session the grant was made under; letting it decide the group's anchor would re-key the authorizing human's session.
- **Credential-link continuity.** Because `signInSessionArn` may be stamped per-service (like `onBehalfOf`), the group's `cred#` link carries the anchor forward to batches where the ARN doesn't appear (§3.3). A credential can therefore never split across two anchors.
- **session_type is derived.** It falls out of the anchor plus links: `sis#` + `mcp#` link → `agent`; `sis#`/`key#` + `login#` link → `login`; `web#` → `web`; otherwise `cli`. Chained-role sessions are `cli` with `assumed_from_session` set. UA classification (`ClassifySessionType`) is a display label only and never separates channels — concurrent console + CLI + agent activity for one person and role lands in three disjoint anchor keyspaces (`web#`, `key#`, `sis#`) by construction.

### 4.2 Windowed fallback (the only place time guesses)

Events whose group reaches the last cascade arm — IAM users on `AKIA…` keys, root, ungroupable events with a resolved person — fall back to idle-gap windows: a maximal run of events for `(person_key, roleID-slot, channel)` with consecutive gaps ≤ `IDLE_GAP` (default 30m, env-overridable). This inherits pre-1.0's cross-batch machinery, scoped small:

- Fetch potentially-adjacent windowed sessions in one Query (`±2×IDLE_GAP`); extend/merge/fold overlapping runs; write back with a `version` conditional (retry ≤3 on conflict). A fold that deletes records runs as one `TransactWriteItems` so a lost race cannot observe or double-merge a partially applied fold. SK is sticky ("first-written start"); true `start_time`/`end_time` are attributes.
- Order-independence (same event set → same sessions under any batch partitioning) is the core property test. Anchored sessions satisfy it trivially; only windowed ones exercise the merge logic.

### 4.3 Ingest idempotency

- **File-level marker:** `trailtool-ingested-files` table, PK = S3 object key, written after successful processing, TTL 30 days. Skip files already marked. (A crash mid-batch can still double-write a partial batch on retry — same exposure as pre-1.0, accepted for 1.0.)
- **In-batch dedupe by `eventID`:** org trails duplicate global-service events across region files; drop repeated eventIDs within a batch. Cross-file duplicate eventIDs are accepted for 1.0 (rare; bounded error).

## 5. Correlation and attribution

The chain/login/MCP correlation layer (C2) is the one piece of pre-1.0's session-keying that survives, slimmed. In-batch attribution runs in the aggregator; cross-batch link reads go through `trailtool-identity-links`.

### 5.1 Role chaining (C2 — the layer that must survive)

On each `AssumeRole` event whose caller resolves to a person: write `chain#<issuedAccessKeyId>` (from `responseElements`) and `chain#<assumedRoleID>#<eventTime>` links carrying the person_key, parent session ref, assumed role ARN, session tags, and session policy. The child session is written under the *person's own partition* with `assumed_from_session` set — so "all of Alice's sessions" naturally includes her chained ones. This is structurally pre-1.0's Pass 1 / Pass 2 logic with the fragile `email:roleID:creationDate` parent keys replaced by stable person keys and anchors.

Both chaining channels are covered, and the child's anchor comes from the ordinary cascade:

- **CLI chaining** (`aws sts assume-role`): the child credential is the issued `ASIA…` key → one `key#` session, typed `cli`. The `chain#<issuedAccessKeyId>` link resolves identity + parent.
- **Console switch-role**: the console's `AssumeRole` vends a child *console* session — fresh access key per request but one `creationDate`, like a normal console session. The cascade anchors it `web#<assumedRoleID>#<creationDate>`, typed `web`; the `chain#<assumedRoleID>#<creationDate>` link resolves identity + parent. Switching back, or switching again, mints a new `creationDate` → a new deterministic session, each with its own `assumed_from_session`.

Direct SAML federation gets the same treatment for free: `AssumeRoleWithSAML` logs the issued key in `responseElements`, so each browser re-auth is one deterministic session.

### 5.2 `aws login` (PKCE OAuth) grants

Same shape as pre-1.0's login pre-pass, with one fix mandated by the July 2025 Identity Center changes: resolve the authorizing human from the `CreateOAuth2Token` event's own `onBehalfOf` (fall back to principalId email only if absent). Never depend on principalId being present on `signin.amazonaws.com` events. Vended-session events resolve at tier 2 via `login#<roleID>#<creationDate>`; the session (whether anchored `sis#` or `key#`) gets `session_type = login`. A `web#` session matching a `login#` link is the *authorizing* console session (it shares the roleID+creationDate the link is keyed on) and stays typed `web`.

### 5.3 MCP agents

A `CreateOAuth2Token` whose `requestParameters.resource` is the AWS MCP Server writes `mcp#<signInSessionArn>`; events carrying that `signInSessionArn` resolve to the authorizing person at tier 2, anchor at `sis#`, and are typed `agent`. **Guard:** `session_type = agent` only on an `mcp#` link match — never on mere presence of `signInSessionArn`, which AWS is rolling out to ordinary console/CLI sessions (§10). Agent credentials may rotate frequently, but every call made with the OAuth token carries the same `signInSessionArn`, so `sis#` groups across rotations.

## 6. Storage model

New tables under clean names — no version suffix anywhere. The old `trailtool-*-aggregated` tables have explicit `TableName`s in `ingestor/template.yaml` and can't be schema-replaced in place under the same name, so the rename is also what makes the CloudFormation update work: one deploy removes the old table resources and creates the new ones (§7 covers the operational cutover).

### 6.1 `trailtool-sessions`

```
PK: customerId # person_key
SK: anchor # roleID                              # deterministic → cross-batch writes hit the same item
    (windowed fallback: "win#" + roleID + "#" + firstWrittenStart, sticky)
Attributes:
  person_key, role_arn, role_id, account_id
  session_type: cli | web | agent | login
  start_time, end_time (true bounds), version (optimistic lock; load-bearing only for win#)
  events_count, source_ips[], clients[], event_counts{}, resources_accessed{}
                                                  # clients[]: per-client ClientAggregate parsed from userAgent
                                                  # (category/name/version/os/arch, per-client counts, commands,
                                                  # first/last seen, capped raw samples) — replaces user_agents[]
  service_driven_event_count                      # events with userIdentity.invokedBy set (§7)
  sign_in_session_arn (when present)
  assumed_from_session, assumed_from_role_arn     # chained child → parent session ref (§5.1)
  chained_session_refs[]                          # parent → children
  denied_* fields, clickops_* fields              # carried over from pre-1.0 shape
GSI role_index:    PK customerId#role_id,    SK start_time
GSI account_index: PK customerId#account_id, SK start_time
```

Session refs are `person_key|sk`. "All of one person's sessions" is one Query on the partition; the CLI sorts by `start_time` (SKs are anchors, not timestamps). The global `time_index` GSI is skipped for 1.0: `customerId`-keyed GSIs hot-partition under SaaS load, so "recent sessions across everyone" scans-with-limit until a real need justifies the GSI.

### 6.2 `trailtool-people`

```
PK: customerId, SK: person_key
Attributes: tier, email (primary), emails_seen[], display_name, first/last_seen, counters…
GSI email_index: PK customerId, SK email → person_key
```

Email→person is **one-to-many**: offboard/rehire mints a new immutable Identity Center `userId` for the same email, and the same human may exist as `idc#…` and `email#…` (pre/post Identity Center adoption). `--user` resolves to all matches (§7). Identity Center usernames are not required to be emails — when the session name has no `@`, record it in `emails_seen` anyway (it's the username) but don't build a tier-3 key from it.

### 6.3 `trailtool-identity-links` (replaces `chain-links`, same access pattern)

```
PK (single string key, disjoint prefixes), all TTL 12h (STS max):
  cred#<accessKeyId>                     → person_key, role_arn, anchor       (§3.3, §4.1)
  cred#<principalId>#<creationDate>      → same                                (§3.3, console)
  chain#<issuedAccessKeyId>              → person_key, parent_session_ref, assumed_role_arn,
                                            session_tags{}, session_policy     (§5.1, CLI)
  chain#<assumedRoleID>#<creationDate>   → same                                (§5.1, console switch-role)
  login#<roleID>#<creationDate>          → person_key, parent_session_ref      (§5.2)
  mcp#<signInSessionArn>                 → person_key, parent_session_ref, mcp_resource (§5.3)
```

Roles / Services / Resources / Accounts tables keep their pre-1.0 shapes (`ingestor/lib/types/types.go`), renamed without the `-aggregated` suffix, with person references switched from email to `person_key`. The role→role relationship graph is derivable from `chain#` links + session records; no dedicated table.

### 6.4 Parser fields

The model above requires these fields on the parsed types (`ingestor/lib/types/types.go`):

```
CloudTrailRecord: EventID, AwsRegion, RecipientAccountID
UserIdentity:     OnBehalfOf{ UserID, IdentityStoreArn }, InvokedBy, UserName, CredentialID
SessionContext:   SourceIdentity                        # parsed; log presence, don't key on it
```

`ClassifySessionType`, `IsClickOpsOperation`, and `NormalizeUserAgent` survive as display labels / windowed-fallback channel only — they no longer gate whether a session exists.

## 7. CLI behavior

- **Reads query the person partition** instead of scan+filter. `--user <email>` → `email_index` → possibly multiple person_keys → query each, merge, note the split in output ("2 identities matched alice@…").
- **`sessions list` sorts by `start_time`.** Adjacent credential-refresh sessions read naturally (same person, same role, back-to-back). Optional later: group rows by sign-in parentage once portal-correlation enrichment exists (§8).
- **Chained-session rendering** uses `assumed_from_session` / `chained_session_refs` (real refs) instead of parsing timestamps out of composite keys.
- **`invokedBy` handling:** forward-access-session events (an AWS service calling another with the human's credentials — CloudFormation fan-out, etc.) are included in the session but counted in `service_driven_event_count` and excluded from ClickOps flagging. The pre-1.0 user-agent blocklist (`IsValidUserAgent`) is demoted to a secondary heuristic behind this.
- **Pre-1.0 stack detection.** Deploying the 1.0 ingestor deletes the pre-1.0 tables (§6). When a query hits a missing table, the CLI runs one `DescribeTable` on `trailtool-sessions-aggregated`; if the legacy table exists, it fails with a clear message rather than a raw AWS error:

  ```
  This version of trailtool requires the 1.0 ingestor stack.
  Redeploy it:  cd ingestor && make deploy
  Note: redeploying deletes the pre-1.0 tables — existing aggregated
  data is not migrated. History rebuilds from CloudTrail going forward.
  ```

  Detection is by table name only — no version markers stored anywhere.
- **Version + deprecation notice.** Inject `main.version` via goreleaser ldflags → Cobra `rootCmd.Version`. Startup notice on stderr, non-fatal, suppressible via `--quiet` / `TRAILTOOL_NO_UPGRADE_NOTICE=1`. The final pre-1.0 release prints an end-of-support date (GA + 90 days, hard-coded at release time) with an upgrade hint.

## 8. Accepted limitations and risks

- **Portal-sign-in parentage** ("these 5 CLI sessions came from one `aws sso login`") is deferred: `GetRoleCredentials` hides the vended credentials (C3), so linking CLI sessions to their sign-in needs a `creationDate`-echo correlation. Useful for display grouping; not a 1.0 dependency.
- **Non-email direct-SAML session names** resolve to no person, no session (role/service/resource aggregates are still written). A `saml#` tier can be added later if real customers hit it.
- **Backfill is forward-only.** Events predating AWS's `onBehalfOf` rollout would land in tier-3 keys and split people across keyspaces; backfill, if ever offered, needs an email-based stitch pass. Out of scope for 1.0.
- **CLI refresh cadence.** Refreshes happen at the permission-set session duration (default 1h, max 12h) — hours, not minutes; worst realistic case ~8 CLI sessions per person per role per day. If that reads as noise in practice, the fix is CLI-side display grouping, never storage windowing. Live validation records the actual sessions/person/day.
- **Mid-batch crash** can double-write a partial batch on retry (§4.3) — same exposure as pre-1.0.

## 9. Verification plan

`go test ./...` must be green in both modules (root and `ingestor/`). The harness carries over: real-JSON fixtures in `ingestor/testdata/` driven through the aggregator's test entrypoint, plus table-driven unit tests.

### 9.1 Unit — identity resolution & anchors

Acceptance scenarios:

1. One CLI credential spanning a 4h wall-clock boundary → 1 session (the pre-1.0 split bug; SSO creds run up to 12h).
2. Credential refresh mid-work (new `ASIA…` key) → 2 sessions, same person_key on both.
3. Console session: 7 per-request access keys, one `creationDate` → 1 `web#` session.
4. **C1:** a credential group where 3 of 5 events carry `onBehalfOf` → all 5 in one tier-1 session; none leak to tier 3.
5. **C1 cross-batch:** batch A resolves `ak#X` with anchor `sis#S`; batch B has `ak#X` events with no `onBehalfOf` and no `signInSessionArn` → tier 2 + anchor via the `cred#X` link → same person, same session.
6. Same `userId`, different `identityStoreArn` → 2 persons, never merged.
7. Tier 3: SAML role session (`AROA…:alice@example.com`, no `onBehalfOf`) → `email#` person; its issued key is one `key#` session.
8. Tiers 4/5: IAMUser (`AKIA…`) and Root events → persons under `iamuser#`/`root#`; two bouts 1h apart on one AKIA key → 2 `win#` sessions.
9. No tier matches (service-internal) → no session; role/service/resource aggregates still written.
10. Agent credentials rotating under one `signInSessionArn` → 1 `sis#` session; typed `agent` only with an `mcp#` link, else not.
11. Concurrent web + CLI + agent for one person and role → 3 sessions, correctly typed (channel separation by construction).
12. `invokedBy` events → included, counted in `service_driven_event_count`, excluded from ClickOps.
13. Console switch-role: parent web session + `AssumeRole` + child console events → child is one `web#` session with `assumed_from_session` pointing at the parent.
14. CLI pointed at a pre-1.0 stack → redeploy message, not a raw AWS error.

### 9.2 Unit — windowed fallback & idempotency

1. Windowed run overlapping an existing `win#` session → extended (start/end/counts), SK unchanged; a late run before its start moves `start_time`, SK sticky.
2. Windowed run bridging two existing sessions → folded into the earliest-SK record, the other deleted.
3. Conditional-write conflict → retry path re-reads and converges.
4. Redelivered file (marker present) → no double counts. Duplicate `eventID` within a batch → counted once.

### 9.3 Property tests (the real safety net)

- **Partition-invariance:** for a fixed event set, any split into batches, in any order, yields identical final session records. Run every fixture through 2–3 random partitions. Anchored sessions satisfy this trivially; the test earns its keep on `win#` sessions and on anchor continuity via `cred#` links.
- **No cross-person merge:** every session's events share one person_key. Assert over all fixtures.

### 9.4 Live validation (once, before tagging)

Deploy to sandbox. Generate a long CLI session with a real refresh, a console session, an assume-role chain, and an MCP call. Assert via the CLI that the refresh produced two cleanly-bounded sessions for one person (not a 4h-window split), the console session is one row, the chain attributes, and nothing merged across people. Record before/after session counts in the release PR. Open questions to resolve here (each just moves work between existing code paths):

- Is `sessionCredentialFromConsole` reliably present on console-session events across services? It gates both the `rc#` credential-group arm (§3.1) and the `web#` anchor arm (§4.1).
- Does a plain `aws sts assume-role` from an SSO session yield child events with `onBehalfOf`? (Expected: no → tier 2 does the work — this is C2, re-confirmed live.)
- What does `CreateOAuth2Token`'s userIdentity look like post-Nov-2025 — does it carry `onBehalfOf`, and is `principalId` still present?
- Do ordinary console/CLI sessions now carry `signInSessionArn`, and is it stamped on every event of a session or per-service?
- Do `aws login`-vended session events carry `signInSessionArn`? (If yes they anchor `sis#`; if no, `key#` — either works.)

## 10. Appendix: evidence

From a live probe of a real Identity Center (Google SAML) environment, aggregated over 8 Lambda invocations:

```
cli_agent_events=31  onBehalfOf.userId=27 (87%)  sourceIdentity=0  credentialId=0  signInSessionArn=3 (10%)
```

- **CLI/SSO credentials rotate silently.** Each refresh re-runs `GetRoleCredentials` → new `accessKeyId` *and* new `sessionContext.creationDate`. Observed: two CLI `creationDate`s 24s apart, different `ASIA…` keys, same `onBehalfOf.userId`. Under the 1.0 model this is two sessions belonging to one person — deterministic, not a bug.
- **Console issues a fresh access key per request** but keeps one `creationDate` and one `onBehalfOf.userId` for the whole console session (observed 7+ keys, one session). `creationDate` is the web anchor; the per-request keys must never become per-event sessions.
- **`onBehalfOf.userId` is identical across CLI + web + MCP-agent** traffic for the same human, and stable across refreshes.
- **`sourceIdentity` and `credentialId`: 0%** on role-session events. `credentialId` is bearer-token-only — it appears on `IdentityCenterUser` events (portal, OIDC `CreateToken`) as the access-portal session ID. Not usable as a role-session key. This is why tier 1 keys on `identityStoreArn#userId`, never `userId` alone.
- **`GetRoleCredentials` does not log vended credentials.** Its CloudTrail `responseElements` are redacted (`HIDDEN_DUE_TO_SECURITY_REASONS`/null), per the AWS Identity Center CloudTrail examples and independent writeups. This forces C3.
- **`signInSessionArn` is broadening.** Observed only on MCP-agent events (10%), but the CloudTrail userIdentity reference now shows it on generic console `AssumedRole` examples — AWS is rolling it out as the general `aws:SignInSessionArn` key. When present it is the best anchor (a literal sign-in session); never infer "agent" from its mere presence (§5.3).
- **July 2025 Identity Center event changes** (fully deployed 2025-11-26): Identity Center's own events carry `onBehalfOf` + `credentialId` and type `IdentityCenterUser`, no `principalId`/`userName`. Member-account `AWSReservedSSO` role-session events are unchanged. Consequence: never parse email out of `signin.amazonaws.com` events; use their `onBehalfOf` (§5.2).

Doc sources: [CloudTrail userIdentity element](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html), [Understanding CloudTrail events for IAM Identity Center](https://docs.aws.amazon.com/singlesignon/latest/userguide/understanding-sso-entries.html), [Important changes to CloudTrail events for IAM Identity Center](https://aws.amazon.com/blogs/security/modifications-to-aws-cloudtrail-event-data-of-iam-identity-center/).
