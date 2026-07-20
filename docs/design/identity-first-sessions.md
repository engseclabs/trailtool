# TrailTool 1.0 — Identity-First Session Model

For status see https://github.com/engseclabs/trailtool/issues/12

## Contents

0. [TL;DR and design constraints](#0-tldr-and-design-constraints)
1. [Evidence base](#1-evidence-base)
2. [Identity resolution (credential groups)](#2-identity-resolution--credential-groups-and-person-tiers)
3. [Session anchors (deterministic; windowing last)](#3-session-anchors--deterministic-session-identity-windowing-as-last-resort)
4. [Data model & DynamoDB schema](#4-data-model--dynamodb-schema)
5. [Chained roles, login, MCP attribution](#5-chained-roles-aws-login-mcp-agents)
6. [Parser/type additions & ingest hygiene](#6-parsertype-additions--ingest-hygiene)
7. [CLI 1.0 changes](#7-cli-10-changes)
8. [Test plan](#8-test-plan)
9. [Rollout](#9-rollout)
10. [Decisions (resolved) & sandbox verifications](#10-decisions-resolved--sandbox-verifications)
11. [Code map: reuse / replace / delete](#11-code-map--reuse--replace--delete)

## 0. TL;DR and design constraints

Pre-1.0 TrailTool has no stable identifier for a human across credential refreshes, so it keys sessions on time hacks (a 4-hour window for CLI/SDK, exact `sessionContext.creationDate` for web) and bolts on a TTL'd `chain-links` table to attribute assumed-role / `aws login` / MCP-agent traffic to a person. 1.0 rebuilds the model on two separated axes:

- **Who** — identity resolves per *credential group* through five fallback tiers headed by `userIdentity.onBehalfOf` (§2). *Implemented.*
- **Which session** — a session is the lifetime of a credential or sign-in, resolved *deterministically* from fields AWS stamps on the events: sign-in session ARN, console session creation date, or the temporary access key itself. Time-window guessing survives only as the last-resort fallback for principals that have no credential boundary at all (long-lived IAM keys, root) (§3). *Implemented.*

> **Design principle (v3):** tie a session to its authentication. Sign in to the console → everything under that sign-in's `creationDate` is one session. Get a CLI credential → everything that credential does is one session; a refresh mints a new credential and that is a *new session, deliberately* — a session equals one credential's blast radius. Windowing sucks; it is confined to principals where AWS gives us no boundary.

Three facts, verified against AWS docs and a live probe, constrain the design:

- **C1 — `onBehalfOf` is per-service, not per-session.** One human session can emit some events with it and some without. Therefore identity resolves per credential group, never per event (§2). The same discipline applies to `signInSessionArn`: any event in a credential group carrying it decides the whole group's anchor (§3.1).
- **C2 — `onBehalfOf` does not survive plain role chaining.** A plain `aws sts assume-role` from an SSO session yields a child session with no `onBehalfOf`. The chain-link correlation layer survives into 1.0, slimmed but load-bearing (§5).
- **C3 — there is no deterministic join from an SSO portal sign-in to the credentials it vends.** The `GetRoleCredentials` CloudTrail event hides the vended credentials (`responseElements` redacted), so CLI sessions cannot be keyed to the portal sign-in — they are keyed to the vended credential itself (`key#accessKeyId`), which needs no correlation at all. Portal-sign-in parentage ("these 5 CLI sessions came from one `aws sso login`") is an optional later enrichment via time-echo correlation, not a 1.0 dependency (§10).

Because anchors are deterministic, cross-batch session assembly is a plain additive merge onto a known key — the same shape as the existing `Merge*` code. The v2 read-extend-merge/optimistic-locking machinery survives only inside the windowed fallback (§3.2).

**Hard cutover, no data migration, no version markers:** 1.0 tables get clean names (`trailtool-sessions`, `trailtool-people`, `trailtool-identity-links`, …) — the legacy `-aggregated` suffix retires and nothing in code, schema, or infra says "v1". Deploying the 1.0 ingestor replaces the stack destructively: pre-1.0 tables and their data are deleted, history starts fresh from CloudTrail. The 1.0 CLI detects a pre-1.0 stack and says exactly that (§7).

## 1. Evidence base

From a live probe of a real Identity Center (Google SAML) environment, aggregated over 8 Lambda invocations:

```
cli_agent_events=31  onBehalfOf.userId=27 (87%)  sourceIdentity=0  credentialId=0  signInSessionArn=3 (10%)
```

- **CLI/SSO credentials rotate silently.** Each refresh re-runs `GetRoleCredentials` → new `accessKeyId` *and* new `sessionContext.creationDate`. Observed: two CLI `creationDate`s 24s apart, different `ASIA…` keys, same `onBehalfOf.userId`. Under v3 semantics this is two sessions belonging to one person — deterministic, not a bug.
- **Console issues a fresh access key per request** but keeps one `creationDate` and one `onBehalfOf.userId` for the whole console session (observed 7+ keys, one session). `creationDate` is the web anchor; the per-request keys must never become per-event sessions.
- **`onBehalfOf.userId` is identical across CLI + web + MCP-agent** traffic for the same human, and stable across refreshes.
- **`sourceIdentity` and `credentialId`: 0%** on role-session events. `credentialId` is bearer-token-only — it appears on `IdentityCenterUser` events (portal, OIDC `CreateToken`) as the access-portal session ID. Useful someday for portal parentage; not usable as a role-session key.
- **`GetRoleCredentials` does not log vended credentials.** Its CloudTrail `responseElements` are redacted (`HIDDEN_DUE_TO_SECURITY_REASONS` / null), per the AWS Identity Center CloudTrail examples and independent writeups. This is what forces C3.
- **`signInSessionArn` is broadening.** Observed only on MCP-agent events (10%), but the CloudTrail userIdentity reference now shows it on generic console `AssumedRole` examples — AWS is rolling it out as the general `aws:SignInSessionArn` key. When present it is the best anchor (a literal sign-in session); never infer "agent" from its mere presence (§5.3).
- **July 2025 Identity Center event changes** (fully deployed 2025-11-26): Identity Center's own events carry `onBehalfOf` + `credentialId` and type `IdentityCenterUser`, no `principalId`/`userName`. Member-account `AWSReservedSSO` role-session events are unchanged. Consequence: never parse email out of `signin.amazonaws.com` events; use their `onBehalfOf` (§5.2).

Doc sources: [CloudTrail userIdentity element](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html), [Understanding CloudTrail events for IAM Identity Center](https://docs.aws.amazon.com/singlesignon/latest/userguide/understanding-sso-entries.html), [Important changes to CloudTrail events for IAM Identity Center](https://aws.amazon.com/blogs/security/modifications-to-aws-cloudtrail-event-data-of-iam-identity-center/).

## 2. Identity resolution — credential groups and person tiers

*Implemented — `ingestor/lib/identity`. The code is the spec.*

### 2.1 Credential group

The atomic unit of resolution — for identity here *and* for session anchors in §3 — is the **credential group**: all events in a batch that share one credential.

```
cred_group_key(event):
  if sessionCredentialFromConsole == "true"
     or (accessKeyId == "" and creationDate != "")
                                               → "rc#" + principalId + "#" + creationDate
  elif userIdentity.accessKeyId != ""          → "ak#" + accessKeyId
  else                                         → "ev#" + eventID          # ungroupable, resolves alone
```

Console-ness is checked *before* the access key (v3.2 fix): the console mints a fresh access key per request, so keying console events on `accessKeyId` would shatter one console session into single-event groups — defeating the "any event in the group resolves the group" C1 mitigation, since a per-request key never recurs for a `cred#` link to catch. The stable console credential is `creationDate`. The `rc#` key uses the full `principalId` (roleID:sessionName), not bare roleID: grouping runs before identity is known, so two humans on the same role in the same second must not share a group (the §3 anchor doesn't need this because `person_key` is part of the session key).

### 2.2 Person tiers

One `person_key` per credential group, first tier that matches *any event in the group* (the C1 mitigation):

| Tier | Condition (any event in group) | person_key | Who this covers |
|---|---|---|---|
| 1 | `onBehalfOf` present | `idc#<identityStoreArn>#<userId>` | Identity Center humans (CLI, console, agents) |
| 2 | chain/login/MCP/cred link resolves (§5) | parent link's `person_key` | chained roles, `aws login`, MCP agents, cross-batch C1 |
| 3 | principalId session name contains `@` | `email#<lowercased-email>` | direct SAML federation, any role session named with an email |
| 4 | `type == "IAMUser"` | `iamuser#<userIdentity.arn>` | humans on long-lived keys — pre-1.0 silently dropped these |
| 5 | `type == "Root"` | `root#<accountId>` | root usage — always worth a session |
| — | none of the above | no person, no session | service-internal traffic; still aggregated into roles/services/resources |

**Uniqueness rule:** tier 1 keys on `identityStoreArn#userId`, never `userId` alone. Tiers are disjoint prefixes (`idc#`, `email#`, `iamuser#`, `root#`) so a person can never merge across tiers by accident. Tier 3 is not a legacy edge case: for a customer on direct SAML federation it's 100% of traffic. Known gap, accepted for 1.0: a direct-SAML shop whose session names are not emails resolves to no person (events still hit role/service/resource aggregates); a `saml#` tier can be added later if it bites.

### 2.3 Credential→person links (cross-batch C1 mitigation)

A credential group can span S3 files: batch A has the `onBehalfOf`-bearing events, batch B (same `accessKeyId`) has none. Fix with a link record in `trailtool-identity-links` (§4.3), written whenever a group resolves at tier 1:

```
PK "cred#<accessKeyId>"                → { person_key, role_arn, anchor, ttl: +12h }   # CLI/SDK groups
PK "cred#<principalId>#<creationDate>" → same                                          # console groups
```

The `anchor` attribute (new in v3) carries the group's resolved session anchor so a later batch of the same credential lands in the same session even if the fields that decided the anchor (e.g. `signInSessionArn`) don't appear in that batch — the C1 discipline applied to session identity (§3.1).

## 3. Session anchors — deterministic session identity, windowing as last resort

*Implemented (in-batch) — anchor cascade in `ingestor/lib/identity`, assembly in `ingestor/lib/aggregator`; cross-batch link reads land with the §5 port.*

### 3.1 The anchor cascade

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
  else                                         → windowed fallback (§3.2)
      # AKIA long-lived keys, root, credential-less events
```

Implementation note: only `sessionContext.signInSessionArn` marks an event as made *under* a sign-in session. A `CreateOAuth2Token` grant is excluded from anchor consideration outright — its ARN names the session it mints, not the session the grant was made under; letting it decide the group's anchor would re-key the authorizing human's session.

- **Refresh boundary is deliberate.** aws-cli/botocore refreshing SSO credentials mints a new `ASIA…` key → a new session. A session equals one credential's lifetime and blast radius; adjacent sessions from the same sign-in read fine in the CLI (same person, seconds apart). No correlation logic, no guessing.
- **MCP/agent rotation doesn't fragment.** Agent credentials may rotate frequently, but every call made with the OAuth token carries `aws:SignInSessionArn` — `sis#` groups across rotations. Typing as `agent` still requires an `mcp#` grant link (§5.3); presence of the ARN alone never implies agent.
- **Channels can't merge by construction.** Concurrent console + CLI + agent activity for one person and role lands in three disjoint anchor keyspaces (`web#`, `key#`, `sis#`) — no user-agent guessing in the grouping. UA classification (`ClassifySessionType`) remains a display label only.
- **Rollout safety:** because `signInSessionArn` may be stamped per-service (like `onBehalfOf`), the anchor is decided per credential group, and the group's `cred#` link carries the anchor forward to batches where the ARN doesn't appear (§2.3). A credential can therefore never split across two anchors.
- **session_type** falls out of the anchor plus links: `sis#` + `mcp#` link → `agent`; `sis#`/`key#` + `login#` link → `login`; `web#` → `web`; otherwise `cli`. Chained-role sessions are `cli` with `assumed_from_session` set.

### 3.2 Windowed fallback (the only place time guesses)

Events whose group reaches the last cascade arm — IAM users on `AKIA…` keys, root, ungroupable events with a resolved person — fall back to idle-gap windows: a maximal run of events for `(person_key, roleID-slot, channel)` with consecutive gaps ≤ `IDLE_GAP` (default 30m, env-overridable). This inherits v2's cross-batch machinery, scoped small:

- Fetch potentially-adjacent windowed sessions in one Query (`±2×IDLE_GAP`); extend/merge/fold overlapping runs; write back with a `version` conditional (retry ≤3 on conflict). A fold that deletes records runs as one `TransactWriteItems` so a lost race can never observe or double-merge a partially applied fold. SK is sticky ("first-written start"); true `start_time`/`end_time` are attributes.
- Order-independence (same event set → same sessions under any batch partitioning) remains the core property test, now cheap to satisfy: anchored sessions are trivially order-independent; only windowed ones exercise the merge logic.

### 3.3 Ingest idempotency (pre-1.0 double-counts on redelivery)

- **File-level marker:** `trailtool-ingested-files` table, PK = S3 object key, written after successful processing, TTL 30 days. Skip files already marked. (A crash mid-batch can still double-write a partial batch on retry — same exposure as pre-1.0, documented, acceptable for 1.0.)
- **In-batch dedupe by `eventID`:** org trails duplicate global-service events across region files; drop repeated eventIDs within a batch. Cross-file duplicate eventIDs accepted for 1.0 (rare; bounded error).

## 4. Data model & DynamoDB schema

New tables under clean names — no version suffix anywhere. The old `trailtool-*-aggregated` tables (explicit `TableName`s in `ingestor/template.yaml`) can't be schema-replaced in place under the same name, so the rename is also what makes the CloudFormation update work: one deploy removes the old table resources and creates the new ones. Data is deleted with them — accepted (§9).

### 4.1 `trailtool-sessions`

```
PK: customerId # person_key
SK: anchor # roleID                              # deterministic → cross-batch writes hit the same item
    (windowed fallback: "win#" + roleID + "#" + firstWrittenStart, sticky)
Attributes:
  person_key, role_arn, role_id, account_id
  session_type: cli | web | agent | login
  start_time, end_time (true bounds), version (optimistic lock; load-bearing only for win#)
  events_count, source_ips[], user_agents[], event_counts{}, resources_accessed{}
  service_driven_event_count                      # events with userIdentity.invokedBy set (§6)
  sign_in_session_arn (when present)
  assumed_from_session, assumed_from_role_arn     # chained child → parent session ref (§5.1)
  chained_session_refs[]                          # parent → children
  denied_* fields, clickops_* fields              # carried over from pre-1.0 shape
GSI role_index:    PK customerId#role_id,    SK start_time
GSI account_index: PK customerId#account_id, SK start_time
```

Session refs are `person_key|sk`. "All of one person's sessions" is one Query on the partition; the CLI sorts by `start_time` (SKs are anchors, not timestamps). Skip the global `time_index` GSI for 1.0 — `customerId`-keyed GSIs hot-partition under SaaS load; "recent sessions across everyone" can scan-with-limit until it hurts.

### 4.2 `trailtool-people`

```
PK: customerId, SK: person_key
Attributes: tier, email (primary), emails_seen[], display_name, first/last_seen, counters…
GSI email_index: PK customerId, SK email → person_key
```

Email→person is **one-to-many**: offboard/rehire mints a new immutable Identity Center `userId` for the same email, and the same human may exist as `idc#…` and `email#…` (pre/post Identity Center adoption). `--user` resolves to all matches (§7). Identity Center usernames are not required to be emails — when the session name has no `@`, record it in `emails_seen` anyway (it's the username) but don't build a tier-3 key from it.

### 4.3 `trailtool-identity-links` (replaces `chain-links`, same access pattern)

```
PK (single string key, disjoint prefixes), all TTL 12h (STS max):
  cred#<accessKeyId>                     → person_key, role_arn, anchor       (§2.3, §3.1)
  cred#<principalId>#<creationDate>      → same                                (§2.3, console)
  chain#<issuedAccessKeyId>              → person_key, parent_session_ref, assumed_role_arn,
                                            session_tags{}, session_policy     (§5.1, CLI)
  chain#<assumedRoleID>#<creationDate>   → same                                (§5.1, console switch-role)
  login#<roleID>#<creationDate>          → person_key, parent_session_ref      (§5.2)
  mcp#<signInSessionArn>                 → person_key, parent_session_ref, mcp_resource (§5.3)
```

Roles / Services / Resources / Accounts tables: same shapes as pre-1.0 (`ingestor/lib/types/types.go`), renamed without the `-aggregated` suffix (`trailtool-roles`, `trailtool-services`, …), person references switched from email to `person_key`. The role→role relationship graph is derivable from `chain#` links + session records; no dedicated table.

## 5. Chained roles, `aws login`, MCP agents

*In-batch attribution implemented with the step-3 aggregator rewrite; cross-batch link reads through `trailtool-identity-links` are the step-4 port.*

### 5.1 Role chaining (C2 — the layer that must survive)

On each `AssumeRole` event whose caller resolves to a person: write `chain#<issuedAccessKeyId>` (from `responseElements`) and `chain#<assumedRoleID>#<eventTime>` links carrying the person_key, parent session ref, assumed role ARN, session tags, and session policy. The child session is written under the *person's own partition* with `assumed_from_session` set — so "all of Alice's sessions" naturally includes her chained ones. This is structurally the pre-1.0 Pass 1 / Pass 2 logic with the fragile `email:roleID:creationDate` parent keys replaced by stable person keys and anchors.

**Both chaining channels are covered, and the child's anchor comes from the ordinary cascade:**

- **CLI chaining** (`aws sts assume-role`): the child credential is the issued `ASIA…` key → one `key#` session, typed `cli`. The `chain#<issuedAccessKeyId>` link resolves identity + parent.
- **Console switch-role**: the console's `AssumeRole` vends a child *console* session — fresh access key per request but one `creationDate`, exactly like a normal console session. The cascade anchors it `web#<assumedRoleID>#<creationDate>`, typed `web`; the `chain#<assumedRoleID>#<creationDate>` link (pre-1.0's console-variant key, ported) resolves identity + parent. Switching back, or switching again, mints a new `creationDate` → a new deterministic session, each with its own `assumed_from_session`.

Direct SAML federation gets the same treatment for free: `AssumeRoleWithSAML` logs the issued key in `responseElements`, so each browser re-auth is one deterministic session.

### 5.2 `aws login` (PKCE OAuth) grants

Same shape as pre-1.0's login pre-pass, with one fix mandated by the July 2025 changes: resolve the authorizing human from the `CreateOAuth2Token` event's own `onBehalfOf` (fall back to principalId email only if absent). Never depend on principalId being present on `signin.amazonaws.com` events. Vended-session events resolve at tier 2 via `login#<roleID>#<creationDate>`; the session (whether anchored `sis#` or `key#`) gets `session_type = login`. A `web#` session matching a `login#` link is the *authorizing* console session (it shares the roleID+creationDate the link is keyed on) and stays typed `web`.

### 5.3 MCP agents

Unchanged logic, new keys: a `CreateOAuth2Token` whose `requestParameters.resource` is the AWS MCP Server writes `mcp#<signInSessionArn>`; events carrying that `signInSessionArn` resolve to the authorizing person at tier 2, anchor at `sis#`, and are typed `agent`. **Guard:** `session_type = agent` only on an `mcp#` link match — never on mere presence of `signInSessionArn`, which AWS is rolling out to ordinary console/CLI sessions (§1).

## 6. Parser/type additions & ingest hygiene

*Implemented — `ingestor/lib/types/types.go`.*

```
CloudTrailRecord: EventID, AwsRegion, RecipientAccountID
UserIdentity:     OnBehalfOf{ UserID, IdentityStoreArn }, InvokedBy, UserName, CredentialID
SessionContext:   SourceIdentity                        # parsed; log presence, don't key on it
```

- **`invokedBy` (forward-access sessions):** when AWS services call other services with the human's credentials (CloudFormation fan-out, etc.), events carry the human's session context and would silently inflate the person's session. Rule: include them in the session but count them in `service_driven_event_count` and exclude them from ClickOps flagging. The pre-1.0 user-agent blocklist (`IsValidUserAgent`) demotes to a secondary heuristic.
- **Session typing:** `ClassifySessionType` (browser vs programmatic UA) survives as a display label and windowed-fallback channel only; it no longer gates whether a session exists and no longer separates channels for anchored sessions (§3.1 does that by construction).
- **Backfill:** forward-only for 1.0. Events predating AWS's `onBehalfOf` rollout would land in tier-3 keys and split people across keyspaces; if backfill is ever offered, it needs an email-based stitch pass. Out of scope.

## 7. CLI 1.0 changes

- Read paths (`core/session/query.go`, `core/store/dynamodb.go`, `cmd/trailtool/`) rewritten to Query the person partition instead of scan+filter. `--user <email>` → `email_index` → possibly multiple person_keys → query each, merge, note the split in output ("2 identities matched alice@…").
- `sessions list` sorts by `start_time`; adjacent credential-refresh sessions read naturally (same person, same role, back-to-back). Optional later: group rows by sign-in parentage once the portal-correlation enrichment exists (§10).
- Chained-session rendering uses `assumed_from_session` / `chained_session_refs` (real refs) instead of parsing timestamps out of composite keys.
- **Pre-1.0 stack detection:** when a query hits a missing table, the CLI runs one `DescribeTable` on `trailtool-sessions-aggregated`. If the legacy table exists, fail with a clear message instead of a raw AWS error:

  ```
  This version of trailtool requires the 1.0 ingestor stack.
  Redeploy it:  cd ingestor && make deploy
  Note: redeploying deletes the pre-1.0 tables — existing aggregated
  data is not migrated. History rebuilds from CloudTrail going forward.
  ```

  Detection is by table name only — no version markers stored anywhere.
- **Version + deprecation notice** (net-new — nothing exists today): inject `main.version` via goreleaser ldflags → Cobra `rootCmd.Version`. Startup notice on stderr, non-fatal, suppressible via `--quiet` / `TRAILTOOL_NO_UPGRADE_NOTICE=1`. Final pre-1.0 release prints: `⚠ TrailTool v0.x reaches end-of-support on <GA+90d>. Upgrade: brew upgrade engseclabs/tap/trailtool` (hard-code the date at release time).

## 8. Test plan

Existing harness carries over: real-JSON fixtures in `ingestor/testdata/` driven through the aggregator's test entrypoint, plus table-driven unit tests. `go test ./...` must be green in both modules (root and `ingestor/`).

### 8.1 Unit — identity resolution & anchors

1. One CLI credential spanning a 4h wall-clock boundary → 1 session (pre-1.0 split bug, proven fixed; SSO creds run up to 12h). ✅
2. Credential refresh mid-work (new `ASIA…` key) → 2 sessions, same person_key on both (deliberate v3 semantics). ✅
3. Console session: 7 per-request access keys, one `creationDate` → 1 `web#` session. ✅
4. **C1:** credential group where 3 of 5 events carry `onBehalfOf` → all 5 in one tier-1 session; none leak to tier 3. ✅
5. **C1 cross-batch:** batch A resolves `ak#X` with anchor `sis#S`; batch B has `ak#X` events with no `onBehalfOf` and no `signInSessionArn` → tier 2 + anchor via `cred#X` link → same person, same session. *(step 4)*
6. Same `userId`, different `identityStoreArn` → 2 persons, never merged. ✅
7. Tier 3: SAML role session (`AROA…:alice@example.com`, no `onBehalfOf`) → `email#` person; its issued key is one `key#` session. ✅
8. Tier 4/5: IAMUser (`AKIA…`) and Root events → persons under `iamuser#`/`root#`; two bouts 1h apart on one AKIA key → 2 `win#` sessions. ✅
9. No tier matches (service-internal) → no session; role/service/resource aggregates still written. ✅
10. Agent credentials rotating under one `signInSessionArn` → 1 `sis#` session; typed `agent` only with an `mcp#` link, else not. ✅
11. Concurrent web + CLI + agent for one person and role → 3 sessions, correctly typed (channel separation by construction). ✅
12. `invokedBy` events → included, counted in `service_driven_event_count`, excluded from ClickOps. ✅
13. Console switch-role: parent web session + `AssumeRole` + child console events → child is one `web#` session with `assumed_from_session` pointing at the parent. ✅
14. CLI pointed at a pre-1.0 stack → redeploy message, not a raw AWS error. *(step 5)*

### 8.2 Unit — windowed fallback & idempotency

1. Windowed run overlapping an existing `win#` session → extended (start/end/counts), SK unchanged; late run before its start moves `start_time`, SK sticky. ✅
2. Windowed run bridging two existing sessions → folded into earliest-SK record, other deleted. ✅
3. Conditional-write conflict → retry path re-reads and converges. ✅
4. Redelivered file (marker present) → no double counts. Duplicate `eventID` within batch → counted once. ✅ *(dedupe; marker exercised at live validation)*

### 8.3 Property tests (the real safety net)

- **Partition-invariance:** for a fixed event set, any split into batches, in any batch order, yields identical final session records. Run every fixture through 2–3 random partitions. Anchored sessions satisfy this trivially; the test earns its keep on `win#` sessions and on anchor continuity via `cred#` links. *(step 6)*
- **No cross-person merge:** every session's events share one person_key. Assert over all fixtures. *(step 6)*

### 8.4 Fixtures (new, plus re-assert all existing ones under 1.0 keying)

`identity_cli_credential`, `identity_mixed_onbehalfof`, `identity_web_console`, `identity_chained_role`, `identity_agent_rotation`, `identity_concurrent_channels`, `identity_multi_person`, `identity_saml_direct`, `identity_iam_user` scenarios — landed as table-driven tests; port `cli_session.json`, `console_session.json`, `aws_login_session.json`, `sso_login_session.json`, `aws_mcp_agent_session.json` as regression fixtures (MCP fixture re-asserted ✅).

### 8.5 Live validation (once, before tagging)

Deploy to sandbox. Generate: a long CLI session with a real refresh; a console session; an assume-role chain; an MCP call. Assert via the CLI that the refresh produced two cleanly-bounded sessions for one person (not a 4h-window split), the console session is one row, the chain attributes, and nothing merged across people. Record before/after session counts in the release PR.

## 9. Decisions (resolved) & sandbox verifications

| Decision | Resolution |
|---|---|
| Session unit | One credential / one sign-in = one session (v3). A CLI refresh is a new session, deliberately. Windowing only where no credential boundary exists. |
| CLI refresh cadence | Assessed acceptable. Refreshes happen at the permission-set session duration (default 1h, max 12h) — hours, not minutes: worst realistic case ~8 CLI sessions per person per role per day. §8.5 records sessions/person/day in the sandbox; if it reads as noise, the fix is CLI-side display grouping — never storage windowing. |
| Portal-sign-in parentage | Deferred enrichment: `GetRoleCredentials` hides vended creds, so linking CLI sessions to their `aws sso login` requires a creationDate-echo correlation. Nice for display grouping; not a 1.0 dependency. |
| Version markers | None, anywhere. No `v1` in Go identifiers, table names, or attributes. The only versioned thing is the release tag. |
| Cutover | Hard: redeploying the ingestor deletes pre-1.0 tables + data (no coexistence window). 1.0 CLI detects the legacy stack by table name and prints the redeploy/data-loss message (§7). |
| IDLE_GAP | 30 min, env-overridable; applies to the windowed fallback only. |
| roleID in session grouping | Yes — same human, two roles = two concurrent sessions (anchor keys embed or pair with roleID). |
| Role graph table | No — derive from `chain#` links + session refs. |
| End-of-support for pre-1.0 | GA + 90 days, hard-coded in the notice at release. |
| Backfill | Forward-only for 1.0. |
| Global recent-sessions GSI | Skipped (hot-partition risk); scan-with-limit until needed. |
| Identity Center required? | No — tiers 3–5 are first-class. |
| Non-email SAML session names | Accepted gap for 1.0: no person, no session (aggregates still written); add a `saml#` tier later if real customers hit it. |

Verify in sandbox early (cheap; each answer just moves work between existing code paths):

- Is `sessionCredentialFromConsole` reliably present on console-session events across services? It gates both the `rc#` credential-group arm (§2.1) and the `web#` anchor arm (§3.1).
- Does a plain `aws sts assume-role` from an SSO session yield child events with `onBehalfOf`? (Expected: no → tier 2 does the work.)
- What does `CreateOAuth2Token`'s userIdentity look like post-Nov-2025 — does it carry `onBehalfOf`, and is `principalId` still present?
- Do ordinary console/CLI sessions now carry `signInSessionArn`, and is it stamped on every event of a session or per-service?
- Do `aws login`-vended session events carry `signInSessionArn`? (If yes they anchor `sis#`; if no, `key#` — either works.)

## 10. Code map — reuse / replace / delete

| Pre-1.0 code | 1.0 fate |
|---|---|
| `session.GenerateSessionKey` (4h window) | Deleted — replaced by §3 anchors ✅ |
| `ingestor/lib/identity` (groups + tiers + anchors) | New, landed ✅ |
| `ExtractEmailFromPrincipalID`, `ExtractRoleIDFromPrincipalID`, ARN helpers, `GetSessionCreationTime`, `IsIdentityCenterRole` | Reused as-is ✅ |
| `ClassifySessionType`, `IsClickOpsOperation`, `NormalizeUserAgent` | Display label / windowed-fallback channel only; no longer session-gating ✅ |
| `IsValidUserAgent`, `IsValidSourceIP` | Demoted to secondary heuristics behind `invokedBy` + tier gating ✅ |
| aggregator pre-passes (login, MCP) + Pass 1 chain discovery | Ported onto in-batch links + `trailtool-identity-links` writes ✅; cross-batch reads → step 4 |
| aggregator Pass 2 session keying + `chain-links` composite keys | Replaced with §2 tiers + §3 anchors + §4.3 key scheme ✅ |
| `dynamodb.go` merge helpers, `BatchGetChainLinks` | Merge helpers reused; batch-get ported to `BatchGetIdentityLinks` (read wiring → step 4) ✅ |
| `resources.ExtractResources`, `ExtractPolicyInfo`, denied-event tracking | Reused unchanged ✅ |
| `chain.go` extract helpers | Reused unchanged ✅ |
| `core/session/query.go`, `core/store/dynamodb.go`, CLI commands | Rewrite read paths per §7 → step 5 |
| `ingestor/testdata/*.json` fixtures + harness | Kept; re-asserted under 1.0 keying ✅ (remaining fixture ports → step 6) |
