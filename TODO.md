# TODO

## Ingest durability & consistency gaps — accepted for now (ingestor)

Four gaps surfaced by code review of the CLI 1.0 branch. Each is documented as an
accepted limitation rather than fixed in this PR; the notes capture why and what a
real fix would cost. The related IAM and tier/TTL findings from the same review
*were* fixed (see the branch diff: `dynamodb:TransactWriteItems` added to both
templates, `MergePerson` tier precedence, identity-link TTL refresh).

- **Write failures are logged, not propagated — file still marked ingested.**
  `aggregator.Process` (`ingestor/lib/aggregator/aggregator.go`, the write loop
  ~L446–534) `log.Printf`s every failed role/service/resource/person/session/link
  write and returns `nil`. The caller (`ingestor/lib/ingest/ingest.go` ~L191) then
  calls `MarkFileIngested`, so a throttled / IAM-denied / transient failure yields
  permanent, silently incomplete data. **Why not just return the error:** the
  merges are additive and non-idempotent (`EventsCount = existing + incoming`,
  `SourceIPs` union, …) and idempotency is per-file, not per-write — so failing
  the whole file on any error means EventBridge redelivery *double-counts* the
  writes that already succeeded. A correct fix needs per-file all-or-nothing or
  per-write idempotency, not just error propagation. Deferred pending that design.

- **Anchored `WriteSession` uses unconditional read-merge-put.**
  `ingestor/lib/dynamodb/sessions.go` (~L24) reads, merges, and puts with no
  version condition, so two concurrent Lambda invocations writing the same
  anchored session can lost-update one another. Accepted per the function's own
  header comment: a concurrent double-merge has the same exposure as a redelivered
  partial batch, which the pipeline already tolerates. The `win#` path *does* use
  version-conditional writes + retry, so the machinery exists if we later decide
  anchored sessions need it too.

- **Windowed (`win#`) sessions can split after ~2×IDLE_GAP.**
  `queryAdjacentWindows` (`ingestor/lib/dynamodb/windows.go` ~L155) bounds the
  adjacency query to ±2×idleGap around the incoming run's sticky first-written SK.
  A long-running session whose earliest SK drifts outside that range for a later
  batch can't see its adjacent existing window and starts a second session (e.g.
  30-min gap, events at t0/t30/t60/t70 → a spurious second session at t70). A fix
  means widening/paginating the adjacency query or a reconciliation pass.

- **Cross-batch chain linking depends on arrival order.**
  `resolveGroups` (`ingestor/lib/aggregator/groups.go` ~L60–81) drops groups that
  never resolve from the session axis. If chained activity arrives *before* its
  `AssumeRole` file, the activity is omitted and the later link doesn't trigger
  reconsideration (EventBridge/Lambda give no ordering guarantee). Same shape as
  the grantee-side gap documented below — a real fix needs a deferred-
  reconsideration / back-patch mechanism keyed on the link.

  Two distinct symptoms depending on whether a *lower* tier can fire without the
  link:
  1. **Dropped activity** — a group that matches no tier without tier 2 (the
     chain link) is omitted entirely, as above.
  2. **Duplicated session** — when the chained role's session-name carries an
     email, tier 3 (`email#`) fires *without* the link, so the group is not
     dropped: it resolves to `email#…` instead of the parent's `idc#…`. Because a
     session ref is `person_key|sk` and only the person key differs, the *same*
     console/chained session is written as two rows under two people. This is
     more visible than a drop (a phantom duplicate) and `MergePerson`
     (`ingestor/lib/dynamodb/people.go`) never heals it — it reconciles records
     sharing one person key, never `email#` into `idc#`. Observed 2026-07-22 in
     sandbox: console session on `RoleChaining1` (chained from CLI parent
     `qk7s7q`, an `idc#…#11fb6570-…` session) split into `3hvmhe` (`idc#`, events
     with `onBehalfOf`) and `kqbomk` (`email#alex@engseclabs.com`, events
     without) — identical anchor/SK `web#AROAUB266OVZPC3ZFTYIY#2026-07-22T18:19:51Z`.

- **Decision (2026-07-22):** documented, not fixed in the CLI 1.0 PR. The first
  two are durability/consistency tradeoffs with a known accepted exposure; the
  latter two are out-of-order-delivery reconciliation gaps deferred until there's
  evidence they matter in practice or a broader need for the underlying machinery.

## Grantee-side cross-batch login/MCP attribution gap (ingestor)

An `aws login` / MCP grantee session can miss its attribution (shown as a plain
`cli` session with no `login_granted_by_session`, instead of typed `login`) when
the grant's identity link is persisted in a batch *after* the vended session was
already written.

- **Root cause:** attribution is applied only at grantee-session creation
  (`ingestor/lib/aggregator/aggregator.go`, where `LoginGrantedBySession` /
  `AgentAuthorizedBySession` are set), reading the fully-registered in-batch
  links plus links persisted by *prior* batches (`fetchStoredLinks`). Co-batch
  delivery is already handled — `resolveGroups` registers every in-batch link to
  a fixpoint before any session is created. The failure is strictly cross-batch:
  the grantee's file is ingested before the grant's link exists, so it is created
  link-less and nothing revisits it. Example: session `ngtklx`, a one-event
  `aws login` smoke test (`s3:ListBuckets`) delivered ahead of its
  `CreateOAuth2Token` grant; the `login#…` link exists in `trailtool-identity-links`
  and `ngtklx`'s event carries the matching `creationDate` + `principalId`, but it
  is still typed `cli`.

- **Why not the obvious fixes:**
  - *Store the grantee SK on the link when co-resolved* — a no-op. Co-batch
    already works (see above); this cannot reach a grantee written in an earlier
    batch.
  - *Deferred grantee back-patch keyed on the link* — the grant event never names
    the vended access key (`responseElements` is null), so the grantee's SK
    (`key#<accessKeyId>#<roleID>`) is not derivable from the link. Reaching an
    already-written grantee would require a **GSI on its
    `(person, roleID, creationDate)` fingerprint** — the only complete
    deterministic fix, but heavy standing infra (GSI cost + backfill) for a rare,
    attribution-only miss.

- **Decision (2026-07-21):** documented, not fixed. Deferred pending either a
  broader need for fingerprint lookups or evidence the gap is common in practice.
  Symmetric to the existing `deferredParentUpdates` / `deferredGrantUpdates`
  paths, which only back-patch the parent/granter side.

## Sign-in bootstrap events misclassified (ingestor)

Console sign-in bootstrap events from `signin.amazonaws.com` are not being
attributed to the console session they belong to. Two related symptoms observed
in sandbox after a fresh wipe + re-ingest:

1. **Lone `ConsoleLogin` → spurious windowed session.**
   A `ConsoleLogin` under a direct-SAML role (e.g. `SandboxAdminDirect`) with no
   follow-on console activity in the batch has a bare userIdentity (no
   sessionContext, no access key, no browser UA). It can't group into or anchor
   onto a console session, so it falls to the windowed fallback (`win#`) as its
   own 1-event session. `foldConsoleSignIn` only folds when a matching `rc#`
   console group with the same principalId exists in the same batch — a lone
   sign-in has none.
   - Partially mitigated: the blank ROLE column is fixed (ExtractRoleNameFromARN
     now handles `sts:assumed-role` ARNs). The spurious-session issue itself
     remains.

2. **`GetSigninToken` → misclassified as CLI (`key#` anchor).**
   Unlike `ConsoleLogin`, `GetSigninToken` carries a temporary access key and no
   browser UA (it's AWS's federation endpoint, from an AWS-internal source IP).
   So `CredentialGroupKey` → `ak#<key>`, `Anchor` → `key#<key>` → typed **CLI**,
   even though it's part of a console (web) sign-in. Example: session `hfdosx`,
   role `SandboxPowerUser`, single event `signin.amazonaws.com:GetSigninToken`,
   typed CLI though the user never used the CLI with that role.

**Chosen direction (not yet implemented):** extend `isConsoleSignInEvent` in
`ingestor/lib/identity/identity.go` to also match
`signin.amazonaws.com:GetSigninToken`, so `foldConsoleSignIn` folds it into the
matching console session by principalId — the same mechanism used for
`ConsoleLogin`.

**Open questions to resolve before implementing (needs raw CloudTrail JSON):**
- Does `GetSigninToken`'s principalId (`roleID:sessionName`) match the console
  activity's principalId exactly? The fold matches on the full principalId, and
  the sign-in's session name may differ from the console activity's.
- The fold only fires on singleton groups (`len==1`) and matches
  `consoleByPrincipal`, which is populated only for `rc#` groups passing
  `isConsoleSessionCredential`. Confirm the console web session is `rc#`-keyed
  and that the sign-in token's access key appears on no other event.
- Whether the same fix (or a separate one) also resolves symptom 1.

**Out of scope for the current PR** (sid / `--session` selector). These are
pre-existing ingestor behaviors surfaced during verification, not caused by the
sid change.
