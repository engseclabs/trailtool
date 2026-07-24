# TrailTool Noun UX and Data Contracts

For status and rollout see https://github.com/engseclabs/trailtool/issues/32.

## 1. Summary

Every TrailTool noun will support a stable list-to-detail workflow:

```text
list -> copy an ID -> inspect detail -> follow related IDs
```

People and resources gain detail commands. Accounts, roles, services, and
sessions gain the information already implied by their stored data. List row
numbers and `--index` go away because they identify a changing view position,
not an entity.

The CLI changes depend on data corrections. Account and service aggregates
currently overwrite prior batches, distinct relationship counts depend on file
partitioning, and resource keys can merge same-named resources across accounts.
The richer views ship only after those contracts are corrected.

This design builds on the render and package boundaries from
[`cli-output.md`](cli-output.md). It keeps `internal/render` free of domain and
AWS dependencies, keeps store access in `cli/commands`, and keeps human
formatting in `cli/view`.

### Decisions

- Remove list index columns and all `--index` selectors.
- Use AWS account IDs, role ARNs, and CloudTrail event sources as canonical
  selectors.
- Keep the existing SID for sessions.
- Add deterministic PID and RID selectors for people and resources.
- Accept positional selectors consistently: `trailtool <noun> detail <id>`.
- Keep `--session` as a deprecated alias for one minor release while adding
  positional SID forms.
- Add a relation table for exact, queryable links between nouns.
- Qualify resource identity by account.
- Make every noun aggregate invariant to file partitioning and ingestion order.
- Preserve existing top-level JSON fields. New detail data is additive.

## 2. Current Gaps

| Noun | Current commands | Selector | Main gap |
|---|---|---|---|
| People | `people list` | none | no detail view |
| Sessions | list, detail, summarize, policy | `--session <sid>` | internal SK shown instead of SID; stored activity omitted |
| Accounts | list, detail | account ID or `--index` | detail repeats aggregate counts |
| Roles | list, detail, policy | name, ARN, or `--index` | resources and denial context omitted |
| Services | list, detail | event source or `--index` | roles, resources, and denied calls omitted |
| Resources | `resources list` | none | no detail view |

The command gaps expose deeper data problems:

- [`WriteServiceToDynamoDB`](../../ingestor/lib/dynamodb/entities.go) replaces
  the stored service item with the current batch.
- [`WriteAccountToDynamoDB`](../../ingestor/lib/dynamodb/entities.go) does the
  same for accounts.
- Person counts keep the largest per-batch value. Role and resource counts add
  per-batch distinct values. Both results depend on file partitioning.
- `Service.ResourcesUsed` exists but the service aggregator does not populate
  it.
- Resources use `(customerId, identifier)` as their table key. Identifiers such
  as `lambda:function:worker` do not include an account.
- Account names and person display names are modeled but have no reliable
  enrichment source.

The specialized actions also have contract gaps:

- Session policy generation uses resource accesses and misses calls without an
  extracted resource.
- Role policy action counts include both resource accesses and the complete
  event map, which double-counts resource-backed calls.
- New session summaries are not persisted. The summary prompt also omits
  event-to-resource and denial-policy context.
- `resources list --days` filters on `last_seen` while showing lifetime totals.
  ClickOps output can include operations outside the requested window.
- `latest` silently searches only the last 90 days.
- `status --format json` still prints text.
- Invalid `--format` and `--color` values fall back instead of failing.

## 3. Selector and Command Contract

### 3.1 Target command matrix

| Noun | List | Detail | Specialized actions |
|---|---|---|---|
| People | `people list` | `people detail <pid>` | none |
| Sessions | `sessions list` | `sessions detail <sid-or-latest>` | `summarize <sid-or-latest>`, `policy <sid-or-latest>` |
| Accounts | `accounts list` | `accounts detail <account-id>` | none |
| Roles | `roles list` | `roles detail <role-arn>` | `roles policy <role-arn>` |
| Services | `services list` | `services detail <event-source>` | none |
| Resources | `resources list` | `resources detail <rid>` | none |

Role detail and policy continue to accept an exact role name when it resolves to
one role. Ambiguous names return candidate ARNs and require the ARN or
`--account`.

Service detail accepts the stored event source. A short service alias such as
`s3` resolves to `s3.amazonaws.com` only when the mapping is exact.

`latest` remains session-only. `--user` is valid only with `latest`; passing it
with a SID is a validation error.

### 3.2 Index removal

Remove the `#` column from people, account, role, service, and resource lists.
Remove `--index` from:

- `accounts detail`
- `roles detail`
- `services detail`

This is an intentional pre-1.0 CLI break. Unknown `--index` flags fail through
Cobra and point users to the relevant list command.

### 3.3 Session positional selectors

Add positional forms without immediately removing `--session`:

```console
$ trailtool sessions detail k7m2qp
$ trailtool sessions summarize latest --user alice@example.com
$ trailtool sessions policy k7m2qp --include-denied
```

For one minor release:

- positional selector or `--session` is required;
- passing both is an error;
- `--session` prints a deprecation notice to stderr;
- JSON stdout remains clean.

Removing `--session` is a later compatibility cleanup.

### 3.4 PID and RID derivation

PID and RID use the SID pattern: a 16-character lowercase base32 prefix of a
SHA-256 digest. Type and version bytes prevent accidental reuse:

```text
PID = base32lower(sha256("person:v1\0" + person_key))[:16]
RID = base32lower(sha256("resource:v1\0" + account_id + "\0" + identifier))[:16]
```

Lists show the shortest unique prefix of at least six characters. Detail accepts
any unambiguous prefix. Resolution returns:

- no matches: not found with a list-command hint;
- one match: the entity;
- multiple matches: candidates with the shortest distinguishing prefixes.

PID and RID are derived read fields. They are not stored and do not require new
indexes. The resolver performs a paginated projection query over the customer
partition. Add an index later only if measured deployments make this query a
bottleneck.

### 3.5 Canonical selector map

| Noun | Canonical identity | Display selector |
|---|---|---|
| Person | `person_key` | PID |
| Session | `person_key` and session SK | SID |
| Account | AWS account ID | account ID |
| Role | role ARN | role ARN |
| Service | event source | event source |
| Resource | account ID and normalized identifier | RID |

Friendly labels never become identity. Emails, role names, account labels, and
resource names may change or collide.

## 4. List Contract

Lists help users choose an entity. They do not attempt to display every stored
field.

### 4.1 Default order

- People, accounts, roles, services, and resources: `last_seen` descending,
  then canonical identity ascending.
- Sessions: `start_time` ascending, then SID ascending.
- `sessions list --reverse`: `start_time` descending, then SID ascending.

Every store list method sorts explicitly after pagination. DynamoDB traversal
order is no longer the CLI order contract.

### 4.2 Columns

| List | Essential columns | Wide columns |
|---|---|---|
| People | `PID PERSON EVENTS LAST SEEN` | `SESSIONS ROLES ACCOUNTS DENIED` |
| Sessions | existing essential columns from #25 | existing collapsible columns |
| Accounts | `ACCOUNT ID EVENTS LAST SEEN` | `SESSIONS PEOPLE ROLES SERVICES RESOURCES DENIED` |
| Roles | `ROLE ARN EVENTS DENIED LAST SEEN` | `SESSIONS PEOPLE` |
| Services | `EVENT SOURCE EVENTS DENIED LAST SEEN` | `ROLES RESOURCES PEOPLE SESSIONS ACCOUNTS` |
| Resources | `RID RESOURCE ACCOUNT EVENTS LAST SEEN` | `TYPE DENIED CLICKOPS ROLES SESSIONS` |

Selector cells remain copyable. The table may move a long role ARN to an
indented continuation line at narrow widths, but it must not replace selector
bytes with a truncation marker.

Account and person label columns appear only when the stored data contains a
defined value. The CLI does not call live AWS APIs to fill labels.

### 4.3 Empty and partial data

The #25 empty-state contract remains. A missing optional aggregate is omitted.
An unavailable relationship section says why when the cause is a schema
cutover, not silently that the entity has no relationships.

## 5. Detail Contract

Every detail view uses this order:

1. title and selector;
2. canonical identity and scope;
3. first seen, last seen, and activity totals;
4. denied and ClickOps signals;
5. top events and event-to-resource activity;
6. related nouns and recent sessions;
7. provenance or session lineage;
8. applicable copy-paste commands.

Related sections default to 10 rows. `--limit <n>` changes the bound.
`--all` returns every relationship and is mutually exclusive with `--limit`.
Counts and top maps sort by count descending, then canonical identity.
Relationship rows sort by last seen descending, then identity.

### 5.1 Detail JSON

Existing detail fields stay at the top level. Detail DTOs embed the stored model
and add derived fields:

```json
{
  "account_id": "123456789012",
  "events_count": 1204,
  "related": {
    "people": [],
    "sessions": [],
    "roles": [],
    "services": [],
    "resources": []
  }
}
```

Lists keep returning arrays of base noun records. PID and RID are additive list
fields. `related` appears only on detail commands.

## 6. Noun View Contracts

### 6.1 People

`people list` adds PID and removes the row index.

`people detail <pid>` renders:

- PID, person key, resolution tier, primary email, and observed aliases;
- first seen, last seen, events, sessions, accounts, roles, services, and
  resources;
- denied event count and top denied calls;
- recent sessions with SID, role, account, type, events, and time;
- related accounts, roles, services, and resources;
- navigation to session and related noun detail commands.

Identity tiers use names, with the numeric tier retained in JSON:

| Tier | Label |
|---|---|
| 1 | Identity Center |
| 2 | Credential link |
| 3 | Email session |
| 4 | IAM user |
| 5 | Root |

Email aliases remain labels. One email may resolve to multiple people.

### 6.2 Sessions

Session detail keeps the #25 layout and adds:

- SID as the primary selector;
- the internal SK and anchor as muted diagnostic facts;
- resource count and source IPs;
- ClickOps count and event breakdown;
- successful event-to-resource rows;
- denied event-to-resource rows with policy ARN, policy type, and error context;
- current cached summary and its model and generation time;
- account, role, person, resource, and related-session navigation.

The existing client, tag, policy, grant, and chaining sections keep their
semantics.

### 6.3 Accounts

Account detail renders:

- account ID and optional stored label;
- first seen, last seen, total events, denied events, and ClickOps;
- top successful and denied events;
- recent sessions;
- related people, roles, services, and resources;
- navigation to every related noun.

Account activity is stored as a cumulative aggregate. Relationship counts come
from the relation table.

### 6.4 Roles

Role detail renders:

- role name, ARN, account, first seen, and last seen;
- events, denied events, people, and sessions;
- services with counts;
- resources with counts and event names;
- denied events and resources with policy ARN, policy type, and bounded error
  text;
- recent sessions and people;
- `trailtool roles policy <role-arn>` navigation.

Role names remain convenience aliases. ARN is the displayed identity.

### 6.5 Services

Service detail renders:

- event source, display name, category, first seen, and last seen;
- successful and denied event totals;
- top successful and denied calls;
- related roles and resources;
- related accounts, people, and recent sessions;
- navigation to role, resource, account, person, and session detail.

`ResourcesUsed` is populated from structured resource identities during
aggregation.

### 6.6 Resources

`resources list` adds RID and removes the row index.

`resources detail <rid>` renders:

- RID, normalized identifier, ARN when available, type, name, and account;
- first seen, last seen, successful events, denied events, and ClickOps;
- top successful and denied calls;
- roles and services;
- people and recent sessions;
- ClickOps operations with actor, event, count, time, and SID navigation.

Resource ARN is a label when CloudTrail provides it. Account ID and normalized
identifier define identity.

## 7. Data Contract

### 7.1 Commutative noun merges

Add pure merge functions for accounts and services. All noun merges follow the
same rules:

- `first_seen`: minimum non-empty timestamp;
- `last_seen`: maximum timestamp;
- event maps and totals: addition;
- string relationships: set union;
- optional labels: first defined value from a documented source;
- derived counts: never add per-batch distinct counts.

Unit tests run each merge across randomized event partitions and permutations.
Given one event set, every ordering must produce the same record.

This fixes partition and ordering dependence. The accepted concurrent
read-merge-write and partial-batch durability limitations in [`TODO.md`](../../TODO.md)
remain separate work.

### 7.2 Relation table

Add `trailtool-relations` for exact noun relationships. Aggregate items retain
event totals and top maps. The relation table owns distinct related IDs and
their counts.

Each subject has one partition:

```text
pk = customerId#<subject-kind>#<encoded-subject-id>
sk = <related-kind>#<encoded-related-id>
```

Edge attributes:

```text
subject_kind
subject_id
related_kind
related_id
first_seen
last_seen
```

Each partition also contains:

```text
sk = _summary
counts = { people, sessions, accounts, roles, services, resources }
```

IDs in keys use base64url encoding so ARNs and composite keys cannot collide
with delimiters. Raw IDs remain attributes for display.

The aggregator deduplicates edges per batch and writes both directions. New
edges use a conditional transaction that inserts the edge and increments the
subject summary. A condition failure means another batch already created the
edge; the writer reloads and retries only missing edges. Existing edges update
first and last seen without changing counts.

The CLI uses:

- `BatchGetItem` for `_summary` items after a noun list query;
- one relation-partition query for a detail view;
- existing session indexes for person, role, and account recent-session lists;
- relation edges for service and resource recent-session lists.

### 7.3 Required relationships

Write bidirectional edges for observed pairs:

- person and session, account, role, service, resource;
- account and session, role, service, resource;
- role and session, service, resource;
- service and session, resource;
- resource and session.

Events without a resolved person or session still contribute account, role,
service, and resource edges when those identities exist.

### 7.4 Resource identity

Replace the resources table sort key with:

```text
resource_key = account_id + "#" + base64url(normalized_identifier)
```

Keep `identifier` as the unqualified display value. Add `resource_key` as a
stored, JSON-hidden field. RID hashes the same account-qualified identity.

Resource extraction returns a structured value:

```text
identifier
account_id
arn
type
name
```

Resource accesses store the resource account ID. They do not assume that the
caller's session account owns a cross-account resource.

CloudFormation cannot change a DynamoDB key schema in place. This design assumes
the work lands before `v1.0.0` and folds the resource-key change into the 1.0
schema cutover from [`identity-first-sessions.md`](identity-first-sessions.md).
If `v1.0.0` ships first, implementation stops and adds a separate migration
design.

### 7.5 New aggregate fields

Add the minimum fields required by the views:

- Person: denied event total and top denied events.
- Account: successful event map, denied event total and map, and ClickOps total.
- Service: populated resource identities.
- Resource access: resource account ID.

Person and account display names remain optional. The default view omits an
empty field instead of implying that enrichment exists.

## 8. Specialized Actions

### 8.1 Policy

Build policy action usage from one canonical event-count map. Resource accesses
attach resources to those actions; they do not add the event count again.

Session policy uses:

- all successful `EventCounts`;
- all successful `ResourceAccesses`;
- denied event and resource accesses when `--include-denied` is set.

The result reports SID in `session_id`. `--explain` always writes its summary to
stderr, including when stdout uses JSON.

### 8.2 Summaries

The summary prompt includes:

- event counts;
- event-to-resource accesses;
- denied calls and resources;
- denying policy ARN and type;
- clients and ClickOps.

Persist generated summaries on the session with model, timestamp, token usage,
and a digest of the canonical prompt input. A cached summary is current only
when its input digest matches the current session data. Add `--refresh` to
bypass a current cache.

Session merges preserve summary fields. A later event changes the input digest,
so the CLI does not silently present an old summary as current.

### 8.3 Resource time filters

`resources list --days <n>` means "resources last seen during this period."
Successful and denied event totals remain lifetime totals and the help text says
so.

In ClickOps mode, the CLI filters `ClickOpsAccesses` to the requested period and
recomputes the displayed ClickOps count from those rows. JSON returns the same
filtered ClickOps rows and count.

### 8.4 Latest, status, and global flags

- `latest` searches all stored sessions and sorts by start time and SID.
- `status --format json` returns a stable array of checks with status and
  diagnostic fields.
- Root flag validation accepts only `text` or `json` for `--format` and `auto`,
  `always`, or `never` for `--color`.
- Validation happens before AWS configuration or store access.

## 9. Compatibility

The work is additive except for explicit selector cleanup:

- `--index` is removed before 1.0.
- positional session selectors are additive;
- `--session` remains for one minor release;
- list ordering changes to the explicit order in this design;
- PID, RID, relation data, and new aggregate fields are additive JSON fields;
- existing top-level detail JSON fields keep their names and values;
- resource `identifier` remains the unqualified display identifier.

Human navigation lines always use the new positional forms.

## 10. Verification

### 10.1 Data

- Property tests partition and permute each fixture, then compare every noun.
- Cross-account fixtures contain same-named Lambda, IAM, and DynamoDB resources.
- Relation tests cover duplicate edges, inverse edges, summary counts, retry
  conflicts, and pagination.
- Resource extraction tests cover caller account, resource account, ARN, and
  fallback identifiers.

### 10.2 Selectors and commands

- Every displayed list selector resolves to exactly one detail record.
- Prefix tests cover no match, one match, and ambiguous PID, SID, and RID.
- Cobra tests cover the target command matrix and prove `--index` is absent.
- Session tests cover positional selectors, deprecated `--session`, conflicting
  selectors, and `latest --user`.

### 10.3 Views and JSON

- Golden tests cover every noun at widths 60, 80, 100, and 132.
- Long role ARNs remain copyable at every width.
- Each relation section tests its default limit, `--limit`, and `--all`.
- JSON tests preserve existing top-level fields and add only documented fields.
- Color and JSON purity tests from #25 remain green.

### 10.4 Actions

- Policy fixtures prove resource-less actions are present and resource-backed
  counts are not doubled.
- Summary tests cover prompt context, persistence, stale cache, and `--refresh`.
- ClickOps tests prove time windows exclude older operations and recompute
  counts.
- Status and root-flag tests run without AWS.

Both modules must pass:

```console
$ go test ./...
$ go -C ingestor test ./...
```

## 11. Rollout

1. **Data contract**: account and service merges, resource identity, relation
   table, new aggregate fields, and partition-invariance tests.
2. **Selectors and command grammar**: PID, RID, positional session selectors,
   deterministic list ordering, and `--index` removal.
3. **People and resource detail**: new commands, DTOs, views, and navigation.
4. **Existing noun detail**: account, role, service, and session enrichment.
5. **Specialized actions**: policy, summaries, ClickOps, `latest`, status, and
   root validation.
6. **Contracts and docs**: full golden and JSON matrix, README, and agent
   instructions.

The data slice is the base for selector and detail work. Specialized action
changes that do not depend on the data slice should use independent branches.
Stack only selector and view PRs that require the unmerged data contract.

Intermediate PRs use `Part of #32`. The final compatibility and documentation PR
uses `Closes #32`.

## 12. Deferred

- A TUI or interactive picker.
- Live AWS API calls for account, person, role, or resource enrichment.
- Generic full-text search.
- Historical reconstruction after `v1.0.0`.
- Removing `--session` before its compatibility period ends.
- The accepted concurrent noun-write and partial-batch durability work in
  [`TODO.md`](../../TODO.md).
