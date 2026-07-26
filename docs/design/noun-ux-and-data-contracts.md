# Make CLI commands more consistent

## Summary

Give every TrailTool noun a consistent list and detail experience:

```text
list -> copy a selector -> inspect detail
```

People and resources gain detail commands. Account, role, service, and session
details expose the activity and relationships already present in stored data.
Lists stop showing row indexes, and detail commands stop accepting `--index`,
because a row number identifies a changing view position rather than an entity.

The richer views require data corrections. Account and service aggregates must
merge across ingestion batches, distinct relationship counts must be exact, and
resource identity must include the resource account.

This design uses the render and package boundaries from
[`cli-output.md`](cli-output.md). Store access stays in `cli/commands`, human
formatting stays in `cli/view`, and `internal/render` remains independent of
domain and AWS packages.

TrailTool is pre-1.0. This change intentionally breaks earlier commands and
derived schemas.

## CLI selectors and lists

### Commands

| Noun | List | Detail | Specialized actions |
|---|---|---|---|
| People | `people list` | `people detail <pid>` | none |
| Sessions | `sessions list` | `sessions detail <sid-or-latest>` | `summarize <sid-or-latest>`, `policy <sid-or-latest>` |
| Accounts | `accounts list` | `accounts detail <account-id>` | none |
| Roles | `roles list` | `roles detail <role-id>` | `roles policy <role-id>` |
| Services | `services list` | `services detail <event-source>` | none |
| Resources | `resources list` | `resources detail <rid>` | none |

Remove the `#` column from people, account, role, service, and resource lists.
Remove `--index` from account, role, and service detail commands.
Remove `--session` from session detail, summary, and policy commands.

Use positional selectors consistently:

```console
$ trailtool people detail 4f6c2a
$ trailtool sessions detail k7m2qp
$ trailtool sessions summarize latest
$ trailtool sessions policy k7m2qp --include-denied
$ trailtool accounts detail 123456789012
$ trailtool roles detail jlnjlx
$ trailtool services detail lambda.amazonaws.com
$ trailtool resources detail cx4m7q
```

`latest` is session-only and always means the globally latest session. `--user`
is a sessions-list filter; use `sessions list --user <email-or-pid> --limit 1`
to find one person's latest SID.

### Canonical selectors

| Noun | Canonical identity | CLI selector |
|---|---|---|
| Person | `person_key` | PID |
| Session | `person_key` and session SK | SID |
| Account | AWS account ID | account ID |
| Role | role ARN | role ID |
| Service | CloudTrail event source | event source |
| Resource | account ID and normalized identifier | RID |

Role detail and policy accept an unambiguous role ID prefix. A full role ARN or
an exact role name also works. Ambiguous names return candidate ARNs and require
a role ID, full ARN, or `--account`.

Service detail accepts the stored event source. A bare token such as `s3` is
retried as `s3.amazonaws.com`. TrailTool does not infer aliases such as `ses`
for `email.amazonaws.com`.

Friendly labels never define identity. Emails, role names, account labels, and
resource names may change or collide.

### Derived IDs

PID, role ID, and RID follow the SID pattern: a 16-character lowercase base32
prefix of a SHA-256 digest. Type and version prefixes prevent accidental reuse:

```text
PID = base32lower(sha256("person:v1\0" + person_key))[:16]
RoleID = base32lower(sha256("role:v1\0" + role_arn))[:16]
RID = base32lower(sha256("resource:v1\0" + account_id + "\0" + identifier))[:16]
```

Lists show the shortest unique prefix of at least six characters. Detail
accepts any unambiguous prefix:

- no matches: return not found with a list-command hint;
- one match: return the entity;
- multiple matches: return candidates with distinguishing prefixes.

These IDs are derived. Resolvers scan the relevant customer noun partition.
Role JSON exposes the derived value as `role_selector`, distinct from the AWS
principal `role_id` stored on sessions.

### Ordering and columns

People, accounts, roles, services, and resources sort by `last_seen`
descending, then canonical identity ascending. Sessions sort by `start_time`
ascending, then SID ascending. `sessions list --reverse` reverses the time
order while retaining SID as the tie-breaker.

| List | Essential columns | Wide columns |
|---|---|---|
| People | `PID PERSON EVENTS LAST SEEN` | `SESSIONS ROLES ACCOUNTS DENIED` |
| Sessions | essential columns from `cli-output.md` | existing collapsible columns |
| Accounts | `ACCOUNT ID EVENTS LAST SEEN` | `SESSIONS PEOPLE ROLES SERVICES RESOURCES DENIED` |
| Roles | `ROLE ID ROLE EVENTS DENIED LAST SEEN` | `ACCOUNT SESSIONS PEOPLE` |
| Services | `EVENT SOURCE EVENTS DENIED LAST SEEN` | `ROLES RESOURCES PEOPLE SESSIONS ACCOUNTS` |
| Resources | `RID RESOURCE ACCOUNT EVENTS LAST SEEN` | `TYPE DENIED CLICKOPS ROLES SESSIONS` |

Selector cells remain copyable at narrow widths. Optional account and person
labels appear only when stored data contains them. The CLI does not call live
AWS APIs to fill labels.

## Detail views

Every detail view follows the same information order:

1. title and selector;
2. canonical identity and scope;
3. first seen, last seen, and activity totals;
4. denied and ClickOps totals;
5. top events and event-to-resource activity;
6. related nouns and recent sessions;
7. provenance or session lineage.

Related sections default to 10 rows. `--limit <n>` changes the bound. `--all`
returns every row and cannot be combined with `--limit`.

Denied totals remain in key facts. Per-event denied breakdowns and denied
resource rows require `--include-denied-details`. `--include-denied` remains
specific to policy generation. Detail JSON remains complete without the flag.
Counts and top maps sort by count descending, then canonical identity.
Relationship rows sort by last seen descending, then identity.

Human-readable timestamps include relative context. Compact tables use relative
timestamps. Key facts pair the raw timestamp with the relative value. JSON
retains machine-readable timestamps.

Detail JSON embeds the stored noun and adds the related data:

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

### People

`people list` adds PID and removes the row index.

`people detail <pid>` includes:

- PID, person key, resolution tier, primary email, and observed aliases;
- first seen, last seen, events, sessions, accounts, roles, services, and
  resources;
- denied event count and top denied calls;
- recent sessions with SID, role, account, type, events, and time;
- accounts, roles, services, and resources.

Identity tiers use names in human output and retain the numeric tier in JSON:

| Tier | Label |
|---|---|
| 1 | Identity Center |
| 2 | Credential link |
| 3 | Email session |
| 4 | IAM user |
| 5 | Root |

Email aliases remain labels. One email may resolve to multiple people.

### Sessions

Session detail uses SID as its primary selector and includes:

- resource count and source IPs;
- ClickOps count and event breakdown;
- successful event-to-resource activity;
- denied activity with policy ARN, policy type, and error context when
  `--include-denied-details` is set;
- the current cached summary, model, and generation time;
- services and resources;
- existing client, tag, policy, grant, login, and chaining data.

The header owns the resource total. Event to Resource Activity owns the activity
evidence. The Resources section owns the resource records. Session detail does
not render a separate Resources Accessed summary.

The internal SK and anchor remain muted diagnostic facts.

### Accounts

Account detail includes:

- account ID and optional stored label;
- first seen, last seen, total events, denied events, and ClickOps;
- top successful and denied events;
- recent sessions;
- people, roles, services, and resources.

Account activity is cumulative. Relationship counts come from the relation
summary.

### Roles

Role detail includes:

- role ID, role name, ARN, account, first seen, and last seen;
- events, denied events, people, and sessions;
- services with counts;
- resources with counts and event names;
- denied events and resources with policy ARN, policy type, and bounded error
  text;
- recent sessions and people.

The role ID is the primary CLI selector. Role names and full ARNs remain
convenience aliases, and detail output shows the canonical ARN.

### Services

Service detail includes:

- event source, display name, category, first seen, and last seen;
- successful and denied event totals;
- top successful and denied calls;
- roles, resources, accounts, people, and recent sessions.

`ResourcesUsed` is populated from structured resource identities during
aggregation.

### Resources

`resources list` adds RID and removes the row index.

`resources detail <rid>` includes:

- RID, normalized identifier, ARN when available, type, name, and account;
- first seen, last seen, successful events, denied events, and ClickOps;
- top successful and denied calls;
- roles, services, people, and recent sessions;
- ClickOps operations with actor, event, count, time, and SID.

Resource ARN is a label when CloudTrail provides it. Account ID and normalized
identifier define identity.

## Data corrections

### Commutative noun merges

Account and service writes merge with the stored aggregate instead of replacing
it. Every noun merge uses the same rules:

- `first_seen`: minimum non-empty CloudTrail `eventTime`, stored as RFC3339;
- `last_seen`: maximum CloudTrail `eventTime`, stored as RFC3339;
- event maps and totals: addition;
- string relationships: set union;
- optional labels: first defined value from a documented source;
- derived relationship counts: read from exact relation summaries.

Property tests partition and permute one event set and require every ordering to
produce the same noun records.

### Exact relationships

Add `trailtool-relations`. Aggregate items retain event totals and top maps.
The relation table owns distinct noun relationships and exact counts.

Each subject has one partition:

```text
pk = customerId#<subject-kind>#<encoded-subject-id>
sk = <related-kind>#<encoded-related-id>
```

Each edge stores:

```text
subject_kind
subject_id
related_kind
related_id
first_seen
last_seen
```

Each partition also stores:

```text
sk = _summary
counts = { people, sessions, accounts, roles, services, resources }
```

IDs in keys use base64url encoding. Raw IDs remain attributes for display.

The aggregator deduplicates edges per batch and writes both directions. A
conditional transaction inserts a new edge and increments the subject summary.
Existing edges update first and last seen without changing counts.

The CLI batch-gets `_summary` items after noun list queries. Detail commands
query one relation partition. Existing session indexes provide person, role,
and account recent sessions. Relation edges provide service and resource recent
sessions.

Write bidirectional edges for observed pairs:

- person and session, account, role, service, resource;
- account and session, role, service, resource;
- role and session, service, resource;
- service and session, resource;
- resource and session.

Events without a resolved person or session still contribute account, role,
service, and resource edges when those identities exist.

### Account-qualified resources

Replace the resources table sort key with:

```text
resource_key = account_id + "#" + base64url(normalized_identifier)
```

Keep `identifier` as the display value. Store `resource_key` outside JSON. RID
hashes the same account-qualified identity.

Resource extraction returns:

```text
identifier
account_id
arn
type
name
```

Resource accesses store the resource account ID. They do not assume the
caller's session account owns a cross-account resource.

The resources and relations tables contain derived ingestion data. The key
schema change replaces the resources table and requires re-ingestion.

### Aggregate fields

Add the fields required by the views:

- Person: denied event total and top denied events.
- Account: successful event map, denied event total and map, and ClickOps total.
- Service: populated resource identities.
- Resource access: resource account ID.

Person and account display names remain optional.

## Specialized actions

### Policy

Build policy action usage from one canonical event-count map. Resource accesses
attach resources to those actions without adding event counts again.

Session policy uses all successful event counts and resource accesses. With
`--include-denied`, it also uses denied events and denied resource accesses.

The result reports SID in `session_id`. `--explain` writes its summary to
stderr, including when stdout uses JSON.

### Session summaries

The summary prompt includes:

- event counts;
- event-to-resource activity;
- denied calls and resources;
- denying policy ARN and type;
- clients and ClickOps.

Persist generated summaries with model, timestamp, token usage, and a digest of
the canonical prompt input. A cached summary is current only when its digest
matches current session data. `--refresh` bypasses a current cache.

Session merges retain summary fields. New session activity changes the input
digest, preventing stale summaries from appearing current.

### Resource time filters

`resources list --days <n>` selects resources last seen during the period.
Successful and denied event totals remain lifetime totals.

ClickOps mode filters operations to the same period and recomputes the displayed
ClickOps count from those rows. Human and JSON output use the same filtered
rows and count.

### Latest, status, and global flags

- `latest` searches all stored sessions and sorts by start time and SID.
- `status --format json` returns a stable array of checks with status and
  diagnostic fields.
- `--format` accepts `text` or `json`.
- `--color` accepts `auto`, `always`, or `never`.
- Global flag validation runs before AWS configuration or store access.

## Verification

### Data

- Partition and permutation tests compare every noun aggregate.
- Cross-account fixtures contain same-named Lambda, IAM, and DynamoDB
  resources.
- Relation tests cover duplicate edges, inverse edges, exact summaries,
  conflicts, and pagination.
- Resource extraction tests cover caller account, resource account, ARN, and
  fallback identifiers.

### Commands and views

- Every displayed list selector resolves to one detail record.
- Prefix tests cover missing, unique, and ambiguous PID, SID, role ID, and RID
  values.
- Cobra tests cover the command matrix and prove `--index` is absent.
- Golden tests cover every noun at widths 60, 80, 100, and 132.
- Role IDs remain copyable at every width.
- Related sections test `--limit` and `--all`.
- Denied-detail tests cover the default and `--include-denied-details`.
- JSON, color, and stdout-purity tests remain green.

### Specialized actions

- Policy fixtures include resource-less actions without double-counting
  resource-backed calls.
- Summary tests cover prompt context, persistence, stale cache, and `--refresh`.
- ClickOps tests cover period boundaries and recomputed counts.
- Status and root-flag tests run without AWS.

Both modules pass:

```console
$ go test ./...
$ go -C ingestor test ./...
```
