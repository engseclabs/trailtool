# TrailTool change events

For status and rollout see https://github.com/engseclabs/trailtool/issues/68

## 1. Summary

After each CloudTrail file, the ingestor can publish EventBridge events describing what changed, so alerting, triage, and analytics systems can use TrailTool's identity correlation without reading its DynamoDB tables. Events report facts only; TrailTool never scores or judges them.

| `detail-type` | Meaning | Cardinality |
|---------------|---------|-------------|
| `TrailTool Noun Created` | A noun appeared for the first time anywhere | Once per noun |
| `TrailTool Relation Created` | Two nouns were linked for the first time | Once per edge |
| `TrailTool Session Activity` | What one session did in one CloudTrail file | Once per session per file |

The feature is off by default. Setting the ingestor's `ActivityEventBusArn` parameter turns it on; empty means no EventBridge client, no extra DynamoDB reads, and no events. Delivery is best-effort: a failed publish is logged and dropped, and never fails ingestion.

Events carry emails, source IPs, user agents, and CloudTrail request parameters. Treat the target bus as holding the same sensitivity as the CloudTrail logs themselves.

## 2. Envelope

Every event has `source: "trailtool"`. Every `detail` starts with the same fields:

| Field | Meaning |
|-------|---------|
| `schema_version` | `1`. Bumped on any breaking change to a detail shape. |
| `customer_id` | The ingest namespace (`default` for open-source deployments). |
| `file.key` | S3 key of the CloudTrail file the batch came from. |
| `file.account_id`, `file.region` | Read from the key's `<account>/CloudTrail/<region>/` segments, falling back to the first record. |

The EventBridge `time` is when the event was published. CloudTrail times live in the detail.

## 3. Trimmed CloudTrail record

`trigger` and `writes` hold trimmed records, never the raw CloudTrail event:

```json
{
  "event_id": "…",
  "time": "2026-10-01T10:00:00Z",
  "event": "s3.amazonaws.com:PutBucketPolicy",
  "error_code": "AccessDenied",
  "error_message": "…",
  "request_parameters": {"bucketName": "logs"},
  "resources": [{"arn": "arn:aws:s3:::logs", "account_id": "111111111111", "type": "AWS::S3::Bucket"}],
  "source_ip": "203.0.113.7",
  "user_agent": "aws-cli/2.17.0",
  "invoked_by": "cloudformation.amazonaws.com"
}
```

- `error_message` is cut to 500 characters.
- `request_parameters` over 2 KB serialized becomes `{"_truncated": true, "bytes": n}`.
- `responseElements` is never included: it is large and often holds credentials or other secrets.
- Empty fields are omitted.

## 4. Noun Created

Fires the first time a noun of kind `person`, `account`, `role`, `service`, or `resource` appears anywhere. Sessions never fire it: every session is new by definition, and Session Activity's `new_session` covers that.

```json
{
  "kind": "person",
  "id": "idc#d-123#user-456",
  "first_seen": "2026-10-01T10:00:00Z",
  "trigger": { "…": "trimmed record" }
}
```

`id` is the same identifier the CLI and relations table use (person key, account ID, role ARN, event source, resource key). `first_seen` and `trigger` are the batch's earliest event touching the noun.

The source of truth is the noun's relation `_summary` item, created with `attribute_not_exists`. A successful create is a new noun. Concurrent Lambdas race on that conditional put, so exactly one reports it.

## 5. Relation Created

Fires the first time two nouns are linked. Both directions of every pair are stored; only these directions are reported, so each pair appears once from the side that reads as "who reached what":

| Subject | Related |
|---------|---------|
| `person` | `account`, `role`, `service`, `resource` |
| `role` | `account`, `service`, `resource` |
| `account` | `service`, `resource` |

Edges involving a session are never reported.

```json
{
  "subject": {"kind": "role", "id": "arn:aws:iam::111111111111:role/admin"},
  "related": {"kind": "resource", "id": "s3:bucket:logs"},
  "first_seen": "2026-10-01T10:00:00Z",
  "subject_counts": {"people": 4, "sessions": 9, "accounts": 1, "roles": 0, "services": 2, "resources": 5},
  "trigger": { "…": "trimmed record" }
}
```

`subject_counts` is the subject's relation summary before this batch's edges, so a consumer can tell an established principal touching something new from a brand-new principal. It costs no read when the subject is itself new in the batch (all zeros) and one `GetItem` per subject otherwise: the post-write summary minus the edges this batch created. A concurrent batch for the same subject can skew it slightly. When the read fails, `subject_counts` is omitted.

The source of truth is the edge's `attribute_not_exists` put. When the put fails its condition, the edge already existed and only its bounds widen; no event fires. `trigger` is the batch's earliest observation of the edge.

## 6. Session Activity

Fires once per session per CloudTrail file, including read-only sessions. Every `activity` field covers this file's slice only, never the session's lifetime.

```json
{
  "session": {
    "sid": "gfo65rnbteswfydb",
    "person": {"key": "idc#d-123#user-456", "email": "alice@example.com", "label": "Alice Example"},
    "type": "cli",
    "account_id": "111111111111",
    "role_arn": "arn:aws:iam::111111111111:role/admin",
    "role_session_name": "alice",
    "new_session": true,
    "origin": {
      "assumed_from_session": "dw2upz6s3khx5zlc",
      "assumed_from_role_arn": "arn:aws:iam::111111111111:role/base",
      "agent_authorized_by_session": "…",
      "mcp_resource": "…",
      "login_granted_by_session": "…",
      "session_tags": {"team": "platform"},
      "has_session_policy": false
    }
  },
  "activity": {
    "start": "2026-10-01T10:00:00Z",
    "end": "2026-10-01T10:01:00Z",
    "events_count": 3,
    "denied_count": 1,
    "service_driven_count": 1,
    "clickops_count": 0,
    "event_counts": {"s3.amazonaws.com:GetObject": 2, "s3.amazonaws.com:PutBucketPolicy": 1},
    "denied_event_counts": {"s3.amazonaws.com:GetObject": 1},
    "source_ips": ["203.0.113.7"],
    "clients": [{"category": "cli", "name": "aws-cli", "version": "2.17.0", "total_event_count": 3}],
    "chained_into": ["…"],
    "write_count": 2,
    "writes": [{ "…": "trimmed record" }],
    "writes_truncated": 0
  }
}
```

- `sid` is the persisted session's id, the same one `trailtool sessions` shows. A windowed (`win#`) session can fold into an earlier window during the write; the event carries the survivor's sid, not the pre-write one. Session references in `origin` and `chained_into` are sids too.
- `new_session` is true when this file's write created the session rather than merging into an existing one.
- `writes` holds the file's mutating calls (`readOnly` false or absent) and every access-denied call, earliest first. It is capped at 50 records; `writes_truncated` counts the rest and `write_count` is the total before truncation. If an event still exceeds EventBridge's 256 KB entry limit, more writes are dropped (and counted in `writes_truncated`) until it fits.
- `write_count` and `denied_count` are numbers so rules can filter on them, for example `{"activity": {"write_count": [{"numeric": [">", 0]}]}}`.
- `origin` fields are empty unless the session was created by role chaining, `aws login`, or AWS MCP Server authorization.

## 7. Delivery semantics

**Best-effort.** The ingestor publishes after the aggregator returns and before it marks the file ingested. `PutEvents` runs in batches of up to 10 entries and 256 KB, retrying rejected entries up to four times with jittered backoff. Anything still undelivered is logged as `EMIT_FAILED` with per-type counts and dropped. Emission gets at most 30 seconds per file and stops 10 seconds before the Lambda deadline, leaving time to mark the file ingested. Emission never fails the Lambda: a failed run is redelivered, and redelivery merges the file's sessions a second time, so failing on a publish error would corrupt counts to save an event.

**Once, not exactly once.** Noun and Relation Created fire once per noun or edge because they ride on conditional creates. When a batch fails partway through its relation writes, the nouns and edges it already created are still published before the error returns; the retry sees them as existing and stays silent. If that publish itself fails, those events are lost.

**Session Activity can repeat.** It is published only after a clean run. A crash after publishing but before the file is marked ingested redelivers the file, which merges and publishes the same sessions again. Consumers that care should key on `(file.key, session.sid)`.

**No ordering.** EventBridge does not order deliveries. A Relation Created can arrive before the Noun Created for its subject, and events from different files interleave.

**Replays are silent by default.** `trailtool replay` marks its synthetic S3 events with `"trailtool": {"replay": true}`, and the ingestor suppresses emission for them. After `trailtool reset`, every noun would otherwise come out new. `trailtool replay --emit-events` opts in.

## 8. Turning it on

Deploy the ingestor with `ActivityEventBusArn` set to a bus ARN. The stack passes it to the function as `ACTIVITY_EVENT_BUS_ARN` and grants `events:PutEvents` on that ARN only. A bus in another account also needs a resource policy allowing the ingestor role to put events.

Consumers match on `source` and `detail-type`:

```json
{
  "source": ["trailtool"],
  "detail-type": ["TrailTool Relation Created"],
  "detail": {"subject": {"kind": ["person"]}, "related": {"kind": ["account"]}}
}
```

## 9. Out of scope

- An `action` relation kind (`eventSource:eventName`) for "first time this person called X". It touches relation kinds, summary counts, and CLI views, so it ships separately.
- Any consumer, classifier, or alerting.
