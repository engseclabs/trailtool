# OTLP log forwarder

For status and rollout see https://github.com/engseclabs/trailtool/issues/71

## 1. Summary

`trailtool-otlp-forwarder` is an optional Serverless Application Repository app
that sends TrailTool's [change events](events.md) to any OTLP/HTTP logs
endpoint, one OpenTelemetry log record per event. An EventBridge rule on the
ingestor's activity bus invokes a Lambda that maps the event and posts it as
OTLP/HTTP protobuf.

The ingestor does not change and does not know the forwarder exists. Its
`Emit` is best-effort and never fails ingestion; putting an OTLP exporter in
that path would make ingestion depend on a third-party endpoint. As a separate
consumer, the forwarder gets retries, a dead-letter queue, and fan-out from
EventBridge and Lambda instead of reimplementing them.

The code is vendor-neutral: an endpoint URL and a set of headers is all it
knows about the receiver.

## 2. What the stack creates

| Resource | Purpose |
|----------|---------|
| `AWS::Events::Rule` on `EventBusName` | Matches `source: ["trailtool"]` and the `DetailTypes` allowlist. |
| Lambda, `provided.al2023`, arm64, 128 MB, 30 s | Maps and posts one event per invocation. |
| SQS dead-letter queue, SSE-SQS, 14-day retention | Receives events from both failure paths (section 6). |
| Log group with `LogRetentionDays` | The function's only log destination. |
| IAM role | `logs:CreateLogStream` and `logs:PutLogEvents` on that log group, `secretsmanager:GetSecretValue` on the headers secret, `sqs:SendMessage` on the dead-letter queue, and `kms:Decrypt` (via Secrets Manager only) when `SecretKmsKeyArn` is set. |

The role and resource names are generated, so several stacks can coexist (for
example one per receiver). Capabilities: `CAPABILITY_IAM`,
`CAPABILITY_RESOURCE_POLICY` (the Lambda permission and SQS queue policy), and
`CAPABILITY_AUTO_EXPAND` (the SAM transform).

## 3. Parameters

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `EventBusName` | *(required)* | Name or ARN of the bus the ingestor publishes to (its `ActivityEventBusArn`). The stack must run in that bus's account and region. |
| `OtlpLogsEndpoint` | *(required)* | Full logs URL, for example `https://otlp.example.com/v1/logs`. Never put credentials in it: the URL appears in errors. |
| `OtlpHeadersSecretArn` | *(required)* | Full ARN (with the six-character suffix) of the headers secret. |
| `SecretKmsKeyArn` | `''` | Customer managed key encrypting that secret. Empty for the AWS managed key. |
| `ServiceName` | `trailtool` | `service.name` on every record. |
| `DetailTypes` | all three | Comma-separated allowlist of `detail-type`s to forward. |
| `LogRetentionDays` | `30` | Function log retention. |

The template never takes a credential as a parameter. The secret's value is a
JSON object of header name to string value, set by the operator outside
CloudFormation:

```json
{"Authorization": "Bearer <token>", "X-Tenant": "<tenant id>"}
```

## 4. Field mapping

Each EventBridge event becomes one `LogRecord` in one `ResourceLogs` and one
`ScopeLogs`.

| OTLP field | Value |
|------------|-------|
| Resource `service.name` | `ServiceName` parameter |
| Resource `cloud.provider` | `aws` |
| Resource `cloud.account.id` | EventBridge envelope `account` |
| Resource `cloud.region` | EventBridge envelope `region` |
| Scope name / version | `trailtool` / the app version (the release tag without `v`) |
| `timeUnixNano` | EventBridge envelope `time` (when the ingestor published). CloudTrail times are in the attributes. |
| `observedTimeUnixNano` | When the forwarder built the record |
| `severityNumber` / `severityText` | `WARN` (13) for Session Activity with `activity.denied_count > 0`; `INFO` (9) otherwise |
| `body` | One-line summary (below) |
| `eventName` and attribute `event.name` | The `detail-type` |
| Attribute `trailtool.event_id` | EventBridge envelope `id` |
| Attributes `trailtool.<path>` | The flattened detail (below) |

`eventName` is the field current OpenTelemetry semantic conventions use;
`event.name` is kept as an attribute for receivers that predate it.

Bodies:

| `detail-type` | Body |
|---------------|------|
| Noun Created | `account 123456789012 seen for the first time`; resources read `resource s3:bucket:logs in account 111111111111 …` |
| Relation Created | `person alice@example.com reached account 123456789012 for the first time` |
| Session Activity | `alice@example.com: s3.amazonaws.com:GetObject ×2, denied s3.amazonaws.com:PutBucketPolicy ×1; 1 denied, 2 writes in account 111111111111 (new cli session gfo65rnbteswfydb; this file)`; the actor is the first non-empty of email, label, role session name, role ARN, person key, sid (else `Unknown actor`). Actions merge `event_counts` and `denied_event_counts` (the latter prefixed `denied`), ordered by count descending then name, capped at 5 with `+N more action types`. Counts cover the one CloudTrail file the event came from, not the session's lifetime |
| anything else | the `detail-type` |

### Flattening

The detail is flattened generically from its JSON, so fields added to the
event schema flow through without a forwarder change.

- Nested objects become dotted keys: `session.person.email` becomes
  `trailtool.session.person.email`.
- Objects whose keys are data stay one map-valued (`kvlist`) attribute instead
  of minting an attribute name per value: `event_counts`,
  `denied_event_counts`, `session_tags`, `subject_counts`, and
  `request_parameters`.
- Arrays stay OTLP array values. Array elements that are objects become
  `kvlist` values, so `trailtool.activity.writes` is an array of trimmed
  records, not a JSON string.
- Integers stay integers (`trailtool.activity.write_count`), booleans stay
  booleans, and nulls are dropped.

Examples for each type:

| Detail field | Attribute | Type |
|--------------|-----------|------|
| `schema_version` | `trailtool.schema_version` | int |
| `file.key` | `trailtool.file.key` | string |
| `kind`, `id` (Noun Created) | `trailtool.kind`, `trailtool.id` | string |
| `trigger.event` | `trailtool.trigger.event` | string |
| `trigger.request_parameters` | `trailtool.trigger.request_parameters` | kvlist |
| `subject.kind` (Relation Created) | `trailtool.subject.kind` | string |
| `subject_counts` | `trailtool.subject_counts` | kvlist of int |
| `session.sid` | `trailtool.session.sid` | string |
| `session.new_session` | `trailtool.session.new_session` | bool |
| `activity.denied_count` | `trailtool.activity.denied_count` | int |
| `activity.event_counts` | `trailtool.activity.event_counts` | kvlist of int |
| `activity.source_ips` | `trailtool.activity.source_ips` | array of string |
| `activity.writes` | `trailtool.activity.writes` | array of kvlist |

### Size caps

A record is capped to stay well under common receiver limits (typically 256 KB
or more per record):

- Every string value is cut to 2,048 bytes on a rune boundary.
- Every array keeps its first 25 items. For a top-level array the number cut
  is in `<key>_dropped`, for example `trailtool.activity.writes_dropped`.
  Writes are earliest first, so the earliest survive.
- Every map-valued field keeps its first 100 keys in sorted order, with the
  rest counted in `<key>_dropped` (for example
  `trailtool.activity.event_counts_dropped`).
- If the encoded record still exceeds 64 KiB, trailing items are dropped from
  the largest top-level array until it fits, and counted in the same
  `<key>_dropped` attribute.

`activity.write_count` and `activity.writes_truncated` keep the ingestor's
counts, so a consumer can always tell how many writes there were.

## 5. Wire format

Records are sent as OTLP/HTTP protobuf (`Content-Type: application/x-protobuf`).
The forwarder imports the generated message packages from
`go.opentelemetry.io/proto/otlp` (`logs/v1`, `common/v1`, `resource/v1`) and
`google.golang.org/protobuf`, and nothing else. It encodes `LogsData`, which
the OTLP spec keeps wire-identical to `ExportLogsServiceRequest`, and reads the
response's `partial_success` with `protowire`. That avoids the `collector/logs/v1`
package, whose gRPC service stubs would pull in `google.golang.org/grpc` and
`grpc-gateway`. JSON was not needed.

`go.opentelemetry.io/proto/otlp` is pinned at v1.10.0, the newest release that
does not require Go 1.26, so the ingestor module's Go version is unchanged.

## 6. Delivery and failure

1. The headers secret is read once per cold start and cached. On a 400, 401,
   or 403 the forwarder re-reads it once and, if it changed, retries the
   request, so a rotated or corrected credential takes effect without a
   redeploy. 400 is included because some receivers, Braintrust among them,
   answer a malformed `Authorization` header with it. An unchanged secret, or
   a second failure, is a failure.
2. Any non-2xx response is a failure, and so is a 2xx whose
   `partial_success.rejected_log_records` is above zero.
3. A failure returns an error from the function. Lambda retries the
   asynchronous invocation twice with its own backoff (events older than an
   hour are not retried), then writes a destination record holding the event
   and the error to the dead-letter queue.
4. If EventBridge cannot invoke the function at all (throttling, a missing
   permission), its target retry policy retries for up to an hour, then writes
   the event to the same queue.

Both paths are needed. An EventBridge target's retry policy and dead-letter
queue cover only failed invocations, never errors the function returns; those
go through Lambda's asynchronous retry and on-failure destination. That is why
the role holds `sqs:SendMessage` on the queue: Lambda sends the destination
record with the function's role.

The HTTP client times out at 10 seconds, so a 401 path (two requests and a
secret read) fits inside the 30-second function timeout.

### Logging

Each invocation logs one line, `OTLP_OK` or `OTLP_FAILED`, with the EventBridge
`id`, `detail-type`, HTTP status, and rejected count. Failures add the error,
which includes up to 256 bytes of the receiver's message (the
`google.rpc.Status` message for protobuf, otherwise the body text). Header
values and the request body are never logged. If a receiver echoes a header
value back in its error, the forwarder replaces the value, and every word of it,
with `[redacted]` before logging or returning the error; values and words
shorter than 8 bytes are left alone, since credentials are longer and redacting
a value like `1` would mangle the message. A receiver's error message can
quote record fields it rejected, so the function's logs and dead-letter records
are as sensitive as the events themselves.

### Duplicates

Delivery is at least once. A request that the receiver stored but whose
response was lost (a timeout, a 5xx after the write) is retried, and EventBridge
can deliver an event more than once. The forwarder does not deduplicate.
Consumers that care should key on `trailtool.event_id`, which is the same on
every retry of one event. Session Activity can also repeat upstream for the
same file (see [events.md](events.md#7-delivery-semantics)); key those on
`trailtool.file.key` and `trailtool.session.sid`.

## 7. Later

- Batching several events per request. One event per invocation is fine at
  TrailTool's volume (a few events per CloudTrail file); an SQS buffer with
  batched reads would cut requests if that changes.

## 8. Out of scope

- Any change to the ingestor or the event schemas.
- Traces and metrics.
