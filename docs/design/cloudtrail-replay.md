# TrailTool — Reset and replay: rebuilding from the CloudTrail log

For status and rollout see https://github.com/engseclabs/trailtool/issues/49

## 1. Summary

**CloudTrail is the transaction log; TrailTool's DynamoDB tables are a derived, disposable projection of it.** This design makes that relationship operational with two primitives:

- **Replay** — ingest historical CloudTrail objects already in S3 through the existing ingestion path, so a deployment reflects real history instead of only what has arrived since its EventBridge rule started firing.
- **Reset** — drop the projection (empty the derived tables) so it can be rebuilt cleanly from the log.

Together they give a full rebuild story: **reset, then replay the range.** Because the log is the durable source of truth, the projection is safe to discard and regenerate at will. This is already the deployment's implicit model. The 1.0 cutover deliberately deletes and recreates the tables on redeploy (`ingestor/template.yaml` §"1.0 cutover"), on the premise that history rebuilds from CloudTrail. Reset and replay make that premise a first-class, on-demand operation rather than a redeploy side effect.

Replay is deliberately thin: **list the historical S3 objects in the chosen range, then invoke the ingestor Lambda once per object with a synthetic S3 event identical in shape to what EventBridge delivers live.** It adds no second ingestion code path. The Lambda downloads, parses, aggregates, and writes exactly as it does today, including the `trailtool-ingested-files` idempotency marker. A small standalone driver (a subcommand or script) owns object listing, invocation, concurrency, and resume; the Lambda stays unchanged.

The one property replay cannot inherit for free is **ordering**. Live delivery is roughly chronological; a naive `ListObjectsV2` sweep is lexicographic, which for CloudTrail's key layout is *also* chronological, so the default sweep order is already correct. Sections 6 and 7 make that precise and explain why it matters for windowed-fallback sessions and cross-file attribution.

Reset changes the double-count calculus. A reset-then-replay into empty tables sidesteps the marker-expiry hazard entirely (§8): there is nothing to double-count. Replay-without-reset (topping up an existing projection) remains supported and relies on the marker plus resume cursor.

## 2. Goals and non-goals

**Goals**

- **Reset:** empty the derived tables so the projection can be rebuilt from scratch, without tearing down and recreating the CloudFormation stack.
- **Replay:** ingest historical CloudTrail objects already in the log bucket into a TrailTool deployment.
- Select what to replay by **time range** or **S3 prefix** (they reduce to the same key-prefix filter, see §5).
- Reuse the normal ingestion path end to end. No parallel parser or aggregator.
- Avoid duplicate processing when a replay overlaps live delivery or a previous replay run.
- Bound concurrency and cost, and make both predictable before the run starts.
- Resume an interrupted replay without reprocessing what already landed.

**Non-goals**

- Backfilling data CloudTrail never wrote to this bucket (retention gaps, a trail enabled late). Replay can only ingest objects that exist.
- Cross-account fan-out orchestration beyond what the existing namespace resolution already does per object.
- A hosted/scheduled replay service. This is an operator-run, one-shot-per-range tool.
- Changing session-merge semantics. Replay must produce the same aggregates live ingestion would have.
- Deleting the CloudTrail log itself. Reset only ever touches TrailTool's derived tables; the transaction log is never modified.

## 3. Why invoke the Lambda rather than re-ingest locally

Two paths could feed historical objects to the aggregator: (a) run the aggregation logic locally against S3, or (b) invoke the deployed Lambda per object. This design picks (b).

- **Identical code path, by construction.** The Lambda already contains the S3-event branch, the parser, the aggregator, namespace resolution, and the idempotency marker (`ingestor/lib/ingest/ingest.go`). Invoking it guarantees replay and live ingestion cannot drift. A local re-implementation would be a second thing to keep in sync, and session attribution is subtle enough (credential groups, chaining links, windowed fallback) that divergence would be a latent correctness bug.
- **Correct IAM and environment, already provisioned.** The Lambda runs as `trailtool-ingestor-role` with S3 read and DynamoDB write already scoped, and reads its table names and `IDLE_GAP` from its own environment. The driver needs only `lambda:InvokeFunction` plus `s3:ListBucket`; it never touches DynamoDB or parses a log.
- **Idempotency comes for free.** The Lambda writes a `trailtool-ingested-files` marker after each object and skips objects already marked (`ingest.go` `processS3Records`). Replay overlapping live traffic, or a re-run of a partial replay, dedupes at the object level with zero driver-side bookkeeping. (Caveat in §7.)

The cost of (b) is one Lambda invocation per object and its cold/warm start overhead. For CloudTrail that is cheap relative to the S3 GET and parse the Lambda does regardless, and §8 bounds it.

## 4. Reset: dropping the projection

Reset empties TrailTool's derived tables so replay can rebuild them from the log. It never touches S3 or the CloudTrail log.

**What gets cleared.** The projection is every DynamoDB table the aggregator writes: `roles`, `services`, `resources`, `people`, `sessions`, `accounts`, `relations`, and `identity-links`. Two operational tables sit alongside it and need explicit handling:

- **`ingested-files`** must be cleared on reset. Its whole purpose is "this object is already in the projection." If the projection is emptied but the markers survive, replay skips every object and rebuilds nothing. **Reset clears the projection and the markers together, atomically in intent.**
- **`identity-links`** is projection state (chaining/login/MCP correlation) and is cleared with the rest. It is TTL'd anyway, but reset should not depend on TTL expiry.

**How to clear, two options:**

1. **Truncate in place (recommended default).** Scan each table and `BatchWriteItem`-delete, or delete-and-recreate the table via the SDK. On-demand billing makes this cheap. Keeps the CloudFormation stack, IAM role, EventBridge rule, and GSIs intact, so live ingestion resumes automatically the moment reset finishes. This is the "clear the database, keep the schema" operation the transaction-log model wants.
2. **Stack teardown/redeploy.** `sam delete` + `sam deploy` recreates the tables empty. Heavier (recreates GSIs, re-runs the EventBridge custom resource) and already the implicit 1.0-cutover behavior. Reset-in-place exists precisely so an operator does not have to reach for this.

**Ordering with replay.** Reset must fully complete before replay starts. Replaying into a half-cleared table double-counts against surviving rows. The combined `reset && replay` flow gates on reset finishing.

**Safety.** Reset is destructive to the projection and irreversible except by replay. It writes nothing to the log, so it is always *recoverable* by replaying the same range, but the derived state (and any windowed sessions whose source objects have aged out of S3 retention) is gone until rebuilt. The driver requires an explicit confirmation (a typed flag such as `--yes`, or an interactive prompt) and prints the table names and approximate item counts it will clear before proceeding. It never runs implicitly as part of replay unless the operator asks for the combined flow.

## 5. Selecting the range

CloudTrail writes objects under a date-partitioned key layout:

```
AWSLogs/<account-id>/CloudTrail/<region>/YYYY/MM/DD/<account>_CloudTrail_<region>_<ts>_<uid>.json.gz
```

Because the date components sit in the key in `YYYY/MM/DD` order, **lexicographic key order is chronological order** (to day granularity; within a day, the embedded timestamp keeps files ordered too). This is the property that makes the whole design simple: a plain `ListObjectsV2` under a prefix yields objects oldest-first.

Two selection modes, both compiling to an S3 prefix plus an optional key-range filter:

- **Prefix mode.** The operator passes a literal prefix, e.g. `AWSLogs/123456789012/CloudTrail/us-east-1/2026/06/`. The driver lists everything under it. This is the escape hatch for non-standard layouts (org trails add an `o-<orgid>/` segment; some buckets prefix a custom string).
- **Time-range mode.** The operator passes `--from` / `--to` (dates or RFC3339 instants) and, if the standard layout applies, an account and region. The driver expands the range into the set of day-partition prefixes it spans and lists each. A partial first/last day is handled by parsing the timestamp embedded in each key (or, cheaply, ingesting the whole boundary day and letting per-event `eventTime` fall where it may — over-ingesting a few hours at the edges is harmless because aggregation is by event time, not file).

Both modes reuse the same non-event skip the Lambda already applies (`CloudTrail-Digest/`, `CloudTrail-Insight/`), so digests and insights are never invoked. The `.json.gz` suffix filter from the live EventBridge rule applies too.

## 6. Ordering: why it matters and why the default is already right

Most of the aggregator is order-insensitive: an event's session, role, service, and resource records are keyed on stable identity and merge commutatively. Two parts are not:

1. **Windowed-fallback sessions.** For principals with no stable session anchor (long-lived keys, root), the aggregator groups events into idle-gap windows and *moves a `win#` session's `StartTime` earlier* when a later batch delivers an earlier event within the gap (`aggregator.go` `WriteWindowedSessionResolved`; see [identity-first-sessions.md](identity-first-sessions.md) §4.2 and [session-recency-gsi.md](session-recency-gsi.md) §4.1). Fed out of order, the same activity can split into extra `win#` sessions or fold differently than live ingestion would have produced.
2. **Cross-file attribution via identity links.** Role chaining, console-login grants, and MCP correlation are carried by rows in `trailtool-identity-links`, written when the authorizing event is seen and read when the granted event arrives. Those links carry a **30-day TTL** (`dynamodb/links.go`). If a parent event and its child event land in the store far apart, the link can expire between them and attribution is lost. The aggregator already documents a residual cross-batch ordering gap here (`aggregator.go` around line 275).

Chronological replay makes both behave as they did live. The good news from §5: **the default listing order is chronological**, so the driver gets correct ordering by simply not shuffling. The design's ordering requirement is therefore a *constraint on concurrency*, not an extra sorting pass:

- Replay objects in ascending key order.
- Concurrency (§7) may run several objects in flight, but the window of reorder it introduces must stay small relative to `IDLE_GAP` (default 30m) and well under the 30-day link TTL. In practice both hold trivially: even highly concurrent replay processes a given day's objects within seconds of each other, far inside a 30-minute idle gap.

The link TTL deserves one more note. During replay, links are written and read in replay wall-clock time, not event time, so a month of history replayed in an hour keeps every link comfortably fresh. The TTL only threatens replays that themselves run for weeks, which §9's throughput makes unnecessary.

## 7. Concurrency and the driver

The driver is a standalone process (proposed: a `trailtool replay` subcommand; a `scripts/` Go program is an acceptable v1). It does no parsing and no DynamoDB access. Its loop:

```
list objects under the selected prefix(es), ascending          # oldest-first, streamed
filter: .json.gz, skip Digest/Insight, skip already-done       # see resume, §8
for each object, with bounded parallelism P:
    invoke trailtool-ingestor synchronously with a synthetic
    S3 event { bucket, key }                                    # same shape ingest.go parses
    on throttling/5xx: retry with backoff
    on success: advance the resume cursor
report progress: N done / M total, failures listed
```

- **Synthetic event shape.** `HandleLambdaEvent` already accepts a direct `events.S3Event` (its first unmarshal branch). The driver emits exactly that: one record with `s3.bucket.name` and `s3.object.key`. No EventBridge envelope needed, so no `sourceAccount` and the default namespace is used — matching a single-tenant deployment. (Multi-tenant/org replay that needs namespace resolution would emit the EventBridge shape with `account` set; called out as a follow-up, §11.)
- **Concurrency bound `P`.** Caps simultaneous in-flight invocations. Trades speed against Lambda concurrency limits, DynamoDB write throughput, and the reorder window of §6. A conservative default (e.g. 4–8) keeps the reorder window to sub-second within a day and stays clear of account Lambda-concurrency ceilings. `P` is operator-tunable.
- **Synchronous invocation** (`RequestResponse`), not async. The driver needs each object's success/failure to advance its resume cursor and to apply backpressure; fire-and-forget would defeat both.
- **Retries.** Lambda throttles (429) and transient 5xx get exponential backoff. A hard parse/aggregate failure on one object is logged and does not abort the run; it surfaces in the final failure list for targeted re-invocation.

## 8. Avoiding duplicate processing

Reset-then-replay into empty tables is the clean path: nothing pre-exists, so nothing double-counts, and this whole section is moot. What follows covers **replay without a preceding reset** — topping up an existing projection, or overlapping live delivery.

Two dedup layers, one inherited and one added:

- **Object-level, inherited: the ingested-files marker.** The Lambda skips any object already in `trailtool-ingested-files` and marks each on success (`ingest.go`). This is what makes replay safe to overlap live delivery and safe to re-run after a partial failure: an object processed by either path is not processed again.
- **Driver-level resume cursor.** Because listing is ordered (§5), the driver records the last successfully-invoked key (a small state file, or the max key confirmed done). Resuming a killed run means listing from that key forward, skipping a full re-list of completed prefixes. The marker table is the correctness backstop; the cursor is the efficiency optimization so resume does not re-invoke thousands of already-marked objects just to have the Lambda skip them.

**The marker's 30-day TTL is the sharp edge.** `MarkFileIngested` sets a 30-day TTL (`dynamodb/links.go`). That is correct for live redelivery dedup, but it means an object's marker can expire and replay could reprocess it, double-counting its events into the aggregates. Mitigations, in order of preference:

1. **Keep replays short and within the TTL window** relative to their own markers. A single replay run completes in hours (§9), so its own markers never expire mid-run. The cross-run risk is only re-running a replay >30 days after the first, which the resume cursor (persistent, no TTL) also guards.
2. **Rely on the resume cursor, not the marker, for long-lived idempotency.** The cursor is operator-side state with no TTL, so "did I already replay this range" survives independent of the marker table.
3. If stricter guarantees are wanted, a replay-scoped marker without a TTL is a possible extension, tracked as a follow-up (§11). Not required for v1. The simplest guarantee remains reset-then-replay (§4), which needs no marker at all.

Aggregation itself is **not** idempotent at the event level (session event counts accumulate), so double-invoking one object *does* corrupt counts. That is exactly why the object-level marker plus cursor matter, and why replay must never be pointed at a range it has already fully ingested without confirming markers/cursor still cover it.

## 9. Cost and throughput

- **Per object:** one Lambda invocation (300s timeout, 512 MB), one S3 GET, one parse, and a batch of DynamoDB writes proportional to distinct sessions/roles/resources in the file. This is the same work live ingestion does per object; replay just front-loads it.
- **Bounding a run:** total cost ≈ (objects in range) × (per-object cost). The operator can size a run before committing by listing the range and counting objects (a `--dry-run` that lists and totals without invoking). CloudTrail file counts are dominated by activity volume; a dry run gives an exact number.
- **Throughput:** with concurrency `P` and warm Lambdas, a month of a moderately active account replays in minutes to low hours, comfortably inside every TTL discussed. DynamoDB is on-demand (`PAY_PER_REQUEST`), so write capacity scales automatically; the practical ceiling is Lambda account concurrency, which `P` respects.
- **Guardrails:** `--dry-run` (count and cost estimate, no writes), `--limit` (cap objects per run for a trial), and the tunable `P`. An operator always sees the size before spending.

## 10. Failure handling and observability

- **Per-object failures** are collected, not fatal. The run finishes the rest and prints the failed keys for targeted re-invocation.
- **Progress** is reported as objects-done / objects-total plus the current key, so a long run is legible and the resume point is always visible.
- **Idempotent re-run:** because of §8, re-running the same command after a failure is safe and cheap. It relists, skips done keys via the cursor, and the marker catches anything the cursor missed.
- **Lambda-side logs** are unchanged; each replayed object logs through the same CloudWatch group as live ingestion, so replay is auditable with the existing tooling.

## 11. Out of scope / follow-ups

- **Multi-tenant / org-trail namespace resolution during replay.** v1 targets the single-tenant deployment and uses the default namespace. Emitting the EventBridge event shape with `account` set (so `ResolveNS` runs) is a clean extension when needed.
- **A TTL-free, replay-scoped idempotency marker** for guaranteed cross-run dedup beyond the resume cursor (§8).
- **Sub-day boundary trimming** by parsing each key's embedded timestamp, if over-ingesting boundary days ever proves costly (§5). Cheap to add; unnecessary by default.
- **Scoped reset** (clear only a time range or a single principal's projection, rather than all tables). Harder than full reset because derived rows are keyed on identity, not event time; full reset-and-replay is the reliable primitive and the intended default.
- **Automated post-replay reconciliation** (comparing replayed aggregates against an independent count) — a verification nicety, not part of the ingestion path.
