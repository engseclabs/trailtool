# TrailTool — Reset and replay: rebuilding from the CloudTrail log

For status and rollout see https://github.com/engseclabs/trailtool/issues/49

## 1. Summary

**CloudTrail is the transaction log; TrailTool's DynamoDB tables are a derived, disposable projection of it.** This design makes that relationship operational with two primitives:

- **Replay** — ingest historical CloudTrail objects already in S3 through the existing ingestion path, so a deployment reflects real history instead of only what has arrived since its EventBridge rule started firing.
- **Reset** — drop the projection (empty the derived tables) so it can be rebuilt cleanly from the log.

Together they give a full rebuild story: **reset, then replay the range.** Because the log is the durable source of truth, the projection is safe to discard and regenerate at will. This is already the deployment's implicit model. The 1.0 cutover deliberately deletes and recreates the tables on redeploy (`ingestor/template.yaml` §"1.0 cutover"), on the premise that history rebuilds from CloudTrail. Reset and replay make that premise a first-class, on-demand operation rather than a redeploy side effect.

Replay is deliberately thin: **list the historical S3 objects in the chosen range, then invoke the ingestor Lambda once per object with a synthetic S3 event identical in shape to what EventBridge delivers live.** It adds no second ingestion code path. The Lambda downloads, parses, aggregates, and writes exactly as it does today. A small standalone CLI subcommand owns object listing and invocation; the Lambda stays unchanged.

**v1 is an offline rebuild, and its correctness rests on two rules that the rest of this doc justifies.** First, **replay does not run concurrently with live delivery**, and reset does not run while the projection is being written. The ingestor's file marker is a read-then-unconditional-write with warning-only error handling (`ingest.go`), so it prevents *sequential* redelivery but not two invocations racing on the same object. Overlap is therefore a non-goal, not a supported mode (§8). Second, **replay is sequential.** Object aggregation is order-sensitive in two places (windowed sessions, cross-file identity links, §6), and attribution is never repaired after the fact, so a reordered replay can produce a permanently wrong projection. Sequential ascending replay reproduces live ordering; concurrency is deferred until cross-file aggregation is order-independent (§7).

The one property replay must get right is **ordering**. Live delivery is roughly chronological; a `ListObjectsV2` sweep under one account/region prefix is lexicographic, which for CloudTrail's key layout is *also* chronological, so a sequential sweep is already correctly ordered. This breaks down only when a single explicit prefix spans multiple accounts or regions, where lexicographic order interleaves them (§5); the time-range mode never does this because it lists one account/region.

Reset makes the projection safe to rebuild: reset to empty, then replay the range into empty tables. Because nothing pre-exists, nothing double-counts (§8).

## 2. Goals and non-goals

**Goals**

- **Reset:** empty the derived tables so the projection can be rebuilt from scratch, without tearing down and recreating the CloudFormation stack.
- **Replay:** ingest historical CloudTrail objects already in the log bucket into a TrailTool deployment.
- Select what to replay by **day range** or **S3 prefix** (§5).
- Reuse the normal ingestion path end to end. No parallel parser or aggregator.
- Bound cost and make it predictable before the run starts (`--dry-run`).
- Produce a projection identical to what live ingestion would have built, by replaying sequentially in chronological order.

**Non-goals**

- **Overlap with live ingestion.** Replay and reset assume the projection is otherwise quiet. The ingestor marker does not make concurrent processing of the same object idempotent (§8), so overlap can double-count. Making overlap safe needs an atomic claim on the marker and is deferred.
- **Concurrent replay.** Sequential is the correctness-preserving default (§7). Parallelism is deferred until cross-file aggregation is order-independent.
- **Resume of an interrupted replay.** v1 has no persistent cursor (an earlier draft's cursor was both unsafe across a reset and ineffective across a kill, §7). A re-run relists the range; the ingestor marker skips objects already done *within the same uninterrupted, non-overlapping window*. A durable, generation-bound checkpoint is a follow-up (§11).
- **Sub-day precision.** Ranges are whole days (§5).
- Backfilling data CloudTrail never wrote to this bucket (retention gaps, a trail enabled late). Replay can only ingest objects that exist.
- Cross-account fan-out orchestration beyond what the existing namespace resolution already does per object.
- A hosted/scheduled replay service. This is an operator-run, one-shot-per-range tool.
- Changing session-merge semantics. Replay must produce the same aggregates live ingestion would have.
- Deleting the CloudTrail log itself. Reset only ever touches TrailTool's derived tables; the transaction log is never modified.

## 3. Why invoke the Lambda rather than re-ingest locally

Two paths could feed historical objects to the aggregator: (a) run the aggregation logic locally against S3, or (b) invoke the deployed Lambda per object. This design picks (b).

- **Identical code path, by construction.** The Lambda already contains the S3-event branch, the parser, the aggregator, and namespace resolution (`ingestor/lib/ingest/ingest.go`). Invoking it guarantees replay and live ingestion cannot drift. A local re-implementation would be a second thing to keep in sync, and session attribution is subtle enough (credential groups, chaining links, windowed fallback) that divergence would be a latent correctness bug.
- **Correct IAM and environment, already provisioned.** The Lambda runs as `trailtool-ingestor-role` with S3 read and DynamoDB write already scoped, and reads its table names and `IDLE_GAP` from its own environment. The driver needs only `lambda:InvokeFunction` plus `s3:ListBucket`; it never touches DynamoDB or parses a log.

The Lambda's `trailtool-ingested-files` marker is a **sequential-redelivery guard, not a general idempotency mechanism.** `processS3Records` reads the marker, aggregates, then writes the marker unconditionally, with marker read/write errors downgraded to warnings. Two invocations of the same object that interleave (live plus replay, or two concurrent replay workers) can both read "not ingested" and both aggregate it, double-counting. This is why v1 forbids overlap and runs replay sequentially rather than leaning on the marker for safety (§8).

The cost of (b) is one Lambda invocation per object and its cold/warm start overhead. For CloudTrail that is cheap relative to the S3 GET and parse the Lambda does regardless, and §9 bounds it.

## 4. Reset: dropping the projection

Reset empties TrailTool's derived tables so replay can rebuild them from the log. It never touches S3 or the CloudTrail log. It ships as a `trailtool reset` CLI subcommand, alongside `trailtool replay` (§7).

**What gets cleared.** The projection is every DynamoDB table the aggregator writes: `roles`, `services`, `resources`, `people`, `sessions`, `accounts`, `relations`, and `identity-links`. Two operational tables sit alongside it and need explicit handling:

- **`ingested-files`** must be cleared on reset. Its whole purpose is "this object is already in the projection." If the projection is emptied but the markers survive, replay skips every object and rebuilds nothing. **Reset clears the projection and the markers together, atomically in intent.**
- **`identity-links`** is projection state (chaining/login/MCP correlation) and is cleared with the rest. It is TTL'd anyway, but reset should not depend on TTL expiry.

**How to clear, two options:**

1. **Truncate in place (recommended default).** Scan each table and `BatchWriteItem`-delete, or delete-and-recreate the table via the SDK. On-demand billing makes this cheap. Keeps the CloudFormation stack, IAM role, EventBridge rule, and GSIs intact, so live ingestion resumes automatically the moment reset finishes. This is the "clear the database, keep the schema" operation the transaction-log model wants.
2. **Stack teardown/redeploy.** `sam delete` + `sam deploy` recreates the tables empty. Heavier (recreates GSIs, re-runs the EventBridge custom resource) and already the implicit 1.0-cutover behavior. Reset-in-place exists precisely so an operator does not have to reach for this.

**Reset assumes ingestion is quiescent.** Reset truncates tables one at a time. If a live object lands mid-reset, its rows can be split across cleared and not-yet-cleared tables, and its marker may be deleted, so a later replay reprocesses it and double-counts one table while rebuilding the others once. Truncation is not atomic across tables, and "run when quiet" is not a correctness guarantee against asynchronous CloudTrail delivery. v1 therefore scopes reset as an **offline operation**: the operator ensures no live delivery is in flight (in practice, the reset-then-replay rebuild is done as a maintenance action). A future coordinated rebuild that fences ingestion (pausing the EventBridge rule around reset+replay) is the principled fix and is a follow-up (§11); until then the offline constraint is the contract.

**Ordering with replay.** Reset must fully complete before replay starts. Replaying into a half-cleared table double-counts against surviving rows. A combined rebuild (`trailtool replay --reset`, or the two commands in sequence) gates replay on reset finishing.

**Safety.** Reset is destructive to the projection and irreversible except by replay. It writes nothing to the log, so it is always *recoverable* by replaying the same range, but the derived state (and any windowed sessions whose source objects have aged out of S3 retention) is gone until rebuilt. Interactively, reset prints the table names and approximate item counts (from `DescribeTable`, refreshed by DynamoDB roughly every six hours, so an estimate) and requires a typed `yes`; `--yes` skips both the prompt and the now-pointless count query. It never runs implicitly as part of replay unless the operator asks for the combined flow.

## 5. Selecting the range

CloudTrail writes objects under a date-partitioned key layout:

```
AWSLogs/<account-id>/CloudTrail/<region>/YYYY/MM/DD/<account>_CloudTrail_<region>_<ts>_<uid>.json.gz
```

Because the date components sit in the key in `YYYY/MM/DD` order, **within one account/region prefix, lexicographic key order is chronological order** (to day granularity; within a day, the embedded timestamp keeps files ordered too). A plain `ListObjectsV2` under such a prefix yields objects oldest-first, which is exactly the order sequential replay needs (§7).

Two selection modes:

- **Day-range mode (recommended).** The operator passes `--from` / `--to` as **dates** (`YYYY-MM-DD`), plus `--account` and `--region`. The driver expands the inclusive range into one day-partition prefix per day and lists them in order. Because the input is a whole day, there is no boundary-day ambiguity: every listed object belongs to a requested day. v1 deliberately does not accept sub-day instants. A one-hour request expressed as an instant would still have to replay whole day objects (the S3 layout is day-partitioned), and letting those extra events into the projection would be wrong, not harmless: aggregating by event time still *places* out-of-range events into sessions and counts. Sub-day precision, if ever needed, means filtering by each object's embedded timestamp and defining file-time versus event-time semantics explicitly (§11).
- **Prefix mode (escape hatch).** The operator passes a literal prefix, e.g. `AWSLogs/123456789012/CloudTrail/us-east-1/2026/06/`, for non-standard layouts (org trails add an `o-<orgid>/` segment; some buckets prefix a custom string). **Ordering caveat:** a prefix that spans multiple accounts or regions (e.g. stopping at `AWSLogs/`) lists them interleaved by lexicographic key, which is *not* chronological across the boundary. Since v1 replays sequentially for attribution correctness, prefix mode should name a single account/region down to (at least) the region segment. The day-range mode never has this problem because it always lists one account/region.

Both modes reuse the same non-event skip the Lambda already applies (`CloudTrail-Digest/`, `CloudTrail-Insight/`), so digests and insights are never invoked. The `.json.gz` suffix filter from the live EventBridge rule applies too.

## 6. Ordering: why it matters and why replay must be sequential

Most of the aggregator is order-insensitive: an event's session, role, service, and resource records are keyed on stable identity and merge commutatively. Two parts are not:

1. **Windowed-fallback sessions.** For principals with no stable session anchor (long-lived keys, root), the aggregator groups events into idle-gap windows and *moves a `win#` session's `StartTime` earlier* when a later batch delivers an earlier event within the gap (`aggregator.go` `WriteWindowedSessionResolved`; see [identity-first-sessions.md](identity-first-sessions.md) §4.2 and [session-recency-gsi.md](session-recency-gsi.md) §4.1). Fed out of order, the same activity can split into extra `win#` sessions or fold differently than live ingestion would have produced.
2. **Cross-file attribution via identity links.** Role chaining, console-login grants, and MCP correlation are carried by rows in `trailtool-identity-links`, written when the authorizing event is seen and read when the granted event arrives. Those links carry a **30-day TTL** (`dynamodb/links.go`). If a parent event and its child event land in the store far apart, the link can expire between them and attribution is lost. The aggregator already documents a residual cross-batch ordering gap here (`aggregator.go` around line 275).

Neither is repaired after the fact: if a parent object is processed after its child, the child's attribution is simply wrong and stays wrong. So ordering is a **correctness requirement**, and the design meets it by replaying **sequentially in ascending key order** (chronological within one account/region, §5). This is not a "small reorder window is fine" argument. Concurrency would introduce reordering that no later pass corrects, so v1 does not run objects in parallel at all. The listing order is already chronological, so sequential replay reproduces live ordering exactly by simply not shuffling.

Concurrency is a genuine speedup and worth adding later, but only after cross-file aggregation is made order-independent (for example, deferring child attribution until the parent link is present, or a reconciliation pass). Until then, sequential is the contract (§7). The link TTL is not a concern for a sequential run: links are written and read in replay wall-clock time, so a month of history replayed in order stays far inside the 30-day TTL.

## 7. The driver

The driver is a `trailtool replay` CLI subcommand. It does no parsing and no DynamoDB access. Its loop is **strictly sequential**:

```
for each selected prefix, in order:
    page ListObjectsV2, ascending                              # streamed, oldest-first
    for each key, in order:
        skip unless .json.gz and not Digest/Insight/Aggregated
        invoke trailtool-ingestor synchronously (RequestResponse)
            with a synthetic S3 event { bucket, key }          # same shape ingest.go parses
        on Lambda handler error or throttle: record the key, continue
report: N processed / M matched, failed keys listed
```

- **Sequential, one invocation at a time.** No worker pool. The next object is invoked only after the previous invocation returns, so the ingestor sees objects in chronological order and the ordering guarantees of §6 hold. This is the central correctness decision, not a tuning knob.
- **Streamed listing.** Keys are consumed page by page as `ListObjectsV2` yields them; the driver does not buffer the whole range or sort it (the API already returns lexicographic order, and the CLI only ever produces single-account/region prefixes, so there is nothing to re-sort or de-duplicate).
- **Synthetic event shape.** `HandleLambdaEvent` accepts a direct `events.S3Event` (its first unmarshal branch). The driver emits one record with `s3.bucket.name` and `s3.object.key`. No EventBridge envelope, so the default namespace is used — matching a single-tenant deployment. (Org/multi-tenant replay that needs `ResolveNS` is a follow-up, §11.)
- **Failures are per-object, not fatal.** A Lambda handler error or throttle on one object is recorded and the run continues; the failed keys are printed at the end for a targeted re-run. Because the ingestor marker skips objects already done within the same uninterrupted window, re-running the range after fixing the cause reprocesses only what failed.
- **No persistent resume cursor in v1.** An earlier draft wrote the last-done key to a local file. That state was both unsafe (it survived a reset, so a rebuild would treat the range as already done and leave the projection empty) and ineffective (it was written only after the whole run, so a killed process saved nothing). Removing it makes replay stateless and deterministic: a re-run always lists the full range and relies on the marker for in-window skip. A durable checkpoint bound to a projection generation (so it cannot outlive a reset) is a follow-up (§11).

## 8. Duplicate processing: what v1 does and does not guarantee

Aggregation is **not** idempotent at the event level: session event counts and other aggregates accumulate, so processing one object twice corrupts counts. There is no after-the-fact repair. The design's safety therefore comes from *not processing an object twice*, and v1 achieves that by construction rather than by relying on the marker:

- **The clean path is reset-then-replay into empty tables.** Nothing pre-exists, so nothing double-counts. This is the supported rebuild.
- **Sequential, non-overlapping replay** means no two invocations of the same object are ever in flight together, so the marker's one weakness (§3, a racy read-then-unconditional-write) is never exercised. Within a single uninterrupted run, the marker correctly skips an object the run already completed.

What v1 explicitly does **not** guarantee, and why these are non-goals rather than latent bugs:

- **Overlap with live delivery.** If the EventBridge-driven Lambda and a replay invocation both process the same object, both can read "not ingested" and both aggregate it. Making this safe requires an **atomic claim** on the marker (a conditional `PutItem` with `attribute_not_exists`, turning read-then-write into a single compare-and-set, and treating a lost claim as "someone else owns this object"). That is a change to the deployed Lambda's hot path and is deliberately out of scope here (§11). Until it lands, the operator must not replay while live delivery is active.
- **Idempotent re-run across the marker's 30-day TTL.** `MarkFileIngested` sets a 30-day TTL. A range re-run after its markers expire will reprocess and double-count. v1's answer is the reset-then-replay rebuild, not incremental top-ups: rebuild from empty rather than trusting stale markers. A generation-bound checkpoint (§11) is the durable fix.

The load-bearing rule is simple: **replay into a projection that is either empty (post-reset) or otherwise untouched during the run.** Everything above is why that rule, not the marker, is what keeps counts correct.

## 9. Cost and throughput

- **Per object:** one Lambda invocation (300s timeout, 512 MB), one S3 GET, one parse, and a batch of DynamoDB writes proportional to distinct sessions/roles/resources in the file. This is the same work live ingestion does per object; replay just front-loads it.
- **Bounding a run:** total cost ≈ (objects in range) × (per-object cost). The operator sizes a run before committing with `--dry-run`, which lists the range and totals matching objects without invoking. CloudTrail file counts are dominated by activity volume; a dry run gives an exact object count.
- **Throughput:** sequential replay is bounded by per-object Lambda latency, so a large range is slower than a parallel run would be. This is the accepted cost of ordering correctness (§7). DynamoDB is on-demand (`PAY_PER_REQUEST`), so write capacity is never the bottleneck. For a moderately active account a month still replays in a bounded, legible time; `--dry-run` sets expectations up front.
- **Guardrails:** `--dry-run` is the single cost guardrail. An operator always sees the object count before spending.

## 10. Failure handling and observability

- **Per-object failures** are collected, not fatal. The run finishes the rest and prints the failed keys for targeted re-invocation. Both text and JSON output report failures, and the command exits non-zero when any object failed, so scripted callers see the failure too.
- **Progress** is reported as objects-done / objects-total plus the current key, so a long sequential run is legible.
- **Re-run after failure:** re-running the same range is safe *within an uninterrupted, non-overlapping window* (§8): the marker skips objects already done, so only the previously-failed objects are reprocessed. Across marker expiry or a reset, rebuild from empty rather than re-running incrementally.
- **Lambda-side logs** are unchanged; each replayed object logs through the same CloudWatch group as live ingestion, so replay is auditable with the existing tooling.

## 11. Out of scope / follow-ups

These are the deferred pieces that would lift v1's constraints, roughly in priority order:

- **Atomic object claim in the ingestor**, so live delivery and replay can safely overlap. A conditional `PutItem` (`attribute_not_exists(object_key)`) as the *first* step, treating a failed claim as "already owned," converts the marker from a racy guard into a real lease. This is the prerequisite for lifting the no-overlap rule (§8) and touches the deployed Lambda.
- **Ingestion fence around reset+replay**, so a coordinated rebuild does not depend on the operator ensuring quiet. Pausing the EventBridge rule (or disabling the target) for the duration and re-enabling after makes reset's cross-table non-atomicity (§4) safe.
- **Concurrent replay**, once cross-file aggregation is order-independent (deferred child attribution, or a reconciliation pass). Only then can the sequential constraint (§7) be relaxed for speed.
- **Durable, generation-bound resume checkpoint.** A resume cursor is safe only if it cannot outlive the projection it describes: tag it with a projection generation that reset increments, so a post-reset replay ignores a stale cursor. This is the correct version of the state removed from v1 (§7).
- **Sub-day precision.** Filtering by each object's embedded timestamp, with file-time versus event-time semantics defined explicitly, if day granularity ever proves too coarse (§5).
- **Multi-tenant / org-trail namespace resolution during replay.** Emit the EventBridge event shape with `account` set so `ResolveNS` runs.
- **Scoped reset** (a time range or single principal, not all tables). Harder than full reset because derived rows are keyed on identity, not event time; full reset-and-replay is the reliable primitive and the intended default.
- **Automated post-replay reconciliation** (comparing replayed aggregates against an independent count) — a verification nicety, not part of the ingestion path.
