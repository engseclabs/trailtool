# TrailTool — Reset and replay

For status and rollout see https://github.com/engseclabs/trailtool/issues/49

## 1. Summary

TrailTool's DynamoDB tables only reflect CloudTrail activity that arrived after its ingestor started running. Everything CloudTrail wrote before that is sitting in S3, unprocessed. This design adds two CLI commands to fix that:

- **`trailtool replay`** re-ingests historical CloudTrail log objects from S3, so a new or rebuilt deployment reflects real history instead of waiting weeks for it to re-accumulate. It lists the objects in a chosen day range and invokes the existing ingestor Lambda once per object, reusing the live ingestion path so replayed and live data are identical.
- **`trailtool reset`** deletes all of TrailTool's derived data, so the tables can be rebuilt from scratch by a replay.

Together they support a full rebuild: reset, then replay the range. This works because CloudTrail's log in S3 is the durable source of truth and TrailTool's tables are just a computed view of it, safe to discard and regenerate.

Two properties make replay safe and correct, and the rest of this doc justifies them:

- **Replay closed days, not today.** CloudTrail writes each day under its own S3 key prefix. Replaying past days never touches the same object as a live delivery landing in today's prefix, so replay and live ingestion process disjoint objects and can run at the same time without interfering (§7).
- **Replay sequentially.** Aggregation is order-sensitive for a couple of session types (§5), and listing under one account/region prefix is already chronological, so replaying objects one at a time in listing order reproduces exactly what live ingestion would have built.

## 2. Goals and non-goals

**Goals**

- **Replay:** re-ingest historical CloudTrail objects already in the log bucket, selectable by day range or S3 prefix.
- **Reset:** empty TrailTool's derived tables so they can be rebuilt, without tearing down and recreating the CloudFormation stack.
- Reuse the normal ingestion path end to end. No second parser or aggregator.
- Produce a projection identical to what live ingestion would have built.
- Make cost predictable before a run (`--dry-run`).

**Non-goals**

- **Replaying the current day.** Replay is for closed, past days whose objects live delivery is no longer writing (§7). Replaying today's still-growing prefix could process the same object as a concurrent live delivery and double-count it.
- **Concurrent replay of objects.** Sequential is the correctness-preserving default (§6). Parallelism is deferred until cross-file aggregation is order-independent.
- **Resuming an interrupted replay.** v1 keeps no persistent progress state. A re-run relists the range; the ingestor's file marker skips objects the same run already finished. A durable checkpoint is a follow-up (§10).
- **Sub-day precision.** Ranges are whole days (§4).
- Backfilling data CloudTrail never wrote (retention gaps, a trail enabled late). Replay can only ingest objects that exist.
- A hosted or scheduled replay service. This is an operator-run, one-shot-per-range tool.
- Deleting the CloudTrail log. Reset only touches TrailTool's derived tables.

## 3. Reset: dropping the derived data

Reset empties TrailTool's derived tables so replay can rebuild them. It never touches S3 or the CloudTrail log.

**What gets cleared.** Every table the ingestor writes: `roles`, `services`, `resources`, `people`, `sessions`, `accounts`, `relations`, `identity-links`, and the `ingested-files` markers. The markers must go with the rest. Their whole purpose is to record "this object is already ingested," so if they survive an otherwise-empty projection, a subsequent replay skips every object and rebuilds nothing.

**How it clears.** Truncate each table in place: scan its keys and `BatchWriteItem`-delete. On-demand billing makes this cheap, and it keeps the stack, IAM role, EventBridge rule, and GSIs intact, so live ingestion resumes the moment reset finishes. (Tearing down and redeploying the stack would also empty the tables, but recreates GSIs and re-runs the EventBridge setup; reset-in-place exists so an operator does not have to.)

**Run reset when live delivery is quiet.** Reset clears all tables, and it does not clear them in a single atomic step. An object the ingestor writes partway through a reset could land in some tables and be deleted from others, leaving inconsistent data. Reset is an infrequent, deliberate "rebuild from scratch" action, so pausing live traffic (or simply running it during a quiet window) is a reasonable expectation. Fencing ingestion automatically around a rebuild is a possible refinement (§10), not required for v1.

**Safety.** Reset is destructive and reversible only by replay: it writes nothing to the log, so the same range can always rebuild the data (except windowed sessions whose source objects have aged out of S3 retention). Interactively, reset prints the table names and approximate item counts (from `DescribeTable`, which DynamoDB refreshes roughly every six hours, so an estimate) and requires a typed `yes`. `--yes` skips both the prompt and the now-pointless count query.

## 4. Selecting what to replay

CloudTrail writes objects under a date-partitioned key layout:

```
AWSLogs/<account-id>/CloudTrail/<region>/YYYY/MM/DD/<account>_CloudTrail_<region>_<ts>_<uid>.json.gz
```

Because the date sits in the key as `YYYY/MM/DD`, **within one account/region prefix, listing objects in key order is listing them in time order.** A plain `ListObjectsV2` yields objects oldest-first, which is exactly what sequential replay needs (§6).

Two ways to select a range:

- **Day range (recommended).** Pass `--from` / `--to` as dates (`YYYY-MM-DD`) plus `--account` and `--region`. The command expands the inclusive range into one prefix per day and lists them in order. Ranges are whole days on purpose: the S3 layout is day-partitioned, so a sub-day instant would still list whole-day objects, and letting the out-of-range events into the tables would be wrong, not harmless (aggregation places every event it sees into a session, regardless of whether it fell inside the requested window). Sub-day precision, if ever needed, means filtering by each object's embedded timestamp (§10).
- **Explicit prefix (escape hatch).** Pass a literal `--prefix` for non-standard layouts (org trails insert an `o-<orgid>/` segment; some buckets add a custom prefix). One caveat: a prefix that spans multiple accounts or regions lists them interleaved, which is not time-ordered across the boundary. Because replay is sequential for correctness, a `--prefix` should name a single account/region down to at least the region segment. The day-range mode never has this problem.

Both modes skip the same non-event files the ingestor already skips (`CloudTrail-Digest/`, `CloudTrail-Insight/`, `CloudTrail-Aggregated/`) and require the `.json.gz` suffix.

## 5. Why order matters

Most of the aggregator is order-insensitive: session, role, service, and resource records are keyed on stable identity and merge in any order. Two things are not:

1. **Windowed-fallback sessions.** For principals with no stable session anchor (long-lived keys, root), the aggregator groups events into idle-gap windows and moves a `win#` session's start time earlier when a later batch delivers an earlier event within the gap (`aggregator.go` `WriteWindowedSessionResolved`; see [identity-first-sessions.md](identity-first-sessions.md) §4.2). Fed out of order, the same activity can split into extra sessions or fold differently than live ingestion produced.
2. **Cross-file attribution via identity links.** Role chaining, console-login grants, and MCP correlation are carried by rows in `identity-links`, written when the authorizing event is seen and read when the granted event arrives. If a child event is processed before its parent, the link is not there yet and the attribution is lost.

Neither is repaired afterward: process a parent after its child and the child's attribution is simply wrong and stays wrong. So replaying in time order is a correctness requirement, met by replaying **sequentially in listing order** (which is time order within one account/region, §4). Concurrency would reintroduce reordering with no later fix, so v1 does not parallelize. It is a real speedup worth adding once cross-file aggregation is made order-independent (§10), but not before.

## 6. The replay command

`trailtool replay` does no parsing and no DynamoDB access. Its loop is strictly sequential:

```
for each selected prefix, in order:
    page ListObjectsV2, ascending                          # oldest-first
    for each key, in order:
        skip unless .json.gz and not a Digest/Insight/Aggregated file
        invoke trailtool-ingestor synchronously with a
            synthetic S3 event { bucket, key }             # same shape ingest.go parses
        on error: record the key, keep going
report: N processed / M matched, failed keys listed
```

- **One invocation at a time.** The next object is invoked only after the previous returns, so the ingestor sees objects in time order (§5). This is the central correctness decision, not a tuning knob.
- **Streamed listing.** Keys are consumed page by page; the command does not buffer or re-sort the range, because `ListObjectsV2` already returns key order and the command only ever produces single-account/region prefixes.
- **Synthetic event.** `HandleLambdaEvent` accepts a direct `events.S3Event` (its first unmarshal branch). Replay emits one record with the bucket and key. No EventBridge envelope, so the default namespace is used, matching a single-tenant deployment. (Org/multi-tenant replay that needs namespace resolution is a follow-up, §10.)
- **Bucket discovery.** The CloudTrail bucket is a property of the deployment, not something the operator should retype. Replay reads it from the ingestor CloudFormation stack (the `CloudTrailBucketName` output, falling back to the stack parameter of the same name for stacks deployed before the output existed), probing the same stack names as `trailtool status`. `--bucket` overrides this for unusual setups.
- **Failures are per-object.** A Lambda error on one object is recorded and the run continues; failed keys are printed for a targeted re-run. Re-running the range reprocesses only the failures, because the ingestor marker skips objects the previous run finished.
- **No persistent progress state.** An earlier draft wrote the last-done key to a local file. That state was unsafe (it survived a reset, so a post-reset replay would treat the range as done and rebuild nothing) and useless (written only after the whole run, so a killed process saved nothing). Removing it makes replay stateless: a re-run relists the range and relies on the marker to skip what a still-running or just-finished run already did. A checkpoint tied to a projection generation, so it cannot outlive a reset, is a follow-up (§10).

## 7. Duplicates: what keeps counts correct

Aggregation accumulates: process an object twice and its event counts double, with no after-the-fact repair. So correctness depends on never processing an object twice, and v1 gets that from *which objects it replays* rather than from the ingestor marker:

- **Reset-then-replay into empty tables** double-counts nothing, because nothing pre-exists. This is the supported rebuild.
- **Replaying past days** processes objects that live delivery has finished with. Live traffic lands in today's prefix; a replayed closed day is a disjoint set of objects, so no object is ever processed by both replay and live ingestion at once. This is why replay and live ingestion can run concurrently as long as the replayed range is in the past.

The one case v1 does not make safe is replaying an object that is *also* being delivered live at that moment (i.e. replaying the current, still-growing day). The ingestor marker does not prevent this: it reads the marker, aggregates, then writes the marker, so two invocations of the same object can both see "not ingested" and both count it. Making that safe needs an atomic claim on the marker (§10). v1 sidesteps it by only replaying closed days.

The load-bearing rule is simple: **replay a range that is either empty (post-reset) or in the past (disjoint from live traffic).** Both hold for every real replay.

## 8. Cost

- **Per object:** one Lambda invocation, one S3 GET, one parse, and DynamoDB writes proportional to the file's distinct sessions/roles/resources — the same work live ingestion does per object, just front-loaded.
- **Sizing a run:** `--dry-run` lists the range and totals matching objects without invoking, giving an exact object count before committing. Total cost is roughly that count times the per-object cost.
- **Throughput:** sequential replay is bounded by per-object Lambda latency, so a large range is slower than a parallel run would be — the accepted cost of ordering correctness (§6). DynamoDB is on-demand, so write capacity is never the bottleneck.

## 9. Failure handling and observability

- **Per-object failures** are collected, not fatal: the run finishes and prints the failed keys for a targeted re-run. Both text and JSON output report failures, and the command exits non-zero when any object failed, so scripted callers see it too.
- **Progress** is reported as objects-done / objects-total plus the current key.
- **Re-run after failure** reprocesses only the failed objects (the marker skips the rest), as long as the range has not since been reset. After a reset, rebuild from empty.
- **Lambda logs** are unchanged: each replayed object logs through the same CloudWatch group as live ingestion, so replay is auditable with existing tooling.

## 10. Follow-ups

Deferred pieces that would lift v1's constraints, roughly in priority order:

- **Atomic object claim in the ingestor** (conditional `PutItem` on `attribute_not_exists(object_key)` as the first step, treating a lost claim as "already owned"). This would make replaying the live day safe and is the one change that touches the deployed Lambda.
- **Concurrent replay**, once cross-file aggregation is order-independent (deferred child attribution, or a reconciliation pass). Only then can the sequential constraint (§6) relax for speed.
- **Ingestion fence around reset+replay**, pausing the EventBridge rule for the duration so a rebuild does not depend on the operator ensuring quiet (§3).
- **Durable resume checkpoint** tied to a projection generation that reset increments, so a post-reset replay ignores a stale checkpoint (§6).
- **Sub-day precision** by filtering on each object's embedded timestamp (§4).
- **Org / multi-tenant namespace resolution** during replay, by emitting the EventBridge event shape with `account` set.
- **Scoped reset** (a day range or single principal, not all tables). Harder than full reset because rows are keyed on identity, not event time; full reset-and-replay is the reliable primitive.
