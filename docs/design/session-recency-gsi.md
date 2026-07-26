# TrailTool — Session Recency GSI

For status and rollout see https://github.com/engseclabs/trailtool/issues/48

## 1. Summary

`trailtool sessions list` with no `--user` answers "the most recent sessions across everyone" with a full-table Scan: it reads and bills for every session before sorting client-side by `start_time`. The cost grows with total table size, not with the number of rows the user actually wants. The CLI `--limit` default (#45) trims output but cannot make the unfiltered Scan cheap, because there is no time-ordered index for the cross-everyone case.

This design adds a **`start_time`-ordered GSI** partitioned on `customerId`. The unfiltered recency read becomes a single Query with `ScanIndexForward=false` and `Limit=N`, returning exactly the newest N sessions in O(N) reads, independent of table size.

This is additive and backward compatible. It introduces one GSI on an attribute the session item already carries (`start_time`), changes no keys or merge logic, and touches no existing index.

## 2. Why a single partition is fine here

A GSI needs a partition key. Keying it on `customerId` means every session write for a customer updates one GSI partition, and a single DynamoDB partition caps at 1000 write units/sec. The question is only whether the session write rate can approach that.

It cannot, in any realistic deployment. Sessions are aggregated, not raw: thousands of CloudTrail events collapse into one session record. Sustaining 1000 *session* writes/sec would require a massive, constantly-churning credential fleet minting new sessions faster than any real environment does. The write rate to this index is bounded by how fast new credential boundaries appear, which is orders of magnitude below the partition ceiling.

## 3. Schema

One GSI on `SessionsTable`. No new attribute: `start_time` and `customerId` are both already declared attributes on the item.

```yaml
- IndexName: recency_index
  KeySchema:
    - AttributeName: customerId
      KeyType: HASH
    - AttributeName: start_time
      KeyType: RANGE
  Projection:
    ProjectionType: ALL
```

`ProjectionType: ALL` matches the existing `role_index` / `account_index` / `sid_index`, so a recency query returns full session rows without a follow-up GetItem. The extra storage is the accepted cost, consistent with the table's other indexes.

## 4. Read path

`ListSessions` gains a recency path for the unfiltered case (no `--user`, no `--role`, no `--account`), replacing `scanSessions`:

```
Query recency_index
    KeyConditionExpression: customerId = :cid
    ScanIndexForward: false        # newest first
    Limit: N                       # N = the CLI --limit
→ exactly the newest N sessions
```

- **Cost.** One Query reading N items. Bounded by the user's limit, independent of table size. This is the whole point.
- **Correctness.** The index is fully `start_time`-ordered, so a descending Query with `Limit=N` returns the true global newest N. No approximation, unlike the sort-then-truncate stopgap in #45. Ties break naturally on the index; the client re-applies `SortSessionsForList` for the `sid`-tiebreak contract.
- **Filtered paths use their noun index.** `--role` queries `role_index`, `--account` queries `account_index`, and `--user` queries the person's partition. The store applies any remaining predicates after choosing one indexed anchor. This GSI serves the cross-everyone case.

### 4.1 `start_time` is mutable for `win#` sessions

Windowed-fallback sessions move `StartTime` earlier when a later batch extends the window (see [identity-first-sessions.md](identity-first-sessions.md) §4.2). Because the GSI range key is `start_time`, a moved start rewrites the index entry — DynamoDB handles this natively as a delete+insert on the index. The read side sees the session at its current start, which is correct: the recency view should reflect where the session actually begins now, not where it was first observed.

## 5. Out of scope

- **CLI flag surface** (owned by #45, shipped).
- **Cross-customer / global recency.** This index is customer-scoped by design; a global view is not a TrailTool use case.

## 6. Rollout

1. Add `recency_index` to `ingestor/template.yaml` and deploy. The GSI keys on attributes every row already has (`customerId`, `start_time`), so DynamoDB populates the index on the existing table automatically.
2. Wire the descending-Query recency read into `ListSessions`, replacing `scanSessions` for the unfiltered case.
3. Confirm `sessions list` (no filter) returns correct newest-N and no longer Scans (check read metrics).

Step 1 is safe to ship before step 2: the index populates while the read path still Scans, so the cutover in step 2 is a pure read change with the index already warm.
