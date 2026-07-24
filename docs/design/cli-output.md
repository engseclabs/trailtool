# TrailTool CLI Output Redesign — Shared Render System + Package Refactor

For status and rollout see https://github.com/engseclabs/trailtool/issues/25

## 1. Summary

TrailTool's human-readable output grew organically inside a single ~1550-line
`cmd/trailtool/main.go`. It has no shared rendering layer: seven independent
`tabwriter` blocks, no terminal awareness, no ANSI styling, inconsistent
capitalization / separators / timestamps, an alphabetically-sorted "Top Events"
list, and raw AWS SDK errors leaking to users. This doc defines a deterministic,
AWS-free `internal/render` package and a package refactor that layers the CLI
into `cli/commands/` (Cobra + store) and `cli/view/` (formatting) on top of it.

- **One rendering system, many views.** All human output flows through
  `internal/render` primitives (`Table`, `KV`, `Section`, `Status`, `Empty`,
  `Error`) with one capability-detection pass deciding color, symbols, and
  width. No view formats bytes on its own (§4, §5).
- **Color and Unicode are additive, never load-bearing.** Every signal — status,
  denied activity, lineage, session type — is legible in plain ASCII with color
  stripped. Golden tests prove it (§4.2, §7, §9).
- **JSON is a hard contract.** `--format json` stays pure machine-readable JSON
  on stdout: no ANSI, no human prefixes, identical field names/shapes/values.
  Tests guard this (§8, §9).
- **Layered, testable packages.** `internal/render` imports neither AWS nor
  `core/models`; `cli/view` never touches the store. This is the seam that makes
  rendering testable without AWS, mirroring the ingestor's `lib/<domain>/` split
  (§3).
- **Refactor first, then style.** The behavior-preserving package split ships as
  its own PR (output byte-identical) before any styling lands, so each diff is
  legible and regressions bisect cleanly to "move" vs "restyle" (§10).

## 2. Current behavior this design preserves

Several output behaviors are already correct in shipped code and this redesign
keeps them — it restyles and reorganizes, it does not relitigate these:

- **Session selection is by SID.** `sessions detail` selects via `--session <SID>`
  (short prefix ok, or `latest`). `--index` selection exists only on
  `accounts` / `roles` / `resources` detail. The redesign preserves both.
- **Client command namespaces are already split.** `splitCommandNamespaces`
  separates bare CloudTrail event names (`API events:`) from `ua:`-prefixed
  user-agent tokens (`client commands:`). They stay two labeled lists (§5.1).
- **Client counts are already reconciled.** The client line renders
  `N requests: M ok, K denied` — "requests" is inclusive of denied, deliberately
  distinct from the session's success-only Events line, so no client appears to
  have more events than its session. The redesign keeps this framing (§5.1).
- **Current list columns** are the baseline for the responsive table work:
  people = `# PERSON KEY SESSIONS ROLES ACCOUNTS LAST SEEN`; sessions =
  `SID WHEN USER ROLE ACCOUNT EVENTS TYPE DURATION CHAINED`.

The unaddressed gaps this design targets: no shared render system, no
color/TTY/width awareness, inconsistent IA/typography/timestamps,
alphabetically-sorted "Top Events", leaking raw AWS errors, and stdout/stderr
interleaving in `status`.

## 3. Package architecture

Mirror the ingestor's layered `lib/<domain>/` convention at the root module.

```
cmd/trailtool/
  main.go            # thin: root cmd, global flags (--format, --color), Execute()

cli/
  commands/          # Cobra glue + store access; one file per command group
    status.go  people.go  sessions.go  accounts.go
    roles.go   services.go  resources.go
  view/              # pure formatting: (models.*, *render.Context) -> string/stdout
    session_detail.go  session_list.go  clients.go  clickops.go
    policy.go  lists.go  status.go

internal/render/     # deterministic, AWS-free rendering
  capability.go  style.go  symbols.go  table.go
  kv.go  section.go  time.go  errors.go
```

**Layering rules (enforced by imports, and the point of the split):**

- `internal/render` imports only the stdlib and `golang.org/x/term`. It imports
  neither the AWS SDK nor `core/models`. It is 100% unit-testable.
- `cli/view` imports `internal/render` and `core/models`. It never imports the
  store or the AWS SDK — it receives already-fetched models and returns rendered
  output. This is what lets view logic be golden-tested without AWS.
- `cli/commands` imports `core/store`, `core/models`, `cli/view`, and cobra. It
  owns flag parsing, store calls, and error mapping, then hands models to
  `cli/view`.
- `cmd/trailtool/main.go` shrinks to root wiring and `Execute()`.

Why `internal/render` (not `cli/render`): it's a general terminal primitive with
no domain meaning, and `internal/` prevents it becoming an accidental public API.

## 4. Terminal visual language

### 4.1 Capability detection (one pass, injected as context)

A single `render.Context` is computed once at command start and threaded to every
view. It never re-reads the environment mid-render, so tests construct it
directly.

```
Context {
  Color   bool   // ANSI styling on?
  Unicode bool   // Unicode symbols vs ASCII fallback?
  Width   int    // terminal columns; 80 when unknown
  Out     io.Writer  // stdout
  Err     io.Writer  // stderr
}
```

Resolution order for `Color`:

1. `--color=never` or `NO_COLOR` set (any value) → **off**.
2. `--color=always` → **on**.
3. `--color=auto` (default): on **iff** stdout is a TTY **and** `TERM != dumb`
   **and** `NO_COLOR` unset.

`Unicode` is on unless `TERM=dumb` (a conservative proxy for "can't render
box-drawing/symbols"); `--color=never` does **not** force ASCII (a mono terminal
can still show `✓`). Width comes from `x/term.GetSize(fd)`; on error or non-TTY,
**80**. `--format json` bypasses all of this — JSON never consults `Context`.

`--color` is a new **global** flag (`auto|always|never`, default `auto`). It is
additive and does not alter any existing flag's semantics.

### 4.2 Semantic style roles

Views name a **role**, never a raw color. Each role maps to an ANSI sequence when
`Color` is on and to identity (no bytes) when off — so removing color changes
nothing but the escapes.

| Role | On-TTY rendering | Meaning |
|---|---|---|
| `Title` | bold | top-of-view identity line |
| `Header` | bold + dim | table column headers, section headings |
| `Muted` | dim | secondary/derived detail, hints |
| `Success` | green | healthy status |
| `Warn` | yellow | warnings, ClickOps flag |
| `Fail` | red | failures |
| `Denied` | red | denied-event counts |
| `Count` | default (bold on emphasis) | numeric aggregates |
| `Ident` | cyan | emails, role names, SIDs, resource ids |
| `Time` | default | timestamps |
| `Nav` | dim | the `→ trailtool …` copy-paste nav lines |

Color is **never the only signal**. Denied counts also carry the word "denied"
and a symbol; status also carries `[ok]`/`[warn]`/`[fail]`.

### 4.3 Symbol vocabulary + ASCII fallback

| Concept | Unicode | ASCII fallback |
|---|---|---|
| success | `✓` | `[ok]` |
| warning | `⚠` | `[warn]` |
| failure | `✗` | `[fail]` |
| denied | `⊘` | `(denied)` |
| lineage / child-of (nav down) | `↳` | `->` |
| nav (copy-paste command) | `→` | `->` |
| assumed-from / parent (up) | `↑` | `^` |
| login / agent source (in) | `←` | `<-` |
| middle-truncation marker | `…` | `...` |

Session-relationship meaning is carried by **words** first — `assumed by`,
`child of`, `via aws login`, `authorized N session(s)` — with the symbol as a
leading accent, never the sole carrier. A mono, no-color, ASCII terminal still
reads every relationship correctly.

### 4.4 Typography, capitalization, spacing

- **Emphasis** available: bold, dim, and 3-bit ANSI color only. No 256-color, no
  truecolor, no italics/underline (uneven terminal support).
- **Capitalization (one rule):** table column headers are `UPPERCASE`; section
  headings and KV field labels are `Title Case`; body values verbatim. This
  replaces today's mix.
- **Sections:** a blank line then a Title-Case heading (`Clients (3):`), body
  indented two spaces. No ASCII rules/separators (`--- … ---`) — the blank line +
  heading is the separator.
- **Numbers:** right-aligned in tables; zero renders as `0` (present, muted),
  never blank — a zero denied-count is meaningful signal.

### 4.5 Timestamps (one rule everywhere)

Absolute RFC3339 UTC, with a relative suffix in brackets for recency:
`2026-07-22T16:43:18Z [5m ago]`. Relative form: `just now`, `Nm ago`, `Nh ago`,
`yesterday`, `Nd ago` (today's `relativeTime` logic, centralized in
`render/time.go`). Intervals: `start → end` on a `Time`-styled line. No view
invents its own timestamp format.

## 5. Information architecture (per view)

Consistent skeleton for every view: **Title → key facts (KV) → sections → lineage
→ policy**. Views differ in which sections appear, never in order or style.

- **Root/command help:** Cobra-generated, left as-is structurally; we ensure our
  result output's tone/casing matches so help and results read as one tool.
- **Standard list (`people`/`accounts`/`roles`/`services`/`resources list`):**
  one `Table`. Header row `Header`-styled; `#` index column preserved (rows are
  addressable by index for detail commands — a hard constraint). Result count is
  **not** printed for plain lists (keeps them pipe-clean); the ClickOps report is
  the one exception (it already prints "Found N …").
- **`sessions list`:** `Table` with the `CHAINED` column carrying lineage markers
  (§4.3). Responsive column policy in §6.
- **Standard detail (`accounts`/`roles`/`services detail`):** `Title` +
  `KV` facts + per-section `Table`s (services, events, resources), each "top"
  list **count-descending**.
- **`sessions detail`:** `Title` (user) → `KV` (role, ARN, account, type, SID,
  time, events) → `Clients (N)` section (§5.1) → Session Tags → Denied Events →
  Top Events (**count desc** — fixes today's alphabetical sort) → Resources
  Accessed → agent/login/parent/child lineage (word-led, §4.3) → Session Policy
  (indented JSON). Order preserved from current code; only styling/sorting change.
- **`status`:** three `Status` lines to **stdout** (`✓/⚠/✗` + label); every
  diagnostic detail to **stderr**, emitted *after* its own status line so
  `Data access: FAIL` precedes its detail (fixes today's interleaving).
- **`resources list --clickops`:** the two-level report — summary `Table` then
  `Console Operations` grouped by resource — with `Warn`-accented ClickOps counts.
- **Policy output:** the IAM policy JSON to **stdout** (clean, pipeable to `jq`);
  the `--explain` summary (role, action count, unmapped events) to **stderr**.
  Unchanged stream split, consistent styling.
- **Empty results:** every list prints one `Empty` line to stdout
  (`No sessions found.`), replacing today's header-only output. Consistent across
  all list commands.
- **Validation errors:** one-line `Error` to stderr, `Error: <msg>`, exit 1.
  Cobra usage/flag dumps remain Cobra's (unchanged).
- **AWS/service errors:** one-line human `Error` + a one-line hint to stderr; the
  raw SDK error (request id, `ResourceNotFoundException`, HTTP status) is shown
  only when `TRAILTOOL_DEBUG=1` (or `--debug`). Exit 1.

### 5.1 Clients section (keep shipped semantics, restyle only)

The shipped rendering is semantically correct; we only restyle and make it
width-aware.

- Heading `Clients (N):`; clients sorted by `total_event_count` desc, then key.
- Identity line: `name [version] [category]  N requests: M ok[, K denied][, S service-driven]`.
  "requests" stays the label (inclusive of denied) — distinct from the session's
  success-only Events line. Denied count `Denied`-styled + word.
- Platform subtitle: `os osversion · arch · runtime` (middle dots), `Muted`.
- Seen line: `seen <start> → <end>` (§4.5 style).
- **API events** and **client commands** stay two separate labeled lists
  (different semantic levels), each count-desc, capped at 5.
- `components` and `raw_user_agent_samples` remain **JSON-only** by default; a
  `--verbose` on `sessions detail` may surface them (optional, §11).
- **Empty `clients[]` is ambiguous**, not proof of no client. When a session has
  events but no client aggregates, print a `Muted` note:
  `Clients: none recorded (pre-cutover data, service-only traffic, or no accepted user agent)`.
  An empty `clients[]` is not proof that no client was involved, and the note
  says so rather than silently omitting the section.

## 6. Responsive output

Break widths and behavior, tested deterministically by constructing a
`Context{Width: N}`.

| Width | Behavior |
|---|---|
| ≥ 132 (wide) | all columns; full role names when `--long`; no truncation unless a single field exceeds a generous cap |
| ~100 (normal-wide) | all essential + collapsible columns; ARNs/role names middle-truncate to fit |
| ~80 (normal, default) | essential columns only; collapsible columns dropped; long identifiers middle-truncate |
| ~60 (narrow) | essential columns only, aggressively truncated; if a row can't fit, wrap the least-essential field to a muted continuation line |

- **Column tiers** per table declared in `cli/view`: *essential* (never dropped),
  *collapsible* (dropped below a threshold), *`--long`-only* (full role names).
  `sessions list`: essential = `SID WHEN USER ROLE EVENTS`; collapsible =
  `ACCOUNT TYPE DURATION CHAINED`.
- **Long identifiers** (ARNs, emails, role names, resource ids) middle-truncate
  with `…`/`...`, preserving the distinguishing head and tail
  (`aws-reserved/…/AdministratorAccess_7d88aa2a`). `--long` disables role-name
  shortening (existing flag semantics preserved).
- **Non-TTY width is 80.** Redirected output is stable and diff-friendly.

## 7. Color/TTY/Unicode/JSON state matrix

| State | Color | Symbols | Width | Notes |
|---|---|---|---|---|
| Interactive TTY | on (auto) | Unicode | detected | full experience |
| Redirected stdout | off | ASCII? no — Unicode ok, color off | 80 | pipe-clean, stable |
| `--format json` | off | n/a | n/a | pure JSON, `Context` bypassed |
| `NO_COLOR` | off | Unicode | detected | meaning intact |
| `--color=always` | on | Unicode | detected | for `less -R` etc. |
| `TERM=dumb` | off | ASCII | 80 | maximally conservative |
| Narrow terminal | on (if TTY) | Unicode | detected | §6 truncation/wrap |
| Empty data | n/a | n/a | n/a | `Empty` line to stdout |
| Partial status failure | mixed | `✓`+`✗` | — | detail to stderr, ordered |
| Raw AWS failure | `Fail` | `✗` | — | clean msg+hint; raw behind `--debug` |
| Long identifiers | — | — | — | middle-truncate `…` |
| No client aggregates | — | — | — | ambiguity note (§5.1) |
| Multiple client families | — | — | — | one block each, sorted |
| Version/platform drift | — | — | — | separate aggregates, separate blocks |
| Agent + AWS MCP Server | — | — | — | word-led attribution, no implied causality |
| Long raw UA samples | — | — | — | JSON-only; truncated if `--verbose` |

## 8. Compatibility contract (preserved, tested)

Unchanged by this work, each with a guarding test:

- Command names and hierarchy; all flag names and semantics; exit codes.
- **All JSON field names, shapes, and values**, including the `clients[]` schema
  and aggregation key/semantics. `--format json` output is byte-for-byte
  unchanged except where a field was already broken.
- No new AWS API calls made for presentation.
- Pipe-friendliness: redirected output usable, no ANSI in non-TTY output.
- The non-interactive, one-command/one-result model. Not a TUI.
- Index-addressability of list rows.

## 9. Testing strategy (AWS-free, deterministic)

- **`internal/render` unit tests:** each primitive against a constructed
  `Context`; ANSI on/off; Unicode/ASCII; widths 60/80/100/132.
- **Golden/snapshot tests** in `cli/view`: feed fixture `models.*`, assert
  rendered output for representative widths and color modes. Fixtures required
  for: one client; mixed client families; version/platform drift; agent + AWS MCP
  Server; absent clients; denied client activity; service-driven client activity.
- **No-color parity test:** strip ANSI from a colored render and assert it equals
  the `Color:false` render — proves color is additive.
- **JSON-purity tests:** assert `--format json` output contains no ANSI escape
  and no human prefix, for a representative command per family.
- **Redirected-output test:** render with a non-TTY `Context` (Width 80, Color
  off) and assert stability.
- `go test ./...` **and** `go -C ingestor test ./...` green.

## 10. Rollout (stacked PRs off #25)

The design doc is PR 1. Implementation is four PRs, refactor before styling:

1. **`internal/render` core** — capability detection, styles, symbols,
   `Table`/`KV`/`Section`/`Status`/`Empty`/`Error`, `time.go` — with unit/golden
   tests. No command wiring; output unchanged.
2. **Behavior-preserving refactor** — split `main.go` into `cli/commands/` +
   `cli/view/`; existing output **byte-identical**, existing tests green. Pure
   move; reviewable as relocation.
3. **Wire lists + status + errors + empty** to `render` — color/symbols/
   responsive tables; fix Top-Events sort, timestamps, `status` stream ordering,
   AWS-error mapping.
4. **Wire session detail + Clients + ClickOps + policy** — responsive detail,
   Clients restyle + empty-ambiguity note, JSON-purity tests.

PRs 1–3 link `Part of #25`; PR 4 links `Closes #25`.

## 11. Accepted scope boundaries and optional follow-ups

**In scope (compatibility-preserving):** everything in §3–§9.

**Optional product recommendations (flagged, not bundled):**

- `--verbose` on `sessions detail` to surface `components` and
  `raw_user_agent_samples` in human output (JSON already exposes them). Additive
  flag; deferrable.
- A mixed-client **indicator** on `sessions list` (e.g. a `CLIENTS` column or a
  marker when a session spans client families). Recommendation: a **neutral**
  count/marker only — TrailTool reports, it does not adjudicate — rather than a
  security signal. Deferrable to a follow-up issue since it touches the list
  schema.

Neither is required for #25; both would be separate slices if pursued.
