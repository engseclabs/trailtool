# TrailTool

TrailTool aggregates CloudTrail logs to simplify analysis for AI agents. It combines:

- A Lambda function for ingesting, parsing, and correlating CloudTrail logs from an S3 bucket
- DynamoDB tables for persisting queryable entities: People, Sessions, Roles, Services, Resources
- `trailtool` CLI for accessing entity data to support common security and operational use cases

With TrailTool, you can:

- Investigate and summarize AWS access by people, agents, and code
- Track activity across role assumptions
- Generate least-privilege IAM policies from actual usage
- Detect malicious or unwanted (e.g. ClickOps) behavior

For more details about how to use TrailTool, see https://engseclabs.com/blog/cloudtrail-for-ai-agents/.

## Quick Start

### Deploy the Ingestor

*Requires [AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html)*

> **Upgrading from a pre-1.0 deployment?** The 1.0 ingestor replaces the old
> `trailtool-*-aggregated` DynamoDB tables with clean-named tables
> (`trailtool-sessions`, `trailtool-people`, …) under a new, identity-first
> schema. Redeploying **deletes the pre-1.0 tables and all their data** — there
> is no migration. History rebuilds from CloudTrail going forward.

### New CloudTrail

Creates new CloudTrail trail/S3 bucket in addition to trailtool resources:

```bash
cd ingestor
sam deploy --template-file template-sandbox.yaml
```

### Existing CloudTrail

Connects to your existing CloudTrail S3 bucket. A custom CloudFormation resource automatically enables EventBridge notifications on the bucket (required for triggering the ingestor on new log delivery):

```bash
cd ingestor
sam deploy --parameter-overrides \
  CloudTrailBucketName=your-bucket
```

## Install the CLI

```bash
brew install engseclabs/tap/trailtool
```

Or with Go:

```bash
go install github.com/engseclabs/trailtool/cmd/trailtool@latest
```

### Usage

```bash
# People
trailtool people list
trailtool people detail 5nmama                    # by PID (prefix ok)

# Sessions
trailtool sessions list --user alice@example.com --days 7
trailtool sessions list --role jlnjlx --account 123456789012 --has-denied
trailtool sessions list --type agent --after 2026-07-01T00:00:00Z
trailtool sessions list --user alice@example.com --days 7 --long  # show full role names
trailtool sessions detail k7m2qp          # by id (SID column, prefix ok)
trailtool sessions detail latest
trailtool sessions summarize k7m2qp        # requires Bedrock
trailtool sessions summarize k7m2qp --refresh

# Accounts
trailtool accounts list --has-denied
trailtool accounts detail 123456789012

# Roles
trailtool roles list --account 123456789012 --days 30
trailtool roles detail jlnjlx              # by role ID (prefix ok)
trailtool roles policy jlnjlx
trailtool roles policy jlnjlx --include-denied --explain

# Session-scoped policy (tighter: only what this session actually did)
trailtool sessions policy latest
trailtool sessions policy k7m2qp --explain

# Services
trailtool services list --category management --after 2026-07-01T00:00:00Z
trailtool services detail s3.amazonaws.com

# Resources
trailtool resources list --days 30
trailtool resources list --clickops                    # ClickOps: console-created resources
trailtool resources list --clickops --service iam      # ClickOps filtered by service
trailtool resources list --service s3 --days 7
trailtool resources detail fyf7wf                      # by RID (prefix ok)

# Setup diagnostics
trailtool status --format json
```

All commands support `--format json` for machine-readable output.
Detail text shows denied totals by default; add `--include-denied-details` for
per-event breakdowns and denied resource-access rows. Detail JSON stays complete.
Noun list and detail relationship totals come from exact distinct-count
summaries; stored aggregate counts are used only if a summary is unavailable.
Aggregate noun lists accept `--days`, `--after`, `--before`, and `--has-denied`.
Time filters select rows using `last_seen`; successful and denied activity totals
remain lifetime totals. With `resources list --clickops`, the ClickOps rows and
count are limited to the requested period.

Session summaries are cached with their model, generation time, token usage,
and input digest. New session activity makes the cache stale automatically.
Use `--refresh` to replace a current cached summary.

### Session aggregation

CloudTrail is a stream of independent events; sessions are an overlay TrailTool derives from latent metadata AWS stamps on those events. The goal is to tie every event back to the initiating human (or, failing that, the role).

TrailTool stitches events into sessions, gives each resulting session a **session type**, and records a **session chain** between sessions when there is role chaining, `aws login`, or AWS MCP Server correlation.

For example:
```
$ trailtool sessions list --days 1

SID     WHEN        USER               ROLE         ACCOUNT       EVENTS  TYPE   DURATION  CHAINED
k7m2qp  5 mins ago  alice@example.com  AdminAccess  123456789012  84      CLI    12m       → assumed q9x4mn  → granted b7k9mp
q9x4mn  5 mins ago  alice@example.com  DeployRole   123456789012  31      CLI    8m        ← assumed by k7m2qp
b7k9mp  5 mins ago  alice@example.com  AdminAccess  123456789012  3       LOGIN  8m        ← granted by k7m2qp
c3d5e7  5 mins ago  alice@example.com  AdminAccess  123456789012  9       AGENT  4m        ← granted by k7m2qp
```


| `TYPE` | Meaning |
|--------|---------|
| `CLI` | CLI/SDK credential session |
| `WEB` | Console (browser) session |
| `AGENT` | AWS MCP Server traffic |
| `LOGIN` | Credentials vended to an agent via `aws login` |


## Using TrailTool with AI Coding Agents

TrailTool is designed to work well with AI coding agents like Claude Code and Cursor. To teach your agent about TrailTool's capabilities, copy [`docs/agent-instructions.md`](docs/agent-instructions.md) into your project as `CLAUDE.md` (or your agent's equivalent configuration file).

This gives your agent full knowledge of the CLI and step-by-step workflows for common tasks like detecting ClickOps, generating least-privilege IAM policies, and validating break-glass access.
