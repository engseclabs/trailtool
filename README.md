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

# Sessions
trailtool sessions list --user alice@example.com --days 7
trailtool sessions list --user alice@example.com --days 7 --long  # show full role names
trailtool sessions detail --session k7m2qp          # by id (SID column, prefix ok)
trailtool sessions detail --session latest
trailtool sessions detail --session latest --user alice@example.com
trailtool sessions summarize --session k7m2qp        # requires Bedrock

# Accounts
trailtool accounts list
trailtool accounts detail 123456789012
trailtool accounts detail --index 1      # by list position

# Roles
trailtool roles list
trailtool roles detail MyRole
trailtool roles detail --index 2         # by list position
trailtool roles policy MyRole
trailtool roles policy MyRole --include-denied --explain

# Session-scoped policy (tighter: only what this session actually did)
trailtool sessions policy --session latest
trailtool sessions policy --session k7m2qp --explain

# Services
trailtool services list
trailtool services detail s3.amazonaws.com
trailtool services detail --index 3      # by list position

# Resources
trailtool resources list --days 30
trailtool resources list --clickops                    # ClickOps: console-created resources
trailtool resources list --clickops --service iam      # ClickOps filtered by service
trailtool resources list --service s3 --days 7
```

All commands support `--format json` for machine-readable output.

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
