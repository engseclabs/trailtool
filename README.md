# TrailTool

TrailTool aggregates CloudTrail logs to simplify analysis for AI agents. It combines:

- A Lambda function for ingesting, parsing, and correlating CloudTrail logs from an S3 bucket
- DynamoDB tables for persisting queryable entities: People, Sessions, Roles, Services, Resources
- `trailtool` CLI for accessing entity data to support common security and operational use cases

With TrailTool, you can:

- Investigate and summarize web/CLI sessions clarifying access patterns
- Track activity across role assumptions — see which human session assumed which roles and what they did
- Generate least-privilege IAM policies from actual usage
- Detect ClickOps resources created or modified via console instead of IaC

For more details about how to use TrailTool, see https://engseclabs.com/blog/cloudtrail-for-ai-agents/.

A hosted version with more features (e.g. UI, API, MCP) is available - see [trailtool.io](https://trailtool.io).

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

### Attribution: answering "who actually did this?"

Assumed roles, vended credentials, and MCP servers all sever the link between a
CloudTrail actor and the human behind it. TrailTool stitches that link back
together by correlating the grant events — `AssumeRole` and `CreateOAuth2Token`
— to the human session that authorized them. Each side of the relationship
cross-references the other by short SID in the `CHAINED` column, so the two rows
line up regardless of list order or filters.

Three grant paths are correlated, each verified end-to-end against real
CloudTrail:

| Path | How the actor gets credentials | Session `TYPE` |
|------|-------------------------------|----------------|
| **Role chaining** | `AssumeRole` — console switch-role and programmatic `aws sts assume-role` | `API` |
| **`aws login`** | A developer runs `aws login` to vend credentials to an AI agent (Claude Code, VS Code Copilot, etc.) | `LOGIN` |
| **AWS MCP Server** | An agent obtains credentials through the AWS MCP Server's OAuth flow | `AGENT` |

```
$ trailtool sessions list --days 1

SID     WHEN        USER               ROLE         ACCOUNT       EVENTS  TYPE   DURATION  CHAINED
k7m2qp  5 mins ago  alice@example.com  AdminAccess  123456789012  84      API    12m       → assumed q9x4mn  → granted b7k9mp
q9x4mn  5 mins ago  alice@example.com  DeployRole   123456789012  31      API    8m        ← assumed by k7m2qp
b7k9mp  5 mins ago  alice@example.com  AdminAccess  123456789012  3       LOGIN  8m        ← granted by k7m2qp
c3d5e7  5 mins ago  alice@example.com  AdminAccess  123456789012  9       AGENT  4m        ← granted by k7m2qp
```

The `CHAINED` marks read directionally — the verb carries the meaning and the
arrow reinforces it:

- `→ assumed <sid>` — this session assumed a role, creating session `<sid>` (or `→ assumed N roles` when there are several).
- `← assumed by <sid>` — this session *is* an assumed-role session, created by `<sid>`.
- `→ granted <sid>` — this session vended credentials (via `aws login` or an MCP grant) to session `<sid>`.
- `← granted by <sid>` — this session's credentials were vended by `<sid>`.

The detail view expands the relationship and gives a ready-to-run command for
the other end:

```bash
trailtool sessions detail --session k7m2qp
```

```
# Parent (grantor) side — roles it assumed:
Assumed Roles (1, 14 events):
  2026-07-22T18:19:56Z  DeployRole  31 events  8m  [5 mins ago]
    → trailtool sessions detail --session q9x4mn

# Parent (grantor) side — credentials it vended (aws login + MCP grants):
Authorized Sessions (2):
  2026-07-22T18:21:33Z  AGENT  AdminAccess  3 events  4m  [5 mins ago]
    → trailtool sessions detail --session c3d5e7
  2026-07-22T18:22:30Z  LOGIN  AdminAccess  2 events  3m  [5 mins ago]
    → trailtool sessions detail --session b7k9mp

# aws login child:
Credentials granted via aws login by: alice@example.com at 2026-07-22T18:20:18Z [8 minutes ago]
  → trailtool sessions detail --session k7m2qp

# AWS MCP Server child:
AWS MCP Server: https://aws-mcp.us-east-1.api.aws/mcp
OAuth grant authorized by: alice@example.com at 2026-07-22T18:20:18Z [5 mins ago]
  → trailtool sessions detail --session k7m2qp
```

Together these turn actor-anonymous activity — an assumed role, an agent's
vended credentials, or MCP traffic — back into "alice ran this," and separate
human-driven agent activity from background automation and long-running CLI
sessions.

All commands support `--format json` for machine-readable output.

## Using TrailTool with AI Coding Agents

TrailTool is designed to work well with AI coding agents like Claude Code and Cursor. To teach your agent about TrailTool's capabilities, copy [`docs/agent-instructions.md`](docs/agent-instructions.md) into your project as `CLAUDE.md` (or your agent's equivalent configuration file).

This gives your agent full knowledge of the CLI and step-by-step workflows for common tasks like detecting ClickOps, generating least-privilege IAM policies, and validating break-glass access.