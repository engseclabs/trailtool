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
trailtool sessions detail --at 2025-01-15T10:30
trailtool sessions detail --index 1 --user alice@example.com --days 7  # by list position
trailtool sessions detail --at 2025-01-15T10:30 --user alice@example.com
trailtool sessions detail --at latest
trailtool sessions summarize --at 2025-01-15T10:30  # requires Bedrock

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
trailtool sessions policy --at latest
trailtool sessions policy --at 2025-01-15T10:35 --user alice@example.com --explain

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

### Role Chaining

TrailTool automatically correlates `AssumeRole` calls back to the originating human session, for both console switch-role and programmatic (`aws sts assume-role`) flows. This lets you answer "who actually did this?" even when the CloudTrail actor is an assumed role with no obvious human attribution.

```
$ trailtool sessions list --days 1

#  WHEN        USER                  ROLE         ACCOUNT        EVENTS  TYPE     DURATION  CHAINED
1  5 mins ago  alice@example.com     AdminAccess  123456789012   84      API      12m       → 2 role(s)
2  5 mins ago  alice@example.com     DeployRole   123456789012   31      API      8m        ↑ child
3  5 mins ago  alice@example.com     AuditRole    123456789012   12      API      3m        ↑ child
```

`→ N role(s)` means this human session assumed N roles. `↑ child` means this session was created via `AssumeRole` and is attributed back to its parent.

```bash
# See which roles a session assumed and how many events each generated
trailtool sessions detail --at 2025-01-15T10:30 --user alice@example.com

# The detail view shows the full chain:
# Assumed by: alice@example.com at 2025-01-15T10:30:00Z            (on child sessions)
#   → trailtool sessions detail --at 2025-01-15T10:30 --user alice@example.com
#
# Assumed Roles (2, 43 events):                                    (on parent sessions)
#   2025-01-15T10:35:00Z  DeployRole  31 events  8m
#     → trailtool sessions detail --at 2025-01-15T10:35 --user alice@example.com
#   2025-01-15T10:36:00Z  AuditRole   12 events  3m
#     → trailtool sessions detail --at 2025-01-15T10:36 --user alice@example.com
```

### `aws login` Session Detection

When a developer runs `aws login` to vend credentials to an AI agent (Claude Code, VS Code Copilot, etc.), TrailTool detects the `CreateOAuth2Token` event on `signin.amazonaws.com` and correlates it back to the agent session that received those credentials. The agent session is tagged as `LOGIN` type and includes attribution back to the authorizing human session.

```
$ trailtool sessions list --days 1

WHEN        USER                  ROLE         ACCOUNT        EVENTS  TYPE     DURATION  CHAINED
5 mins ago  alice@example.com     AdminAccess  123456789012   3       LOGIN    8m        ← login
8 mins ago  alice@example.com     AdminAccess  123456789012   84      API      12m
```

`← login` means the session's credentials were vended via `aws login` by a human in another session. The detail view shows the attribution:

```
Credentials granted via aws login by: alice@example.com at 2025-01-15T10:30:00Z (8 minutes ago)
  → trailtool sessions detail --at 2025-01-15T10:30 --user alice@example.com
```

This distinguishes agent-driven activity (credentials vended by a human developer via `aws login`) from background automation or long-running CLI sessions.

All commands support `--format json` for machine-readable output.

## Using TrailTool with AI Coding Agents

TrailTool is designed to work well with AI coding agents like Claude Code and Cursor. To teach your agent about TrailTool's capabilities, copy [`docs/agent-instructions.md`](docs/agent-instructions.md) into your project as `CLAUDE.md` (or your agent's equivalent configuration file).

This gives your agent full knowledge of the CLI and step-by-step workflows for common tasks like detecting ClickOps, generating least-privilege IAM policies, and validating break-glass access.