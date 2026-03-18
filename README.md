# TrailTool

Pre-aggregated CloudTrail for AI agents and humans. Turns raw CloudTrail logs into queryable entities: People, Sessions, Roles, Services, Resources.

A hosted version is available at [trailtool.io](https://trailtool.io).

## What It's For

- **Least-privilege IAM policies** from actual usage
- **Session investigation** — what did this user do, what got denied
- **ClickOps detection** — resources created via console instead of IaC

## Architecture

```
CloudTrail S3 → EventBridge → Ingestor Lambda → DynamoDB ← CLI
```

## Quick Start

### Deploy the Ingestor

Requires AWS SAM CLI. Deploys a Lambda, 6 DynamoDB tables, and an EventBridge rule.

```bash
cd ingestor
sam deploy --parameter-overrides \
  CloudTrailBucketName=your-bucket \
  CloudTrailBucketArn=arn:aws:s3:::your-bucket
```

### Install the CLI

```bash
go install github.com/engseclabs/trailtool/cmd/trailtool@latest
```

### Usage

```bash
# People
trailtool users list

# Sessions
trailtool sessions list --user alice@example.com --days 7
trailtool sessions detail --start-time "2025-01-15T10:30:00Z"
trailtool sessions summarize --start-time "2025-01-15T10:30:00Z"  # requires Bedrock

# Resources
trailtool resources list --days 30
trailtool resources list --clickops                    # ClickOps: console-created resources
trailtool resources list --clickops --service iam      # ClickOps filtered by service
trailtool resources list --service s3 --days 7

# IAM Policy
trailtool policy generate --role MyRole
trailtool policy generate --role MyRole --include-denied --explain
```

All commands support `--format json` for machine-readable output.

## Using with AI Agents

TrailTool's pre-aggregated data model means agents get concise, structured answers instead of raw log dumps. Example prompts:

> Identify resources created or modified via ClickOps over the last 30 days, and suggest Terraform import commands to bring them under IaC control.

> Remove unused permissions from IAM policies for roles assumable by Identity Center users.

> Add permissions for AccessDenied events on roles assumable by Identity Center users.

> Investigate the session for alex@example.com around 8AM March 18 to validate their break-glass justification.

## License

MIT
