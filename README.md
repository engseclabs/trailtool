# TrailTool

TrailTool aggregates CloudTrail logs to simplify analysis for AI agents. It combines:

- A Lambda function for ingesting, parsing, and correlating CloudTrail logs from an S3 bucket
- DynamoDB tables for persisting queryable entities: People, Sessions, Roles, Services, Resources
- `trailtool` CLI for accessing entity data to support common security and operational use cases

```
CloudTrail S3 → EventBridge → Ingestor Lambda → DynamoDB ← CLI
```

*A hosted version with more features (e.g. UI, API, MCP) is available - see [trailtool.io](https://trailtool.io).*

## Use cases

- Investigate and summarize web/CLI sessions clarifying access patterns
- Generate least-privilege IAM policies from actual usage
- Detect ClickOps resources created or modified via console instead of IaC

For details, see https://engseclabs.com/blog/cloudtrail-for-ai-agents/


## Quick Start

### Deploy the Ingestor

*Requires [AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html)*

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
go install github.com/engseclabs/trailtool/cmd/trailtool@latest
```

### Usage

```bash
# People
trailtool people list

# Sessions
trailtool sessions list --user alice@example.com --days 7
trailtool sessions detail --start-time "2025-01-15T10:30:00Z"
trailtool sessions summarize --start-time "2025-01-15T10:30:00Z"  # requires Bedrock

# Accounts
trailtool accounts list
trailtool accounts detail 123456789012

# Roles
trailtool roles list
trailtool roles detail MyRole
trailtool roles policy MyRole
trailtool roles policy MyRole --include-denied --explain

# Services
trailtool services list
trailtool services detail s3.amazonaws.com

# Resources
trailtool resources list --days 30
trailtool resources list --clickops                    # ClickOps: console-created resources
trailtool resources list --clickops --service iam      # ClickOps filtered by service
trailtool resources list --service s3 --days 7
```

All commands support `--format json` for machine-readable output.