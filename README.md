# TrailTool

TrailTool makes auditing CloudTrail logs *fast* and *powerful*.

![TrailTool CLI demo with masked data](docs/assets/trailtool-demo.gif)

With TrailTool, you can:

- Correlate human and agent activity to investigate and summarize access
- Track identity across role assumptions and OAuth authorization (e.g. `aws login` and AWS MCP)
- Generate least-privilege IAM policies from usage
- Detect malicious or unwanted (e.g. ClickOps) behavior

TrailTool is composed of:

- An ingestor Lambda function for parsing and correlating CloudTrail from S3.
- DynamoDB tables for persisting queryable entities: People, Sessions, Roles, Services, Resources
- `trailtool` CLI for accessing DynamoDB data and supporting common use cases

## Quick Start

The ingestor is published to the Serverless Application Repository as
`trailtool-ingestor`, with `trailtool-cloudtrail-forwarder` for buckets in
another account. [`ingestor/README.md`](ingestor/README.md) has CloudFormation
and Terraform examples for each step, and how to verify the setup.

S3 publishes EventBridge notifications only to the bucket owner's account, so
the setup depends on where the CloudTrail bucket lives. In both, the steps can
run in any order.

### Same account

1. **Bucket:** enable EventBridge notifications (see the warning below), or
   deploy the ingestor with `ManageBucketNotification=true` and it does this.
2. **Ingestor:** deploy `trailtool-ingestor` with `CloudTrailBucketName`.

### Cross account

For example, an organization trail whose bucket is in a log archive account.

1. **Bucket owner:** enable EventBridge notifications.
2. **Bucket owner:** grant `trailtool-ingestor-role` `s3:GetObject` in the bucket
   policy. Grant the ingestor account root with an `aws:PrincipalArn`
   condition, because S3 rejects a policy naming a role that doesn't exist yet.
3. **Ingestor account:** deploy `trailtool-ingestor` with
   `ManageBucketNotification=false` and `EventSourceAccount=<bucket owner account>`.
4. **Bucket owner account:** deploy `trailtool-cloudtrail-forwarder` with
   `CloudTrailBucketName` and `IngestorAccountId`.

Steps 3 and 4 can run in either order. Events forwarded before the ingestor's
event bus policy exists fail delivery; `trailtool replay` backfills them.

> [!WARNING]
> `aws s3api put-bucket-notification-configuration` replaces the bucket's whole
> notification config. Fetch it with `get-bucket-notification-configuration` and
> merge `EventBridgeConfiguration` in. Terraform's `aws_s3_bucket_notification`
> with `eventbridge = true` likewise owns the whole config.

### Deploy from source

*Requires [AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html)*

```bash
cd ingestor
sam deploy --template-file template-sandbox.yaml                          # new trail and bucket
sam deploy --parameter-overrides CloudTrailBucketName=your-bucket         # existing bucket
make deploy-org-all TRAIL_BUCKET=your-bucket BUCKET_ACCOUNT=111111111111  # cross account
```

## Install the CLI

```bash
brew install engseclabs/tap/trailtool
```

Or with Go:

```bash
go install github.com/engseclabs/trailtool/cmd/trailtool@latest
```

## Usage

```bash
# People
trailtool people list
trailtool people detail <id>

# Sessions
trailtool sessions list
trailtool sessions detail <id>
trailtool sessions summarize <id>
trailtool sessions policy <id>

# Accounts
trailtool accounts list
trailtool accounts detail <account-id>

# Roles
trailtool roles list <id>
trailtool roles policy <id>

# Services
trailtool services list
trailtool services detail <service-name>

# Resources
trailtool resources list
trailtool resources list
trailtool resources detail <id>

# Setup diagnostics
trailtool status
```

All commands support `--format json` for machine-readable output.

### What are sessions?

CloudTrail is a stream of independent events; sessions are an overlay TrailTool derives from latent metadata AWS stamps on those events. The goal is to tie every event back to the initiating human (or, failing that, the role).

TrailTool stitches events into sessions, gives each resulting session a **session type**, and records a **session chain** between sessions when there is role chaining, `aws login`, or AWS MCP Server correlation.

| `TYPE` | Meaning |
|--------|---------|
| `CLI` | CLI/SDK credential session |
| `WEB` | Console (browser) session |
| `AGENT` | AWS MCP Server traffic |
| `LOGIN` | Credentials vended to an agent via `aws login` |

## Change events

The ingestor can publish what it learns to EventBridge, so alerting and triage systems can react to TrailTool's identity correlation without reading its tables. Deploy `trailtool-ingestor` with `ActivityEventBusArn` set to a bus ARN; it is off when empty. Consumers filter on `source: "trailtool"` and the `detail-type`:

| `detail-type` | Fires when |
|---------------|------------|
| `TrailTool Noun Created` | a person, account, role, service, or resource appears for the first time |
| `TrailTool Relation Created` | two nouns are linked for the first time (for example, a person reaches a new account) |
| `TrailTool Session Activity` | a session does anything in a CloudTrail file, with its writes and denied calls |

Events come only from live ingestion; `trailtool replay` never publishes them. Delivery is best-effort. Schemas and delivery semantics are in [`docs/design/events.md`](docs/design/events.md).

## Using TrailTool with agents

TrailTool is designed to work well with AI coding agents like Claude Code and Cursor. To teach your agent about TrailTool's capabilities, copy [`docs/agent-instructions.md`](docs/agent-instructions.md) into your project as `CLAUDE.md` (or your agent's equivalent configuration file).

This gives your agent full knowledge of the CLI and step-by-step workflows for common tasks like detecting ClickOps, generating least-privilege IAM policies, and validating break-glass access.
