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

*Requires [AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html)*

### Deploy the Ingestor with a new CloudTrail

Creates new CloudTrail trail/S3 bucket in addition to trailtool resources:

```bash
cd ingestor
sam deploy --template-file template-sandbox.yaml
```

### Deploy the Ingestor with an existing CloudTrail

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

## Using TrailTool with agents

TrailTool is designed to work well with AI coding agents like Claude Code and Cursor. To teach your agent about TrailTool's capabilities, copy [`docs/agent-instructions.md`](docs/agent-instructions.md) into your project as `CLAUDE.md` (or your agent's equivalent configuration file).

This gives your agent full knowledge of the CLI and step-by-step workflows for common tasks like detecting ClickOps, generating least-privilege IAM policies, and validating break-glass access.
