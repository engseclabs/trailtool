# TrailTool

Open-source CLI and core library for analyzing AWS CloudTrail data. Provides visibility into user sessions, role usage, and generates least-privilege IAM policies from observed activity.

## What It Does

TrailTool processes CloudTrail logs at write-time into DynamoDB, then lets you query that data:

- **Users** - List all Identity Center users with session/role/account counts
- **Sessions** - Browse time-bounded activity windows per user+role
- **IAM Policy Generation** - Generate least-privilege policies from actual CloudTrail usage (18,600+ event-to-action mappings)
- **AI Summaries** - Summarize sessions in plain English via Amazon Bedrock

## Architecture

```
CloudTrail S3 → EventBridge → Ingestor Lambda → DynamoDB ← CLI queries
```

The **ingestor** is a Go Lambda that processes CloudTrail log files as they arrive in S3, aggregating events into 6 DynamoDB tables (roles, services, resources, people, sessions, accounts).

The **CLI** queries those tables directly using the AWS SDK.

## Quick Start

### Prerequisites

- Go 1.25+
- AWS account with CloudTrail enabled
- AWS CLI configured (`aws configure`)

### Deploy the Ingestor

```bash
cd ingestor
make build
make deploy PARAMS="CloudTrailBucketName=your-bucket CloudTrailBucketArn=arn:aws:s3:::your-bucket"
```

Optionally enable Identity Center display name enrichment:

```bash
make deploy PARAMS="CloudTrailBucketName=your-bucket CloudTrailBucketArn=arn:aws:s3:::your-bucket IdentityCenterInstanceArn=arn:aws:sso:::instance/ssoins-xxxxx"
```

### Install the CLI

```bash
go install github.com/engseclabs/trailtool/cmd/trailtool@latest
```

Or build from source:

```bash
go build -o trailtool ./cmd/trailtool
```

### Usage

```bash
# List all tracked users
trailtool users list

# List sessions (optionally filter by user or time window)
trailtool sessions list
trailtool sessions list --user alice@example.com --days 7

# View session details
trailtool sessions detail --start-time "2025-01-15T10:30:00Z"

# Generate AI summary of a session (requires Bedrock access)
trailtool sessions summarize --start-time "2025-01-15T10:30:00Z"

# Generate least-privilege IAM policy for a role
trailtool policy generate --role MyRoleName
trailtool policy generate --role arn:aws:iam::123456789012:role/MyRole --explain

# Include denied events in policy generation
trailtool policy generate --role MyRole --include-denied

# JSON output for scripting
trailtool users list --format json
trailtool policy generate --role MyRole --format json
```

## Project Structure

```
cmd/trailtool/       CLI binary (cobra)
core/
  models/            Shared types (Person, Session, Role, etc.)
  store/             DynamoDB client and queries
  policy/            IAM policy generator + 18K CloudTrail→IAM mappings
  session/           Session queries and Bedrock summarization
ingestor/            CloudTrail log processor (Lambda + SAM template)
```

## How It Works

### Session Detection

Uses `sessionContext.attributes.creationDate` from CloudTrail as the session identifier. All events from the same IAM console session share the exact same creation timestamp.

### Identity Center Integration

Tracks AWS IAM Identity Center (SSO) federated users by detecting role patterns (`/aws-reserved/sso.amazonaws.com/AWSReservedSSO_*`) and extracting emails from `principalId`.

### IAM Policy Generation

Maps CloudTrail event names to IAM actions using [iann0036/iam-dataset](https://github.com/iann0036/iam-dataset) (18,613 mappings). Generates resource-constrained policies with specific ARNs when possible.

### Resource Extraction

Extracts parent resources from CloudTrail events to prevent database explosion:
- S3: `bucketName` (not object keys)
- Lambda: `functionName`
- DynamoDB: `tableName`

## Configuration

The CLI reads from DynamoDB tables with the `trailtool-` prefix. All queries use `customerID = "default"` as the partition key.

| Table | Partition Key | Sort Key |
|-------|--------------|----------|
| trailtool-people-aggregated | customerId | email |
| trailtool-sessions-aggregated | customerId | session_start |
| trailtool-roles-aggregated | customerId | arn |
| trailtool-services-aggregated | customerId | event_source |
| trailtool-resources-aggregated | customerId | identifier |
| trailtool-accounts-aggregated | customerId | account_id |

### Required IAM Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["dynamodb:Query", "dynamodb:GetItem"],
      "Resource": "arn:aws:dynamodb:*:*:table/trailtool-*"
    },
    {
      "Effect": "Allow",
      "Action": "bedrock:InvokeModel",
      "Resource": "arn:aws:bedrock:*::foundation-model/anthropic.claude-*"
    }
  ]
}
```

The Bedrock permission is only needed for `sessions summarize`.

### AWS Profile

Set your AWS profile if not using the default:

```bash
export AWS_PROFILE=your-profile
```

## Using as a Go Library

The `core/` package is designed to be imported by other Go projects:

```go
import (
    "github.com/engseclabs/trailtool/core/models"
    "github.com/engseclabs/trailtool/core/store"
    "github.com/engseclabs/trailtool/core/policy"
    "github.com/engseclabs/trailtool/core/session"
)

// Query sessions
s, _ := store.NewStore(ctx)
sessions, _ := s.ListSessions(ctx, "your-customer-id", "user@example.com", 7)

// Generate policy for a role
role, _ := s.GetRoleByName(ctx, "your-customer-id", "MyRole")
result, _ := policy.GeneratePolicy(role, false)
fmt.Println(result.PolicyJSON)

// AI summarize a session
summary, _ := session.SummarizeSession(ctx, &sessions[0])
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | AWS/infrastructure error |
| 2 | Resource not found |
| 3 | Bad arguments |
| 4 | Bedrock invocation error |

## License

MIT
