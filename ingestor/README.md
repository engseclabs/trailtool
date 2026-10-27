# TrailTool Ingestor

The ingestor is the serverless half of [TrailTool](https://github.com/engseclabs/trailtool):
a Lambda function that reads CloudTrail log files as S3 delivers them, correlates
each event back to the human (or role) behind it, and writes queryable entities —
people, sessions, roles, services, resources, accounts — into DynamoDB. The
`trailtool` CLI reads those tables.

## What the stack creates

- **Lambda function** `trailtool-ingestor` (`provided.al2023`), triggered by
  EventBridge on `Object Created` under `AWSLogs/` with a `.json.gz` suffix.
- **DynamoDB tables** `trailtool-people`, `trailtool-sessions`, `trailtool-roles`,
  `trailtool-services`, `trailtool-resources`, `trailtool-accounts`,
  `trailtool-relations`, `trailtool-identity-links`, `trailtool-ingested-files`
  — all `PAY_PER_REQUEST`. The names are fixed because the CLI looks them up by
  name, so one stack per account/region.
- **EventBridge rule** `trailtool-cloudtrail-trigger` plus the Lambda invoke
  permission.
- **Custom resource** that enables EventBridge notifications on the CloudTrail
  bucket (skipped when `ManageBucketNotification` is `false`).

Deploying over a pre-1.0 stack **deletes** the old `*-aggregated` tables and
their data. There is no migration; history rebuilds from CloudTrail with
`trailtool replay`.

## Parameters

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `CloudTrailBucketName` | *(required)* | S3 bucket holding the CloudTrail logs. |
| `ManageBucketNotification` | `true` | Whether this stack turns on EventBridge notifications for the bucket. Set to `false` when another account owns it. |
| `EventSourceAccount` | `''` | Bucket owner's account ID, allowed to forward S3 events onto this account's default event bus. Set for cross-account (organization trail) deployments. |

## Deploy from the Serverless Application Repository

```yaml
Transform: AWS::Serverless-2016-10-31

Resources:
  TrailToolIngestor:
    Type: AWS::Serverless::Application
    Properties:
      Location:
        ApplicationId: arn:aws:serverlessrepo:us-east-1:<PUBLISHER_ACCOUNT_ID>:applications/trailtool-ingestor
        SemanticVersion: 1.0.0
      Parameters:
        CloudTrailBucketName: my-cloudtrail-bucket
```

The stack creates named IAM resources and an event bus policy, so deploy the
parent with:

```bash
aws cloudformation deploy --template-file parent.yaml --stack-name trailtool \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
                 CAPABILITY_AUTO_EXPAND CAPABILITY_RESOURCE_POLICY
```

The nested app's outputs (`FunctionName`, `SessionsTableName`, …) are available
to the parent as `!GetAtt TrailToolIngestor.Outputs.SessionsTableName`.

## Deploy from source

```bash
make build
sam deploy --parameter-overrides CloudTrailBucketName=my-cloudtrail-bucket
```

`template-sandbox.yaml` deploys the same ingestor alongside a fresh trail and
bucket; `template-forwarder.yaml` goes into the bucket-owning account for
cross-account organization trails (see `make deploy-org-all`). Neither is
published to the Serverless Application Repository.
