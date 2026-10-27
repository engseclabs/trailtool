# TrailTool Ingestor

The ingestor is the serverless half of [TrailTool](https://github.com/engseclabs/trailtool):
a Lambda function that reads CloudTrail log files as S3 delivers them, correlates
each event back to the human (or role) behind it, and writes queryable entities —
people, sessions, roles, services, resources, accounts — into DynamoDB. The
`trailtool` CLI reads those tables.

Two applications are published to the Serverless Application Repository (SAR),
always at the same version:

- `trailtool-ingestor` (`template.yaml`) runs where you want the data.
- `trailtool-cloudtrail-forwarder` (`template-forwarder.yaml`) runs in the
  bucket owner's account, for cross-account setups only.

S3 publishes EventBridge notifications only to the bucket owner's account. If the
bucket and the ingestor share an account, nothing needs forwarding. If the bucket
lives elsewhere (for example an organization trail in a log archive account),
that account forwards the events to the ingestor's.

Neither template touches the bucket. Enabling notifications and granting read
access are the bucket owner's job.

## Same-account setup

Deploy in the bucket's region. The steps can run in any order.

1. **Bucket:** [enable EventBridge notifications](#enabling-eventbridge-notifications).
   Or deploy the ingestor with `ManageBucketNotification=true` and it does this.
2. **Ingestor:** deploy `trailtool-ingestor` with `CloudTrailBucketName`.

   ```yaml
   # ingestor.yaml
   Transform: AWS::Serverless-2016-10-31
   Resources:
     TrailToolIngestor:
       Type: AWS::Serverless::Application
       Properties:
         Location:
           ApplicationId: arn:aws:serverlessrepo:us-east-1:843363563907:applications/trailtool-ingestor
           SemanticVersion: 1.2.0
         Parameters:
           CloudTrailBucketName: my-cloudtrail-bucket
           ManageBucketNotification: 'false'
   Outputs:
     CloudTrailBucketName: # read by `trailtool replay`
       Value: !GetAtt TrailToolIngestor.Outputs.CloudTrailBucketName
   ```

   ```bash
   aws cloudformation deploy --template-file ingestor.yaml --stack-name trailtool-ingestor \
     --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND CAPABILITY_RESOURCE_POLICY
   ```

   ```hcl
   resource "aws_serverlessapplicationrepository_cloudformation_stack" "trailtool_ingestor" {
     name             = "trailtool-ingestor"
     application_id   = "arn:aws:serverlessrepo:us-east-1:843363563907:applications/trailtool-ingestor"
     semantic_version = "1.2.0"
     capabilities     = ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND", "CAPABILITY_RESOURCE_POLICY"]
     parameters = {
       CloudTrailBucketName     = "my-cloudtrail-bucket"
       ManageBucketNotification = "false"
     }
   }
   ```

## Cross-account setup

`BUCKET_ACCOUNT` owns the bucket; `INGESTOR_ACCOUNT` runs TrailTool. The steps
can run in any order.

1. **Bucket owner:** [enable EventBridge notifications](#enabling-eventbridge-notifications).
2. **Bucket owner:** grant the ingestor role `s3:GetObject` in the bucket policy.
   Name the account, not the role: S3 rejects a policy naming a role that
   doesn't exist yet.

   ```json
   {
     "Sid": "TrailToolIngestorRead",
     "Effect": "Allow",
     "Principal": { "AWS": "arn:aws:iam::INGESTOR_ACCOUNT:root" },
     "Action": "s3:GetObject",
     "Resource": "arn:aws:s3:::my-cloudtrail-bucket/*",
     "Condition": {
       "ArnEquals": { "aws:PrincipalArn": "arn:aws:iam::INGESTOR_ACCOUNT:role/trailtool-ingestor-role" }
     }
   }
   ```

   ```bash
   aws s3api get-bucket-policy --bucket my-cloudtrail-bucket --query Policy --output text > policy.json
   # add the statement to policy.json — put-bucket-policy replaces the whole policy
   aws s3api put-bucket-policy --bucket my-cloudtrail-bucket --policy file://policy.json
   ```

   `trailtool replay` also needs `s3:ListBucket` on the bucket for whoever runs
   it. SSE-KMS buckets also need `kms:Decrypt` for the ingestor role, which the
   template doesn't grant.
3. **Ingestor account:** deploy `trailtool-ingestor` as above, with
   `ManageBucketNotification: 'false'` and `EventSourceAccount: 'BUCKET_ACCOUNT'`.
4. **Bucket owner account:** deploy `trailtool-cloudtrail-forwarder` in the
   bucket's region. Set `IngestorRegion` if the ingestor runs in another region.

   ```yaml
   # forwarder.yaml
   Transform: AWS::Serverless-2016-10-31
   Resources:
     TrailToolForwarder:
       Type: AWS::Serverless::Application
       Properties:
         Location:
           ApplicationId: arn:aws:serverlessrepo:us-east-1:843363563907:applications/trailtool-cloudtrail-forwarder
           SemanticVersion: 1.2.0
         Parameters:
           CloudTrailBucketName: my-cloudtrail-bucket
           IngestorAccountId: 'INGESTOR_ACCOUNT'
   ```

   ```bash
   aws cloudformation deploy --template-file forwarder.yaml --stack-name trailtool-cloudtrail-forwarder \
     --capabilities CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND
   ```

   ```hcl
   resource "aws_serverlessapplicationrepository_cloudformation_stack" "trailtool_forwarder" {
     provider         = aws.log_archive
     name             = "trailtool-cloudtrail-forwarder"
     application_id   = "arn:aws:serverlessrepo:us-east-1:843363563907:applications/trailtool-cloudtrail-forwarder"
     semantic_version = "1.2.0"
     capabilities     = ["CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"]
     parameters = {
       CloudTrailBucketName = "my-cloudtrail-bucket"
       IngestorAccountId    = "INGESTOR_ACCOUNT"
     }
   }
   ```

Steps 3 and 4 can run in either order. Events forwarded before the ingestor's
event bus policy exists fail delivery; `trailtool replay` backfills them.

## Enabling EventBridge notifications

`put-bucket-notification-configuration` **replaces the bucket's entire
notification config**. Fetch it first and merge `EventBridgeConfiguration` in:

```bash
aws s3api get-bucket-notification-configuration --bucket my-cloudtrail-bucket --output json > notification.json
jq -s '(.[0] // {}) + {EventBridgeConfiguration: {}}' notification.json > merged.json
aws s3api put-bucket-notification-configuration --bucket my-cloudtrail-bucket \
  --notification-configuration file://merged.json
```

In Terraform, `aws_s3_bucket_notification` with `eventbridge = true` owns the
whole config too, so declare the bucket's other notifications in the same
resource.

## Capabilities

| Application | Capabilities |
|-------------|--------------|
| `trailtool-ingestor` | `CAPABILITY_IAM`, `CAPABILITY_NAMED_IAM`, `CAPABILITY_AUTO_EXPAND`, `CAPABILITY_RESOURCE_POLICY` |
| `trailtool-cloudtrail-forwarder` | `CAPABILITY_NAMED_IAM`, `CAPABILITY_AUTO_EXPAND` |

## Verify it works

CloudTrail delivers a file about every five minutes, so within about five
minutes the ingestor's logs should show one:

```bash
aws logs tail /aws/lambda/trailtool-ingestor --since 15m --follow
```

Then `trailtool people list` should show data. If nothing arrives cross-account,
check the forwarder rule's `FailedInvocations` metric in `BUCKET_ACCOUNT`. Run
`trailtool replay` to backfill older logs.

## What the stacks create

`trailtool-ingestor`:

- **Lambda function** `trailtool-ingestor` (`provided.al2023`), triggered by
  EventBridge on `Object Created` under `AWSLogs/` with a `.json.gz` suffix.
- **DynamoDB tables** `trailtool-people`, `trailtool-sessions`, `trailtool-roles`,
  `trailtool-services`, `trailtool-resources`, `trailtool-accounts`,
  `trailtool-relations`, `trailtool-identity-links`, `trailtool-ingested-files`
  — all `PAY_PER_REQUEST`. The names are fixed because the CLI looks them up by
  name, so one stack per account/region.
- **EventBridge rule** `trailtool-cloudtrail-trigger` plus the Lambda invoke
  permission, and an event bus policy when `EventSourceAccount` is set.
- **Custom resource** that enables EventBridge notifications on the CloudTrail
  bucket (skipped when `ManageBucketNotification` is `false`).

`trailtool-cloudtrail-forwarder`: an EventBridge rule forwarding
`*/CloudTrail/*.json.gz` deliveries to the ingestor account's default bus, and
the role it uses. When `IngestorAccountId` is empty or the stack's own account,
it creates only an inert placeholder.

Deploying over a pre-1.0 stack **deletes** the old `*-aggregated` tables and
their data. There is no migration; history rebuilds from CloudTrail with
`trailtool replay`.

## Parameters

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `CloudTrailBucketName` | *(required)* | S3 bucket holding the CloudTrail logs. |
| `ManageBucketNotification` | `true` | Whether this stack turns on EventBridge notifications for the bucket. Set to `false` when another account owns it. |
| `EventSourceAccount` | `''` | Bucket owner's account ID, allowed to forward S3 events onto this account's default event bus. Set for cross-account deployments. |

Forwarder:

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `CloudTrailBucketName` | *(required)* | The CloudTrail bucket, owned by this account. |
| `IngestorAccountId` | `''` | Account running the ingestor. Empty or this account forwards nothing. |
| `IngestorRegion` | `''` | Region of the ingestor's event bus. Empty means this stack's region. |

## Deploy from source

```bash
make build
sam deploy --parameter-overrides CloudTrailBucketName=my-cloudtrail-bucket
```

`template-sandbox.yaml` deploys the same ingestor alongside a fresh trail and
bucket. For cross-account organization trails, `make deploy-org-all` deploys the
ingestor and the forwarder from source.
