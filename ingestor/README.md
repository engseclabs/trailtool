# TrailTool Ingestor

The ingestor is the serverless half of [TrailTool](https://github.com/engseclabs/trailtool):
a Lambda function that reads CloudTrail log files as S3 delivers them, correlates
each event back to the human (or role) behind it, and writes queryable entities —
people, sessions, roles, services, resources, accounts — into DynamoDB. The
`trailtool` CLI reads those tables.

Two applications are published to the AWS Serverless Application Repository
(SAR), always at the same version:

| Application | Template | Deploy it in |
|-------------|----------|--------------|
| `trailtool-ingestor` | `template.yaml` | the account where you want the TrailTool data |
| `trailtool-cloudtrail-forwarder` | `template-forwarder.yaml` | the account that owns the CloudTrail bucket, only when that is a different account |

Neither published template creates or owns the bucket. Turning on EventBridge
notifications and granting read access are the bucket owner's job, because the
bucket is often managed elsewhere (Control Tower, Terraform).

## Choose a setup

S3 publishes EventBridge notifications only to the default event bus of the
**bucket owner's account**.

- **[Same account](#same-account-setup):** the bucket and the ingestor are in one
  account. The ingestor's own EventBridge rule sees the events, so nothing needs
  forwarding.
- **[Cross account](#cross-account-setup):** the bucket is in another account,
  for example an organization trail bucket in a log archive account. That
  account has to forward the events to the ingestor account's bus.

In the examples below, `<PUBLISHER_ACCOUNT_ID>` is the account that publishes
the SAR applications. Pin both applications to the same `SemanticVersion`.

## Same-account setup

Run the ingestor in the **bucket's region**. These steps are independent and can
run in any order.

### 1. Bucket: enable EventBridge notifications

This is a prerequisite, done by whoever manages the bucket. See
[Enabling EventBridge notifications](#enabling-eventbridge-notifications). If you
want the ingestor to do it instead, deploy it with
`ManageBucketNotification=true`. Its custom resource merges
`EventBridgeConfiguration` into the existing config.

### 2. Ingestor: deploy `trailtool-ingestor`

CloudFormation (`ingestor.yaml`):

```yaml
Transform: AWS::Serverless-2016-10-31

Resources:
  TrailToolIngestor:
    Type: AWS::Serverless::Application
    Properties:
      Location:
        ApplicationId: arn:aws:serverlessrepo:us-east-1:<PUBLISHER_ACCOUNT_ID>:applications/trailtool-ingestor
        SemanticVersion: 1.2.0
      Parameters:
        CloudTrailBucketName: my-cloudtrail-bucket
        ManageBucketNotification: 'false' # step 1 handles it; 'true' to let this stack do it

# Lets `trailtool replay` discover the bucket from this stack.
Outputs:
  CloudTrailBucketName:
    Value: !GetAtt TrailToolIngestor.Outputs.CloudTrailBucketName
```

```bash
aws cloudformation deploy --template-file ingestor.yaml --stack-name trailtool-ingestor \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
                 CAPABILITY_AUTO_EXPAND CAPABILITY_RESOURCE_POLICY
```

Name the stack `trailtool-ingestor` (or `trailtool`). `trailtool status` and
`trailtool replay` look for a stack with that name.

Terraform:

```hcl
resource "aws_serverlessapplicationrepository_cloudformation_stack" "trailtool_ingestor" {
  name             = "trailtool-ingestor"
  application_id   = "arn:aws:serverlessrepo:us-east-1:<PUBLISHER_ACCOUNT_ID>:applications/trailtool-ingestor"
  semantic_version = "1.2.0"
  capabilities = [
    "CAPABILITY_IAM",
    "CAPABILITY_NAMED_IAM",
    "CAPABILITY_AUTO_EXPAND",
    "CAPABILITY_RESOURCE_POLICY",
  ]
  parameters = {
    CloudTrailBucketName     = "my-cloudtrail-bucket"
    ManageBucketNotification = "false"
  }
}
```

Terraform prefixes the stack name, so the stack is called
`serverlessrepo-trailtool-ingestor`. `trailtool status` doesn't recognize that
name and reports a warning for its stack check, and `trailtool replay` needs
`--bucket`.

## Cross-account setup

Two accounts are involved:

- `BUCKET_ACCOUNT` owns the CloudTrail bucket, for example a Control Tower log
  archive account.
- `INGESTOR_ACCOUNT` runs TrailTool.

Each step is independent and can run in any order. Steps 1 and 2 are bucket
prerequisites that no published template performs.

### 1. Bucket owner: enable EventBridge notifications

In `BUCKET_ACCOUNT`, follow
[Enabling EventBridge notifications](#enabling-eventbridge-notifications).

### 2. Bucket owner: grant the ingestor role read access

Add this statement to the bucket policy. It grants the ingestor account's root
principal and narrows access to `trailtool-ingestor-role` with an
`aws:PrincipalArn` condition. S3 rejects a policy that names a role that doesn't
exist yet. The account form avoids that, so you can apply the policy before the
ingestor is deployed.

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
# Add the statement above to policy.json's "Statement" array, then:
aws s3api put-bucket-policy --bucket my-cloudtrail-bucket --policy file://policy.json
```

`put-bucket-policy` replaces the whole policy, and so does Terraform's
`aws_s3_bucket_policy`. Always merge the statement into the existing policy.

To run `trailtool replay`, the role you run it as also needs `s3:ListBucket` on
`arn:aws:s3:::my-cloudtrail-bucket`. Grant that in a second statement with the
same root principal, with `aws:PrincipalArn` set to that role.

If the bucket uses SSE-KMS, the ingestor role also needs `kms:Decrypt` on the
key, in both the key policy and the role. The published template doesn't grant
it. Control Tower's default SSE-S3 encryption needs nothing extra.

### 3. Ingestor account: deploy `trailtool-ingestor`

Set `ManageBucketNotification=false`, because this account can't change the
bucket. Set `EventSourceAccount` to `BUCKET_ACCOUNT`, which adds an event bus
policy that lets that account put events onto this account's default bus.

CloudFormation (`ingestor.yaml`), deployed in `INGESTOR_ACCOUNT`:

```yaml
Transform: AWS::Serverless-2016-10-31

Resources:
  TrailToolIngestor:
    Type: AWS::Serverless::Application
    Properties:
      Location:
        ApplicationId: arn:aws:serverlessrepo:us-east-1:<PUBLISHER_ACCOUNT_ID>:applications/trailtool-ingestor
        SemanticVersion: 1.2.0
      Parameters:
        CloudTrailBucketName: my-cloudtrail-bucket
        ManageBucketNotification: 'false'
        EventSourceAccount: 'BUCKET_ACCOUNT'

Outputs:
  CloudTrailBucketName:
    Value: !GetAtt TrailToolIngestor.Outputs.CloudTrailBucketName
```

```bash
aws cloudformation deploy --template-file ingestor.yaml --stack-name trailtool-ingestor \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
                 CAPABILITY_AUTO_EXPAND CAPABILITY_RESOURCE_POLICY \
  --profile ingestor
```

Terraform:

```hcl
resource "aws_serverlessapplicationrepository_cloudformation_stack" "trailtool_ingestor" {
  provider         = aws.ingestor
  name             = "trailtool-ingestor"
  application_id   = "arn:aws:serverlessrepo:us-east-1:<PUBLISHER_ACCOUNT_ID>:applications/trailtool-ingestor"
  semantic_version = "1.2.0"
  capabilities = [
    "CAPABILITY_IAM",
    "CAPABILITY_NAMED_IAM",
    "CAPABILITY_AUTO_EXPAND",
    "CAPABILITY_RESOURCE_POLICY",
  ]
  parameters = {
    CloudTrailBucketName     = "my-cloudtrail-bucket"
    ManageBucketNotification = "false"
    EventSourceAccount       = "BUCKET_ACCOUNT"
  }
}
```

### 4. Bucket owner account: deploy `trailtool-cloudtrail-forwarder`

Deploy it in the **bucket's region**. `IngestorRegion` defaults to that same
region. Set it if the ingestor runs elsewhere.

CloudFormation (`forwarder.yaml`), deployed in `BUCKET_ACCOUNT`:

```yaml
Transform: AWS::Serverless-2016-10-31

Resources:
  TrailToolForwarder:
    Type: AWS::Serverless::Application
    Properties:
      Location:
        ApplicationId: arn:aws:serverlessrepo:us-east-1:<PUBLISHER_ACCOUNT_ID>:applications/trailtool-cloudtrail-forwarder
        SemanticVersion: 1.2.0
      Parameters:
        CloudTrailBucketName: my-cloudtrail-bucket
        IngestorAccountId: 'INGESTOR_ACCOUNT'
```

```bash
aws cloudformation deploy --template-file forwarder.yaml --stack-name trailtool-cloudtrail-forwarder \
  --capabilities CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND \
  --profile log-archive
```

Terraform:

```hcl
resource "aws_serverlessapplicationrepository_cloudformation_stack" "trailtool_forwarder" {
  provider         = aws.log_archive
  name             = "trailtool-cloudtrail-forwarder"
  application_id   = "arn:aws:serverlessrepo:us-east-1:<PUBLISHER_ACCOUNT_ID>:applications/trailtool-cloudtrail-forwarder"
  semantic_version = "1.2.0"
  capabilities     = ["CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"]
  parameters = {
    CloudTrailBucketName = "my-cloudtrail-bucket"
    IngestorAccountId    = "INGESTOR_ACCOUNT"
  }
}
```

**Steps 3 and 4 can run in either order.** If the forwarder goes first, events
it forwards before the ingestor's event bus policy exists fail delivery. Run
`trailtool replay` afterwards to backfill them.

## Enabling EventBridge notifications

`put-bucket-notification-configuration` **replaces the bucket's entire
notification config**. Running it with only `{"EventBridgeConfiguration":{}}`
deletes every existing SNS, SQS and Lambda notification on the bucket. Fetch the
current config first and merge `EventBridgeConfiguration` into it:

```bash
aws s3api get-bucket-notification-configuration --bucket my-cloudtrail-bucket --output json > notification.json
# Add "EventBridgeConfiguration": {} at the top level, for example with jq.
# (Slurping copes with a bucket that has no config, where get prints nothing.)
jq -s '(.[0] // {}) + {EventBridgeConfiguration: {}}' notification.json > merged.json
aws s3api put-bucket-notification-configuration --bucket my-cloudtrail-bucket \
  --notification-configuration file://merged.json
```

**Terraform:** `aws_s3_bucket_notification` with `eventbridge = true` owns the
bucket's whole notification config. Declare every other notification for the
bucket in that same resource. If something else manages notifications on the
bucket (Control Tower, another stack), the resource removes them. Use one
`aws_s3_bucket_notification` per bucket, and don't use it at all if another tool
already manages the bucket's notifications.

## Capabilities

| Application | Required capabilities |
|-------------|-----------------------|
| `trailtool-ingestor` | `CAPABILITY_IAM`, `CAPABILITY_NAMED_IAM`, `CAPABILITY_AUTO_EXPAND`, `CAPABILITY_RESOURCE_POLICY` |
| `trailtool-cloudtrail-forwarder` | `CAPABILITY_NAMED_IAM`, `CAPABILITY_AUTO_EXPAND` |

Both create IAM roles with fixed names. The ingestor also creates an event bus
policy. A parent stack that nests either app with `AWS::Serverless::Application`
needs the same capabilities.

## Verify it works

1. CloudTrail delivers a log file roughly every five minutes. Within about five
   minutes of deploying, the ingestor's Lambda logs should show a new file being
   processed. Run this in the ingestor account:

   ```bash
   aws logs tail /aws/lambda/trailtool-ingestor --since 15m --follow
   ```

2. `trailtool status` should then pass, and `trailtool people list` should show
   who made the newly logged API calls. `status` only checks that the tables
   are reachable, so it passes on empty tables too.

If nothing arrives in a cross-account setup, check the forwarder rule's
`FailedInvocations` metric in `BUCKET_ACCOUNT`. Failures mean step 3 isn't done
yet, or `IngestorAccountId` or `IngestorRegion` is wrong. No invocations at all
means EventBridge notifications are off on the bucket. Once it works, run
`trailtool replay` to backfill earlier logs.

## Stack reference

### `trailtool-ingestor`

- **Lambda function** `trailtool-ingestor` (`provided.al2023`), triggered by
  EventBridge on `Object Created` under `AWSLogs/` with a `.json.gz` suffix.
- **DynamoDB tables** `trailtool-people`, `trailtool-sessions`, `trailtool-roles`,
  `trailtool-services`, `trailtool-resources`, `trailtool-accounts`,
  `trailtool-relations`, `trailtool-identity-links`, `trailtool-ingested-files`.
  All are `PAY_PER_REQUEST`. The CLI looks the tables up by these fixed names,
  so you can run only one stack per account and region.
- **IAM role** `trailtool-ingestor-role`, with `s3:GetObject` on the bucket.
- **EventBridge rule** `trailtool-cloudtrail-trigger` plus the Lambda invoke
  permission.
- **Event bus policy**, only when `EventSourceAccount` is set.
- **Custom resource** that turns on EventBridge notifications on the bucket, only
  when `ManageBucketNotification` is `true`.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `CloudTrailBucketName` | *(required)* | S3 bucket holding the CloudTrail logs. |
| `ManageBucketNotification` | `true` | Same-account convenience: the stack turns on EventBridge notifications for the bucket. Set to `false` when the bucket owner handles it, and always for cross account. |
| `EventSourceAccount` | `''` | Bucket owner's account ID, allowed to forward S3 events onto this account's default event bus. Set it for cross account. |

The outputs are `FunctionName`, `FunctionArn`, `CloudTrailBucketName`,
`SessionsTableName` and `RolesTableName`. A parent stack reads them as
`!GetAtt TrailToolIngestor.Outputs.<Name>`.

Deploying over a pre-1.0 stack **deletes** the old `*-aggregated` tables and
their data. There is no migration. Run `trailtool replay` to rebuild history from
CloudTrail.

### `trailtool-cloudtrail-forwarder`

- **EventBridge rule** `trailtool-cloudtrail-forwarding-to-ingestor`. It matches
  `Object Created` for `*/CloudTrail/*.json.gz` keys in the bucket, so digest and
  Insights files are not forwarded. Its target is the ingestor account's default
  bus.
- **IAM role** `trailtool-cloudtrail-forwarder-role`, which EventBridge assumes
  to call `events:PutEvents` on that bus.
- If `IngestorAccountId` is empty or names the stack's own account, the stack
  creates neither of these. It holds only an inert
  `AWS::CloudFormation::WaitConditionHandle`, and its `Forwarding` output is
  `false`.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `CloudTrailBucketName` | *(required)* | The CloudTrail bucket, owned by this account. |
| `IngestorAccountId` | `''` | Account running the ingestor. If you leave it empty or set it to this account, nothing is forwarded. |
| `IngestorRegion` | `''` | Region of the ingestor's event bus. Empty means this stack's region. |

## Deploy from source

```bash
make build
sam deploy --parameter-overrides CloudTrailBucketName=my-cloudtrail-bucket
```

For an organization trail, `make deploy-org-all` deploys the ingestor and then
the forwarder. It takes two AWS profiles. It doesn't change the bucket policy,
and the forwarder step fails if notifications are off.

```bash
make deploy-org-all INGESTOR_PROFILE=audit BUCKET_PROFILE=log-archive \
  TRAIL_BUCKET=my-cloudtrail-bucket BUCKET_ACCOUNT=111111111111
```

`template-sandbox.yaml` deploys the ingestor together with a new trail and
bucket. It isn't published to SAR.
