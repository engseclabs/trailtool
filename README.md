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

## Deploy

The ingestor is published to the AWS Serverless Application Repository (SAR), so
you don't need to clone this repo. Two applications are published, always at the
same version:

- **`trailtool-ingestor`** runs where you want the TrailTool data.
- **`trailtool-cloudtrail-forwarder`** is only for the cross-account setup.

S3 publishes EventBridge notifications only to the bucket owner's account, so
which setup you need depends on where the CloudTrail bucket lives:

- **Same account:** the bucket and the ingestor are in one account. Nothing is
  forwarded.
- **Cross account:** for example, an organization trail bucket in a log archive
  account. The bucket owner's account forwards the events to the ingestor
  account.

No published template touches the bucket itself. The bucket owner turns on
notifications and grants read access, because the bucket is often managed
elsewhere (Control Tower, Terraform). Within each setup, the steps are
independent and can run in any order. [`ingestor/README.md`](ingestor/README.md)
has the full reference: parameters, outputs, troubleshooting and the Terraform
version of every step.

### Same account

Deploy in the bucket's region.

1. **Bucket: enable EventBridge notifications.** This is a prerequisite, done by
   whoever manages the bucket. See
   [Enabling EventBridge notifications](#enabling-eventbridge-notifications).
   Alternatively, deploy the ingestor with `ManageBucketNotification=true` and
   let it do this.

2. **Ingestor: deploy `trailtool-ingestor`** with `CloudTrailBucketName`.

   ```yaml
   # ingestor.yaml
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
           ManageBucketNotification: 'false' # step 1 handles it
   Outputs:
     CloudTrailBucketName: # lets `trailtool replay` find the bucket
       Value: !GetAtt TrailToolIngestor.Outputs.CloudTrailBucketName
   ```

   ```bash
   aws cloudformation deploy --template-file ingestor.yaml --stack-name trailtool-ingestor \
     --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
                    CAPABILITY_AUTO_EXPAND CAPABILITY_RESOURCE_POLICY
   ```

   Or with Terraform:

   ```hcl
   resource "aws_serverlessapplicationrepository_cloudformation_stack" "trailtool_ingestor" {
     name             = "trailtool-ingestor"
     application_id   = "arn:aws:serverlessrepo:us-east-1:<PUBLISHER_ACCOUNT_ID>:applications/trailtool-ingestor"
     semantic_version = "1.2.0"
     capabilities     = ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND", "CAPABILITY_RESOURCE_POLICY"]
     parameters = {
       CloudTrailBucketName     = "my-cloudtrail-bucket"
       ManageBucketNotification = "false"
     }
   }
   ```

### Cross account

`BUCKET_ACCOUNT` owns the bucket, and `INGESTOR_ACCOUNT` runs TrailTool.

1. **Bucket owner: enable EventBridge notifications.** This is a prerequisite
   that no published template does. See
   [Enabling EventBridge notifications](#enabling-eventbridge-notifications).

2. **Bucket owner: grant the ingestor role `s3:GetObject` in the bucket policy.**
   This is also a prerequisite. Grant the ingestor account's root principal and
   narrow access to `trailtool-ingestor-role` with an `aws:PrincipalArn`
   condition. S3 rejects a policy that names a role that doesn't exist yet, and
   the account form avoids that.

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
   # put-bucket-policy replaces the whole policy, so add the statement to policy.json first.
   aws s3api put-bucket-policy --bucket my-cloudtrail-bucket --policy file://policy.json
   ```

3. **Ingestor account: deploy `trailtool-ingestor`** with
   `ManageBucketNotification=false` and `EventSourceAccount=BUCKET_ACCOUNT`.

   ```yaml
   # ingestor.yaml — same as the same-account template, with these parameters
         Parameters:
           CloudTrailBucketName: my-cloudtrail-bucket
           ManageBucketNotification: 'false'
           EventSourceAccount: 'BUCKET_ACCOUNT'
   ```

   ```bash
   aws cloudformation deploy --template-file ingestor.yaml --stack-name trailtool-ingestor \
     --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
                    CAPABILITY_AUTO_EXPAND CAPABILITY_RESOURCE_POLICY \
     --profile ingestor
   ```

   In Terraform, add `EventSourceAccount = "BUCKET_ACCOUNT"` to the same-account
   resource's `parameters`.

4. **Bucket owner account: deploy `trailtool-cloudtrail-forwarder`** with
   `CloudTrailBucketName` and `IngestorAccountId`, in the bucket's region.

   ```yaml
   # forwarder.yaml
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

   Or with Terraform:

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

Steps 3 and 4 can run in either order. If the forwarder goes first, events it
forwards before the ingestor's event bus policy exists fail delivery. Run
`trailtool replay` afterwards to backfill them.

### Enabling EventBridge notifications

> [!WARNING]
> `aws s3api put-bucket-notification-configuration` **replaces the bucket's
> entire notification config**. Fetch the current config with
> `get-bucket-notification-configuration` and merge `EventBridgeConfiguration`
> into it. Don't send `{"EventBridgeConfiguration":{}}` on its own.

```bash
aws s3api get-bucket-notification-configuration --bucket my-cloudtrail-bucket --output json > notification.json
jq -s '(.[0] // {}) + {EventBridgeConfiguration: {}}' notification.json > merged.json
aws s3api put-bucket-notification-configuration --bucket my-cloudtrail-bucket \
  --notification-configuration file://merged.json
```

In Terraform, `aws_s3_bucket_notification` with `eventbridge = true` owns the
bucket's **whole** notification config. Declare every other notification for
the bucket in that same resource. Don't use it if another tool already manages
the bucket's notifications.

### Capabilities

| Application | Capabilities |
|-------------|--------------|
| `trailtool-ingestor` | `CAPABILITY_IAM`, `CAPABILITY_NAMED_IAM`, `CAPABILITY_AUTO_EXPAND`, `CAPABILITY_RESOURCE_POLICY` |
| `trailtool-cloudtrail-forwarder` | `CAPABILITY_NAMED_IAM`, `CAPABILITY_AUTO_EXPAND` |

### Verify it works

CloudTrail delivers a log file roughly every five minutes. Within about five
minutes, the ingestor's Lambda logs should show a new file. Run this in the
ingestor account:

```bash
aws logs tail /aws/lambda/trailtool-ingestor --since 15m --follow
```

Then `trailtool status` should pass, and `trailtool people list` should show
data. Run `trailtool replay` to backfill older logs.

### Deploy from source

*Requires the [AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html).*

```bash
cd ingestor
sam deploy --template-file template-sandbox.yaml                         # new trail + bucket + ingestor
sam deploy --parameter-overrides CloudTrailBucketName=my-cloudtrail-bucket # existing bucket, same account
make deploy-org-all INGESTOR_PROFILE=audit BUCKET_PROFILE=log-archive \
  TRAIL_BUCKET=my-cloudtrail-bucket BUCKET_ACCOUNT=111111111111            # cross account

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
