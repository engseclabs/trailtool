# TrailTool CloudTrail Forwarder

The forwarder is the cross-account half of the
[TrailTool](https://github.com/engseclabs/trailtool) ingestor setup. Deploy it in
the account that **owns the CloudTrail bucket** (for example, a Control Tower log
archive account) when `trailtool-ingestor` runs in a different account.

S3 publishes its EventBridge notifications only to the default event bus of the
bucket owner's account. An ingestor in another account never sees them. This
stack adds an EventBridge rule that forwards the bucket's `Object Created` events
for `*/CloudTrail/*.json.gz` keys to the ingestor account's default bus.

## What the stack creates

- **When forwarding** (`IngestorAccountId` is set and differs from this account):
  - an EventBridge rule named `trailtool-cloudtrail-forwarding-to-ingestor`
  - an IAM role named `trailtool-cloudtrail-forwarder-role`, which lets
    EventBridge call `events:PutEvents` on the ingestor's bus
- **Always**: an inert `AWS::CloudFormation::WaitConditionHandle`. CloudFormation
  rejects a stack with no resources, so the stack keeps this one when it has
  nothing to forward. If `IngestorAccountId` is empty or names this account, the
  stack does nothing.

The stack never touches the bucket. You need to set up both of these yourself as
the bucket owner:

1. Turn on EventBridge notifications on the bucket.
2. In the bucket policy, grant the ingestor role (`trailtool-ingestor-role`)
   `s3:GetObject`.

## Parameters

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `CloudTrailBucketName` | *(required)* | The CloudTrail bucket, owned by this account. |
| `IngestorAccountId` | `''` | Account running `trailtool-ingestor`. If you leave it empty or set it to this account, nothing is forwarded. |
| `IngestorRegion` | `''` | Region of the ingestor's event bus. Empty means this stack's region. |

Deploy the stack in the **bucket's region**, because S3 emits its events there.
The ingestor can run in any region.

**Capabilities:** `CAPABILITY_NAMED_IAM` and `CAPABILITY_AUTO_EXPAND`.

Full setup instructions:
<https://github.com/engseclabs/trailtool/blob/main/ingestor/README.md>
