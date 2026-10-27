# TrailTool CloudTrail Forwarder

Deploy in the account that **owns the CloudTrail bucket** (for example a Control
Tower log archive account) when [`trailtool-ingestor`](https://github.com/engseclabs/trailtool)
runs in a different account.

S3 publishes EventBridge notifications only to the bucket owner's account. This
stack forwards the bucket's `*/CloudTrail/*.json.gz` deliveries to the ingestor
account's default bus. When `IngestorAccountId` is empty or this account, it
creates only an inert placeholder.

Deploy in the bucket's region. The stack doesn't touch the bucket: enable
EventBridge notifications on it and grant `trailtool-ingestor-role`
`s3:GetObject` yourself.

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `CloudTrailBucketName` | *(required)* | The CloudTrail bucket, owned by this account. |
| `IngestorAccountId` | `''` | Account running the ingestor. Empty or this account forwards nothing. |
| `IngestorRegion` | `''` | Region of the ingestor's event bus. Empty means this stack's region. |

Capabilities: `CAPABILITY_NAMED_IAM`, `CAPABILITY_AUTO_EXPAND`.

Setup guide: <https://github.com/engseclabs/trailtool/blob/main/ingestor/README.md>
