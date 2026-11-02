# TrailTool OTLP Forwarder

Sends [TrailTool](https://github.com/engseclabs/trailtool) change events to any
OTLP/HTTP logs endpoint, one OpenTelemetry log record per event. It subscribes
to the EventBridge bus that `trailtool-ingestor` publishes to
(`ActivityEventBusArn`), so deploy it in that bus's account and region. The
ingestor is unaware of it: an unreachable endpoint never affects ingestion.

## Setup

1. **Headers secret.** Create a Secrets Manager secret whose value is a JSON
   object of header name to value. The forwarder sends these headers with every
   request. Use a file so the credential stays out of shell history:

   ```json
   {"Authorization": "Bearer <token>", "X-Tenant": "<tenant id>"}
   ```

   ```bash
   aws secretsmanager create-secret --name trailtool/otlp-headers --secret-string file://headers.json
   ```

2. **Forwarder.** Deploy `trailtool-otlp-forwarder` with the bus, the full logs
   URL, and the secret's full ARN.

   ```yaml
   # otlp-forwarder.yaml
   Transform: AWS::Serverless-2016-10-31
   Resources:
     TrailToolOtlpForwarder:
       Type: AWS::Serverless::Application
       Properties:
         Location:
           ApplicationId: arn:aws:serverlessrepo:us-east-1:843363563907:applications/trailtool-otlp-forwarder
           SemanticVersion: 1.4.0
         Parameters:
           EventBusName: trailtool-activity
           OtlpLogsEndpoint: https://otlp.example.com/v1/logs
           OtlpHeadersSecretArn: arn:aws:secretsmanager:us-east-1:111111111111:secret:trailtool/otlp-headers-AbCdEf
   ```

   ```bash
   aws cloudformation deploy --template-file otlp-forwarder.yaml --stack-name trailtool-otlp-forwarder \
     --capabilities CAPABILITY_IAM CAPABILITY_RESOURCE_POLICY CAPABILITY_AUTO_EXPAND
   ```

   ```hcl
   resource "aws_serverlessapplicationrepository_cloudformation_stack" "trailtool_otlp_forwarder" {
     name             = "trailtool-otlp-forwarder"
     application_id   = "arn:aws:serverlessrepo:us-east-1:843363563907:applications/trailtool-otlp-forwarder"
     semantic_version = "1.4.0"
     capabilities     = ["CAPABILITY_IAM", "CAPABILITY_RESOURCE_POLICY", "CAPABILITY_AUTO_EXPAND"]
     parameters = {
       EventBusName         = "trailtool-activity"
       OtlpLogsEndpoint     = "https://otlp.example.com/v1/logs"
       OtlpHeadersSecretArn = aws_secretsmanager_secret.otlp_headers.arn
     }
   }
   ```

`OtlpLogsEndpoint` is the full logs path. Most receivers serve it at
`<base URL>/v1/logs`; some put it under a prefix such as `/otel/v1/logs`, and a
receiver with regional or dedicated endpoints needs the URL for your instance.
Check the receiver's OTLP documentation.

## Parameters

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `EventBusName` | *(required)* | Name or ARN of the bus receiving TrailTool change events. |
| `OtlpLogsEndpoint` | *(required)* | Full OTLP/HTTP logs URL. Must not contain credentials. |
| `OtlpHeadersSecretArn` | *(required)* | Full ARN of the headers secret. |
| `SecretKmsKeyArn` | `''` | Customer managed KMS key encrypting the secret. Empty for the AWS managed key. |
| `ServiceName` | `trailtool` | `service.name` resource attribute. |
| `DetailTypes` | all three | Comma-separated `detail-type`s to forward: `TrailTool Noun Created`, `TrailTool Relation Created`, `TrailTool Session Activity`. |
| `LogRetentionDays` | `30` | Retention of the function's log group. |

Capabilities: `CAPABILITY_IAM`, `CAPABILITY_RESOURCE_POLICY`, `CAPABILITY_AUTO_EXPAND`.

## Failures

Any non-2xx response, or a response reporting rejected records, fails the
invocation. Lambda retries it twice, then sends the event and the error to the
stack's dead-letter queue (output `DeadLetterQueueUrl`). Events EventBridge
cannot deliver to the function at all land in the same queue after an hour of
retries. A 400, 401, or 403 re-reads the secret once first and retries if it
changed, so rotating or correcting the credential needs no redeploy.

Delivery is at least once. Deduplicate on the `trailtool.event_id` attribute if
duplicates matter.

The function logs one `OTLP_OK` or `OTLP_FAILED` line per event, with the event
id, detail-type, HTTP status, and rejected count. Failures add up to 256 bytes
of the receiver's error message, which can quote rejected record fields. It
never logs header values or the request body.

Field mapping and design: <https://github.com/engseclabs/trailtool/blob/main/docs/design/otlp-forwarder.md>
