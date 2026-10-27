# SAR publishing infrastructure

Terraform for the AWS side of the Serverless Application Repository publishing
pipeline. The `serverless-app-repo` job in
[`.github/workflows/release.yaml`](../../.github/workflows/release.yaml) runs on
every `v*` tag and uses what this stack creates:

- an S3 staging bucket SAR reads packaged artifacts from, and
- an IAM role the workflow assumes over GitHub OIDC.

The SAR application itself is not created here. `sam publish` creates it on the
first tag; there is no usable Terraform resource for a SAR application version.

## Apply

```bash
cd infra/sar-publish
terraform init
terraform apply
```

If `token.actions.githubusercontent.com` already exists in the account (an
account allows only one OIDC provider per URL), reuse it:

```bash
terraform apply -var='create_oidc_provider=false'
```

## Wire up GitHub

Copy the outputs into the repo's Actions variables (Settings → Secrets and
variables → Actions → Variables):

| Output                 | GitHub repo variable   |
| ---------------------- | ---------------------- |
| `sar_s3_bucket`        | `SAR_S3_BUCKET`        |
| `sar_publish_role_arn` | `SAR_PUBLISH_ROLE_ARN` |
| `sar_region`           | `SAR_REGION` (optional; workflow defaults to `us-east-1`) |

Once set, the next `v*` tag publishes the ingestor as a **publicly listed** SAR
application.

## State

State is local and untracked (see `.gitignore`). Apply from one place, or move
the backend to the team's shared state before sharing.
