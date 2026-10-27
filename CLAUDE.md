# TrailTool

Go CLI for querying precomputed CloudTrail data. Entrypoint: `cmd/trailtool/main.go`.

## Build & Test

```bash
go build ./cmd/trailtool/          # build
go test ./...                      # test
AWS_PROFILE=sandbox-admin AWS_REGION=us-east-1 go run ./cmd/trailtool/ status  # smoke test
```

## Releasing

Releases are automated via goreleaser + GitHub Actions. Pushing a semver tag triggers the workflow.

```bash
git tag v0.X.0
git push origin v0.X.0
```

This will:
1. Build linux/darwin binaries (amd64 + arm64)
2. Create a GitHub release with archives
3. Update the Homebrew tap (`engseclabs/homebrew-tap`)
4. Publish the ingestor and forwarder to the Serverless Application Repository (see below)

Users install/upgrade via `brew install engseclabs/tap/trailtool`.

Config: `.goreleaser.yaml`, `.github/workflows/release.yaml`.

### Serverless Application Repository

The same tag publishes two apps to the AWS Serverless Application Repository, so
consumers can nest them with `AWS::Serverless::Application` instead of copying
templates:

- `ingestor/template.yaml` as `trailtool-ingestor`
- `ingestor/template-forwarder.yaml` as `trailtool-cloudtrail-forwarder` (the
  cross-account hop; a no-op when `IngestorAccountId` is empty or the stack's own
  account)

Each SAR listing lives in its template's `Metadata: AWS::ServerlessRepo::Application`
block. Both get the tag's version with the `v` stripped (`v1.2.0` → `1.2.0`), so
their versions always match; SAR versions are immutable. The job also sets each
application policy to `Principals='*'`, which is what makes it publicly listed.
Every resource type in a published template must be on SAR's supported-resources
list.

The `serverless-app-repo` job is skipped unless these repository variables are
set (Settings → Secrets and variables → Actions → Variables), so tags keep
working in forks and before SAR is configured:

| Variable | Purpose |
|----------|---------|
| `SAR_S3_BUCKET` | Bucket holding the packaged artifacts. Its policy must let `serverlessrepo.amazonaws.com` read it — `make -C ingestor sar-bucket-policy SAR_BUCKET=…` prints the statement. |
| `SAR_PUBLISH_ROLE_ARN` | Role assumed through GitHub OIDC. Needs `s3:PutObject` on that bucket plus `serverlessrepo:CreateApplication`, `serverlessrepo:CreateApplicationVersion`, `serverlessrepo:UpdateApplication` and `serverlessrepo:PutApplicationPolicy`. |
| `SAR_REGION` | Optional; defaults to `us-east-1`. |

To publish by hand (what the workflow does, step for step):

```bash
make -C ingestor publish-sar VERSION=1.2.0 SAR_BUCKET=your-bucket
```

After the first publish, replace `<PUBLISHER_ACCOUNT_ID>` in `README.md` and
`ingestor/README.md` (and bump the `SemanticVersion` examples there) with the publishing account ID so the `ApplicationId` in
the docs is copy-pasteable.

## Project Structure

- `cmd/trailtool/` — CLI entrypoint and commands
- `docs/agent-instructions.md` — agent-facing instructions (copied into consumer repos as CLAUDE.md)

#### Credential groups

A credential group is the set of events sharing one credential boundary, keyed on whatever stable field AWS provides (checked in this order).

| Key | Events it groups |
|-----|------------------|
| `sig#<signInSessionArn>` | everything made under one sign-in session (survives credential rotation) |
| `rc#<principalId>#<creationDate>` | per-request-credential sessions — console and forward-access (`invokedBy`) — which mint a fresh key per request |
| `ak#<accessKeyId>` | ordinary CLI/SDK access-key traffic |
| `ev#<eventID>` | anything else — the event resolves alone |

#### Session anchors

The anchor is the session's stable identity (i.e. `USER`).

| Anchor | Session boundary |
|--------|------------------|
| `sis#<signInSessionArn>` | a literal AWS sign-in session (MCP agents, `aws login`, and AWS's ongoing rollout to ordinary sessions) |
| `web#<roleID>#<creationDate>` | one console sign-in, stable across its per-request access keys |
| `key#<accessKeyId>` | one temporary credential = one session (CLI/SDK, chained roles, SAML); a refresh is deliberately a new session |
| *(none)* | windowed fallback - the only time-based path |
