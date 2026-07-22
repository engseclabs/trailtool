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

Users install/upgrade via `brew install engseclabs/tap/trailtool`.

Config: `.goreleaser.yaml`, `.github/workflows/release.yaml`.

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
