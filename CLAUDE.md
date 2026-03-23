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
