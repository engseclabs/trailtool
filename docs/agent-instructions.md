# TrailTool Agent Instructions

Copy this file into your project as `CLAUDE.md` (or the equivalent for your coding agent) to enable TrailTool-powered workflows.

---

## What is TrailTool?

TrailTool precomputes and caches CloudTrail data into queryable entities (People, Sessions, Roles, Services, Resources) so you can answer common AWS security and operations questions quickly. It ships as a CLI (`trailtool`) that works with standard AWS credentials.

## Prerequisites

Before using trailtool, verify the environment is ready:

1. **CLI installed**: Run `which trailtool`. If not found: `brew install engseclabs/tap/trailtool`.
2. **Status check**: Run `trailtool status`. This verifies AWS credentials, that the ingestor CloudFormation stack is deployed, and that TrailTool data is accessible. If any check fails, follow the printed guidance before erroring out:
   - **AWS credentials not configured**: Ensure the correct profile is set (e.g. `export AWS_PROFILE=<profile>`).
   - **Ingestor stack not found**: The wrong region is configured. Set `AWS_REGION` to the region where the ingestor was deployed (e.g. `export AWS_REGION=us-east-1`) and re-run `trailtool status`.

## CLI Reference

All commands support `--format json` for structured output. Use JSON when you need to parse or process results programmatically.

### People
```bash
trailtool people list                          # List all tracked identities
```

### Sessions
```bash
trailtool sessions list                        # List all sessions (# column shows index)
trailtool sessions list --user <email> --days 7  # Filter by user and recency
trailtool sessions list --role <name> --user <email>  # Filter by role name (substring match)
trailtool sessions list --account <id>         # Filter by AWS account ID
trailtool sessions list --after 2026-01-01T00:00:00Z --before 2026-01-02T00:00:00Z  # Time range
trailtool sessions list --long                 # Show full role names (SSO roles shortened by default)
trailtool sessions detail --session k7m2qp                # Session detail by id (SID column, prefix ok)
trailtool sessions detail --session latest                # Most recent session
trailtool sessions detail --session latest --user alice@example.com  # Most recent for one user
trailtool sessions summarize --session k7m2qp             # AI-generated session summary (requires Bedrock)
trailtool sessions summarize --session latest --user alice@example.com
trailtool sessions policy --session k7m2qp                # Least-privilege policy for this session only
trailtool sessions policy --session latest --user alice@example.com --include-denied --explain
```

**Filtering tips:** Combine flags to narrow results. `--role` does substring matching (e.g. `--role BreakGlass` matches `AWSReservedSSO_BreakGlassEmergency_...`). `--after`/`--before` take ISO8601 timestamps and override `--days` if both are set.

**Session detail tips:** `--session` takes the id shown in the SID column of `sessions list`. It's a stable, deterministic handle for one specific session — a short prefix (the 6 chars shown) is enough, and the CLI asks you to lengthen it in the rare case a prefix is ambiguous. Use `--session latest` to jump to the most recent session (add `--user` to scope "latest" to one person). The detail view shows role chaining: if a session assumed another role, it prints the parent session with a ready-to-run `--session` command, and vice versa for child sessions.

**SSO role names:** The ROLE column in `sessions list` displays the short permission-set name (e.g. `AdministratorAccess`) rather than the full SSO path. Use `--long` to show the full role name. The full path and ARN are always shown in `sessions detail`.

**Session types in the CHAINED column:**
- `→ N role(s)` — this human session assumed N roles via `AssumeRole`
- `↑ child` — this session was created via `AssumeRole` and is attributed to a parent human session
- `← login` — this session's credentials were vended via `aws login` (PKCE OAuth2) by a human in another session

**`aws login` attribution:** When a developer runs `aws login` to grant credentials to an AI agent (Claude Code, VS Code, etc.), the agent session is tagged as `LOGIN` type and the `CHAINED` column shows `← login`. The detail view shows who authorized the credential grant and when, with a command to inspect the authorizing session.

### Accounts
```bash
trailtool accounts list                        # List all tracked AWS accounts (# column shows index)
trailtool accounts detail <account-id>         # Account detail: people, roles, services, resources
trailtool accounts detail --index <n>          # Same, by list position
```

### Roles
```bash
trailtool roles list                           # List all tracked IAM roles (# column shows index)
trailtool roles detail <role-name-or-arn>      # Role detail: services used, top events, denied events
trailtool roles detail --index <n>             # Same, by list position
trailtool roles policy <role-name-or-arn>      # Generate least-privilege IAM policy from actual usage
trailtool roles policy <role> --include-denied --explain  # Include denied events, show explanation
```

### Services
```bash
trailtool services list                        # List all tracked AWS services (# column shows index)
trailtool services detail <event-source>       # e.g. s3.amazonaws.com — top events, roles, resources
trailtool services detail --index <n>          # Same, by list position
```

### Resources
```bash
trailtool resources list --days 30             # Resources seen in last 30 days
trailtool resources list --clickops            # Resources created/modified via AWS console
trailtool resources list --clickops --service iam  # ClickOps filtered by service
trailtool resources list --service s3 --days 7     # Filter by service and recency
```

## Workflows

### 1. Detect ClickOps and import to Terraform

Resources created or modified through the AWS console ("ClickOps") bypass change control and IaC standards. Use this workflow to find them, import them into Terraform state, and generate the corresponding HCL.

**Steps:**
1. `trailtool resources list --clickops --days 30 --format json` — get all console-created resources
2. Optionally filter by service: `--service iam`, `--service s3`, etc.
3. For each resource, determine the Terraform resource type and generate:
   - A `terraform import` command to import existing state
   - An HCL resource block matching the current configuration
4. Present results grouped by service, noting who created each resource and when

**Context:** ClickOps resources may represent legitimate prototyping that needs to be formalized, or unauthorized drift. The output includes who performed the console action and when, which helps the user decide whether to import, recreate, or delete.

### 2. Generate least-privilege IAM policies

Tighten IAM roles by generating policies based on actual usage observed in CloudTrail, rather than guessing what permissions to remove.

**Role-scoped (lifetime of the role):**
1. `trailtool roles list --format json` — identify roles to tighten
2. `trailtool roles policy <RoleName> --format json` — generate least-privilege policy from all observed usage
3. Compare the generated policy with the current Terraform `aws_iam_role_policy` or `aws_iam_policy` resource
4. Propose a PR that narrows permissions to actual usage

**Session-scoped (a specific recording window):**
1. Run the workflow you want to capture (deploy, migration, agent run, etc.)
2. `trailtool sessions list --user <email> --days 1` — find the session
3. `trailtool sessions policy --session <sid> --format json` — generate a policy covering only that session's API calls (the SID is the id column from step 2)
4. Use this as the tightest possible baseline for the specific task

**Options (both variants):**
- `--include-denied` — include permissions for actions that were attempted but denied
- `--explain` — print a summary of action counts and unmapped CloudTrail events to stderr

**When to use each:** Role-scoped gives a policy that covers everything the role has ever done and is best for long-lived roles. Session-scoped is tighter and is best when you want to scope a policy to a specific workflow (a deploy pipeline, a one-off migration, an agent task).

**Context:** The generated policy uses IAM action mappings from CloudTrail event names; some events may not map cleanly. The `--explain` flag surfaces unmapped events so you can handle them manually.

### 3. Respond to AccessDenied errors

When a tightened IAM policy blocks legitimate access, use the denied event data to draft a targeted policy fix.

**Steps:**
1. `trailtool roles detail <RoleName> --format json` — check if the role has denied events
2. `trailtool roles policy <RoleName> --include-denied --explain --format json` — generate a policy that includes the denied actions
3. Diff against the current Terraform IAM policy to identify what's missing
4. Propose a minimal policy addition that grants only the denied actions, scoped to the appropriate resources

**Context:** This closes the feedback loop on least-privilege. Rather than the user filing a ticket saying "I can't do X," the agent can detect the denial, draft the fix, and open a PR. A human should still review permission changes before merge.

### 4. Inspect your own `aws login` session

If you are an AI agent with credentials vended via `aws login`, you can look up your own session and the human session that authorized it.

**Steps:**
1. `trailtool sessions list --days 1 --format json` — find sessions with `"session_type": "login"` or `"chained": "← login"` in the output
2. `trailtool sessions detail --session <sid> --format json` — get your session detail; look for the `login_granted_by_session` attribution
3. Use the printed drilldown command to inspect the authorizing human session:
   `trailtool sessions detail --session <sid>`

**Context:** This is useful for self-audit — understanding what credentials you are using, who authorized them, and what the authorizing session has done. It also lets you show a human reviewer the audit trail for a sensitive operation.

### 5. Validate break-glass session justifications

When someone uses emergency/break-glass access, compare what they said they would do (the justification) with what they actually did (the session).

**Steps:**
1. `trailtool sessions list --user <email> --role <break-glass-role> --after <time> --before <time> --format json` — find the specific break-glass session using role name, user, and time range
2. `trailtool sessions detail --session <sid> --format json` — get the full session: events, resources accessed, services used, denied actions (the SID is the id column from step 1's list)
3. Compare the session activity against the stated justification
4. Flag discrepancies: actions that don't align with the justification, unexpected services accessed, or resources modified that weren't mentioned

**Context:** Break-glass justifications are often brief and vague. Session-level analysis lets you verify after the fact whether the actual activity matched the stated intent. Discrepancies don't necessarily mean misuse — but they should be reviewed. This is especially valuable for compliance and audit trails.
