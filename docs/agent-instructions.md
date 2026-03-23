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
trailtool sessions list                        # List all sessions
trailtool sessions list --user <email> --days 7  # Filter by user and recency
trailtool sessions detail --start-time <ISO8601> # Full session detail: events, resources, denied calls
trailtool sessions summarize --start-time <ISO8601>  # AI-generated session summary (requires Bedrock)
```

### Accounts
```bash
trailtool accounts list                        # List all tracked AWS accounts
trailtool accounts detail <account-id>         # Account detail: people, roles, services, resources
```

### Roles
```bash
trailtool roles list                           # List all tracked IAM roles
trailtool roles detail <role-name-or-arn>      # Role detail: services used, top events, denied events
trailtool roles policy <role-name-or-arn>      # Generate least-privilege IAM policy from actual usage
trailtool roles policy <role> --include-denied --explain  # Include denied events, show explanation
```

### Services
```bash
trailtool services list                        # List all tracked AWS services
trailtool services detail <event-source>       # e.g. s3.amazonaws.com — top events, roles, resources
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

**Steps:**
1. `trailtool roles list --format json` — identify roles to tighten
2. `trailtool roles policy <RoleName> --format json` — generate least-privilege policy from actual usage
3. Compare the generated policy with the current Terraform `aws_iam_role_policy` or `aws_iam_policy` resource
4. Propose a PR that narrows permissions to actual usage

**Options:**
- Use `--include-denied` to include permissions for actions that were attempted but denied (useful if the current policy is already too tight)
- Use `--explain` to get a summary of action counts and any unmapped CloudTrail events

**Context:** This is best run as a recurring workflow. Permissions are dynamic — what's unused today may be needed next quarter. Generate, review, deploy, repeat. The generated policy uses IAM action mappings from CloudTrail event names, but some events may not map cleanly; the `--explain` flag surfaces these.

### 3. Respond to AccessDenied errors

When a tightened IAM policy blocks legitimate access, use the denied event data to draft a targeted policy fix.

**Steps:**
1. `trailtool roles detail <RoleName> --format json` — check if the role has denied events
2. `trailtool roles policy <RoleName> --include-denied --explain --format json` — generate a policy that includes the denied actions
3. Diff against the current Terraform IAM policy to identify what's missing
4. Propose a minimal policy addition that grants only the denied actions, scoped to the appropriate resources

**Context:** This closes the feedback loop on least-privilege. Rather than the user filing a ticket saying "I can't do X," the agent can detect the denial, draft the fix, and open a PR. A human should still review permission changes before merge.

### 4. Validate break-glass session justifications

When someone uses emergency/break-glass access, compare what they said they would do (the justification) with what they actually did (the session).

**Steps:**
1. `trailtool sessions list --user <email> --days 1 --format json` — find the relevant session
2. `trailtool sessions detail --start-time <start-time> --format json` — get the full session: events, resources accessed, services used, denied actions
3. Compare the session activity against the stated justification
4. Flag discrepancies: actions that don't align with the justification, unexpected services accessed, or resources modified that weren't mentioned

**Context:** Break-glass justifications are often brief and vague. Session-level analysis lets you verify after the fact whether the actual activity matched the stated intent. Discrepancies don't necessarily mean misuse — but they should be reviewed. This is especially valuable for compliance and audit trails.
