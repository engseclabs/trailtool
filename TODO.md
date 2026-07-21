# TODO

## Sign-in bootstrap events misclassified (ingestor)

Console sign-in bootstrap events from `signin.amazonaws.com` are not being
attributed to the console session they belong to. Two related symptoms observed
in sandbox after a fresh wipe + re-ingest:

1. **Lone `ConsoleLogin` → spurious windowed session.**
   A `ConsoleLogin` under a direct-SAML role (e.g. `SandboxAdminDirect`) with no
   follow-on console activity in the batch has a bare userIdentity (no
   sessionContext, no access key, no browser UA). It can't group into or anchor
   onto a console session, so it falls to the windowed fallback (`win#`) as its
   own 1-event session. `foldConsoleSignIn` only folds when a matching `rc#`
   console group with the same principalId exists in the same batch — a lone
   sign-in has none.
   - Partially mitigated: the blank ROLE column is fixed (ExtractRoleNameFromARN
     now handles `sts:assumed-role` ARNs). The spurious-session issue itself
     remains.

2. **`GetSigninToken` → misclassified as CLI (`key#` anchor).**
   Unlike `ConsoleLogin`, `GetSigninToken` carries a temporary access key and no
   browser UA (it's AWS's federation endpoint, from an AWS-internal source IP).
   So `CredentialGroupKey` → `ak#<key>`, `Anchor` → `key#<key>` → typed **CLI**,
   even though it's part of a console (web) sign-in. Example: session `hfdosx`,
   role `SandboxPowerUser`, single event `signin.amazonaws.com:GetSigninToken`,
   typed CLI though the user never used the CLI with that role.

**Chosen direction (not yet implemented):** extend `isConsoleSignInEvent` in
`ingestor/lib/identity/identity.go` to also match
`signin.amazonaws.com:GetSigninToken`, so `foldConsoleSignIn` folds it into the
matching console session by principalId — the same mechanism used for
`ConsoleLogin`.

**Open questions to resolve before implementing (needs raw CloudTrail JSON):**
- Does `GetSigninToken`'s principalId (`roleID:sessionName`) match the console
  activity's principalId exactly? The fold matches on the full principalId, and
  the sign-in's session name may differ from the console activity's.
- The fold only fires on singleton groups (`len==1`) and matches
  `consoleByPrincipal`, which is populated only for `rc#` groups passing
  `isConsoleSessionCredential`. Confirm the console web session is `rc#`-keyed
  and that the sign-in token's access key appears on no other event.
- Whether the same fix (or a separate one) also resolves symptom 1.

**Out of scope for the current PR** (sid / `--session` selector). These are
pre-existing ingestor behaviors surfaced during verification, not caused by the
sid change.
