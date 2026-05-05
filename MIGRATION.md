<!-- AUTO-GENERATED from bridged-mcp/migration/STATE.yaml. DO NOT EDIT.
     Last sync: 2026-05-05. Re-run: bridged-mcp/migration/sync.sh -->

# Migration status — mcp-vikunja

**Current stage:** 4 of 9
**Auth model:** shared-key
**Port (target):** 8085
**Last change:** 2026-05-05

## Why this migration is happening

Aircall marketing pilots (20 users) are moving from local `.mcpb` installs to a hosted MCP fleet behind `mcp.trentmorris.dev`. The fleet uses **Cloudflare Access SSO** (Google IdP) as the gate — pilots install the bridge once, sign in with their `@aircall.io` Google account once, and never touch credentials again. Drive additionally does Google OAuth for per-user Drive access; the other 3 MCPs share org-wide vendor credentials in GCP Secret Manager.

- Architectural pattern: `/Users/trentmorris/AI/General/libraries/bridged-mcp/pattern.md`
- Deployment recipe: `/Users/trentmorris/AI/General/libraries/bridged-mcp/deployment/vm-cloudflare.md` (§5–§6 describe the CF Access SSO gate model used by this fleet)
- Decision record: `project_hosted_mcp_architecture.md` in this workspace's Claude project memory dir

## What stage 4 means

See `bridged-mcp/migration/STAGES.md` § Stage 4 for the verifiable definition-of-done.

## In-flight refactors

None.

## Blockers



## Where the truth lives

`/Users/trentmorris/AI/General/libraries/bridged-mcp/migration/STATE.yaml`. Hand-edits to *this file* will be overwritten on the next sync. To change state, edit `STATE.yaml` and run `./migration/sync.sh`.