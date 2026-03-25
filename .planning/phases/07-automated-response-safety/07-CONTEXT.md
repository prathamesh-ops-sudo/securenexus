# Phase 7: Automated Response Safety - Context

**Gathered:** 2026-03-25
**Status:** Ready for planning

<domain>
## Phase Boundary

Make response actions production-safe: Zod validation schemas for every action type, dry-run mode that validates without executing, rollback API that generates and executes reverse operations, comprehensive audit logging for every action, and a test suite covering all safety scenarios.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion
All implementation choices are at Claude's discretion — pure infrastructure phase. Key technical considerations:
- Action types to validate: IsolateHost, BlockIP, QuarantineFile, DisableUser, KillProcess (from response_actions table and action-dispatcher.ts)
- Dry-run mode: add `dryRun: boolean` parameter to action dispatch, validate and log but skip execution
- Rollback: POST /api/incidents/{id}/rollback-actions generates reverse operations (UnisolateHost, UnblockIP, etc.)
- Audit logging: every action writes to audit_logs with action type, parameters, result, duration, triggering user
- Test suite: cover dry-run, rollback, permission checks, concurrent execution on same incident

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `server/action-dispatcher.ts` — Current action dispatch logic
- `server/routes/playbooks/execution.ts` — Playbook execution with action dispatch
- `server/routes/playbooks/approvals.ts` — Human-in-the-loop approval workflows
- `shared/schema.ts` — `responseActions` table with status (pending/executing/completed/failed), `auditLogs` table with chain-hash structure
- `server/remediation-engine.ts` — Remediation orchestration

### Established Patterns
- Response actions use status lifecycle: pending → executing → completed/failed
- Audit logs use chain-hash for tamper evidence (previousHash → currentHash)
- RBAC checks via `server/rbac.ts` for action permissions
- Zod validation already used extensively for request bodies

### Integration Points
- `POST /api/incidents/:id/actions` — trigger response actions
- `POST /api/incidents/:id/rollback-actions` — new rollback endpoint
- Playbook execution triggers actions via action-dispatcher
- Audit logs written via createAuditLog storage function

</code_context>

<specifics>
## Specific Ideas

No specific requirements — infrastructure phase

</specifics>

<deferred>
## Deferred Ideas

None

</deferred>
