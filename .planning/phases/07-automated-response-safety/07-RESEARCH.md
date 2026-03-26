# Phase 7: Automated Response Safety - Research

**Researched:** 2026-03-25
**Domain:** Response action validation, dry-run mode, rollback operations, audit trail
**Confidence:** HIGH

## Summary

Phase 7 adds production safety to the existing response action infrastructure. The codebase already has significant building blocks: `action-dispatcher.ts` handles 12+ action types with risk levels and approval workflows, `rollback-engine.ts` defines reverse action mappings, `responseActions`/`responseActionRollbacks`/`responseActionApprovals` tables exist in the schema, and `storage/response-actions.ts` provides CRUD for all three tables. The playbook execution system already implements dry-run mode as a pattern.

The gaps are: (1) no Zod validation schemas for action-type-specific inputs -- the dispatcher uses TypeScript interfaces with `as` casts and no runtime validation, (2) no dedicated dry-run mode on `dispatchAction()` itself -- only playbook execution skips dispatch, (3) the rollback endpoint `POST /api/incidents/{id}/rollback-actions` does not exist (rollbacks are currently only via `POST /api/autonomous/rollbacks`), (4) audit logging for response actions is inconsistent -- some paths write audit logs, others don't, and (5) no test suite for action dispatcher at all.

**Primary recommendation:** Add Zod schemas per action type as the foundation, then thread `dryRun` flag through `dispatchAction()`, wire up the incident rollback endpoint using existing `rollback-engine.ts`, ensure every dispatch path writes to `auditLogs`, and create a comprehensive test file `server/__tests__/action-dispatcher.test.ts`.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
None -- all implementation choices are at Claude's discretion.

### Claude's Discretion
All implementation choices are at Claude's discretion -- pure infrastructure phase. Key technical considerations:
- Action types to validate: IsolateHost, BlockIP, QuarantineFile, DisableUser, KillProcess (from response_actions table and action-dispatcher.ts)
- Dry-run mode: add `dryRun: boolean` parameter to action dispatch, validate and log but skip execution
- Rollback: POST /api/incidents/{id}/rollback-actions generates reverse operations (UnisolateHost, UnblockIP, etc.)
- Audit logging: every action writes to audit_logs with action type, parameters, result, duration, triggering user
- Test suite: cover dry-run, rollback, permission checks, concurrent execution on same incident

### Deferred Ideas (OUT OF SCOPE)
None
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| RESP-01 | Dry-run mode on action dispatcher -- validates inputs, checks permissions, logs planned actions without executing | Playbook execution already has dry-run pattern (lines 97-104, 145-151 of execution.ts). `dispatchAction()` needs `dryRun` option; `responseActionApprovals` table already has `dryRunResult` column. |
| RESP-02 | Action rollback API (`POST /api/incidents/{id}/rollback-actions`) generates and executes reverse operations with full audit trail | `rollback-engine.ts` already defines reverse mappings (isolate->unisolate, block->unblock, etc.) and `executeRollback()`. Storage layer has `createResponseActionRollback()`. Need new route in `incidents.ts` that finds completed actions for an incident and creates rollback records. |
| RESP-03 | Zod validation schema for each action type validated before dispatch | Currently uses TypeScript interfaces with `as` casts (no runtime validation). Zod is already used extensively in the project. Need Zod schemas for: IsolateHost, BlockIP, BlockDomain, QuarantineFile, DisableUser, KillProcess, plus ticketing and notification types. |
| RESP-04 | Every response action writes to audit_logs with action type, parameters, result, duration, and triggering user | `createAuditLog()` in `storage/audit.ts` exists with chain-hash integrity. Some paths (like `incidents.ts` push-to-ticketing) already create audit logs, but `dispatchAction()` itself does not. Need centralized audit logging in the dispatcher. |
| RESP-05 | Action dispatcher test suite covering dry-run, rollback, permission checks, and concurrent execution on same incident | No test file exists for action-dispatcher. Vitest 4.x configured with `server/__tests__/**/*.test.ts` pattern. Use transaction mock proxy pattern (established in Phase 5) for DB mocking. |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| zod | Already installed | Action input validation schemas | Already used throughout the project for request validation. Project convention. |
| vitest | 4.x (installed) | Test suite for action dispatcher | Project test framework, already configured. |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| drizzle-orm | Already installed | DB queries for response actions, audit logs | All storage operations go through Drizzle. |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Zod per-action schemas | Single generic schema | Per-action schemas catch field-level errors (e.g., IP format, hostname required). Generic schema misses domain constraints. |
| Centralized audit in dispatchAction | Audit in each caller | Centralized ensures no path skips logging. Callers can add extra context. |

**Installation:** No new dependencies needed. Everything is already installed.

## Architecture Patterns

### Recommended Project Structure
```
server/
  action-dispatcher.ts         # Add dryRun support, Zod validation before dispatch
  action-schemas.ts            # NEW: Zod schemas per action type + validation helper
  rollback-engine.ts           # Already exists, enhance with incident-level rollback
  routes/
    incidents.ts               # Add POST /api/incidents/:id/rollback-actions
  storage/
    response-actions.ts        # Already has CRUD for actions, rollbacks, approvals
    audit.ts                   # Already has createAuditLog with chain-hash
  __tests__/
    action-dispatcher.test.ts  # NEW: comprehensive test suite
```

### Pattern 1: Zod Action Schema Registry
**What:** A map of action type -> Zod schema, with a `validateActionInput()` function that dispatchers call before execution.
**When to use:** Before every action dispatch.
**Example:**
```typescript
// server/action-schemas.ts
import { z } from "zod";

const isolateHostSchema = z.object({
  hostname: z.string().min(1).optional(),
  ip: z.string().ip().optional(),
  target: z.string().min(1).optional(),
  sensorId: z.string().uuid().optional(),
  reason: z.string().optional(),
  timeoutSeconds: z.number().int().min(1).max(3600).optional(),
}).refine(
  (d) => d.hostname || d.ip || d.target || d.sensorId,
  { message: "At least one of hostname, ip, target, or sensorId is required" }
);

const blockIpSchema = z.object({
  ip: z.string().ip().optional(),
  targetIp: z.string().ip().optional(),
  target: z.string().min(1).optional(),
  reason: z.string().optional(),
}).refine(
  (d) => d.ip || d.targetIp || d.target,
  { message: "At least one of ip, targetIp, or target is required" }
);

export const ACTION_SCHEMAS: Record<string, z.ZodType> = {
  isolate_host: isolateHostSchema,
  block_ip: blockIpSchema,
  block_domain: blockDomainSchema,
  quarantine_file: quarantineFileSchema,
  disable_user: disableUserSchema,
  kill_process: killProcessSchema,
  // ... ticketing, notification schemas
};

export function validateActionInput(
  actionType: string,
  config: Record<string, unknown>,
): { valid: true; data: unknown } | { valid: false; errors: z.ZodError } {
  const schema = ACTION_SCHEMAS[actionType];
  if (!schema) return { valid: true, data: config }; // unknown action types pass through
  const result = schema.safeParse(config);
  if (result.success) return { valid: true, data: result.data };
  return { valid: false, errors: result.error };
}
```

### Pattern 2: Dry-Run Flag Threading
**What:** Add `dryRun?: boolean` to `ActionContext`, check it at the top of `dispatchAction()` after validation.
**When to use:** When the caller wants to preview actions without executing.
**Example:**
```typescript
// In action-dispatcher.ts
export async function dispatchAction(
  actionType: string,
  config: Record<string, unknown>,
  context: ActionContext,
): Promise<ActionResult> {
  const executedAt = new Date().toISOString();

  // Step 1: Validate inputs with Zod schema
  const validation = validateActionInput(actionType, config);
  if (!validation.valid) {
    return {
      actionType,
      status: "failed",
      message: `Validation failed: ${validation.errors.issues.map(i => i.message).join(", ")}`,
      details: { validationErrors: validation.errors.issues },
      executedAt,
    };
  }

  // Step 2: If dry-run, return simulated result without executing
  if (context.dryRun) {
    const dryResult: ActionResult = {
      actionType,
      status: "simulated",
      message: `[Dry Run] Would execute: ${actionType}`,
      details: { config, validationPassed: true, dryRun: true },
      executedAt,
    };
    // Log dry-run to audit
    await createDryRunAuditLog(actionType, config, context, dryResult);
    return dryResult;
  }

  // Step 3: Execute action (existing switch)
  const startMs = Date.now();
  const result = await executeAction(actionType, config, context, executedAt);
  const durationMs = Date.now() - startMs;

  // Step 4: Audit log
  await createActionAuditLog(actionType, config, context, result, durationMs);

  return result;
}
```

### Pattern 3: Incident-Level Rollback
**What:** `POST /api/incidents/:id/rollback-actions` finds all completed rollback-eligible actions for the incident, creates reverse operations, and executes them sequentially.
**When to use:** When an incident's containment actions need to be reversed (e.g., host re-joined, IP unblocked).
**Example:**
```typescript
// In server/routes/incidents.ts
app.post("/api/incidents/:id/rollback-actions", isAuthenticated, async (req, res) => {
  const incident = await storage.getIncident(p(req.params.id));
  if (!incident) return res.status(404).json({ message: "Incident not found" });

  // Find completed response actions for this incident that can be rolled back
  const actions = await storage.getResponseActions(orgId, incident.id);
  const rollbackable = actions.filter(
    (a) => (a.status === "completed" || a.status === "simulated") && canRollback(a.actionType)
  );

  if (rollbackable.length === 0) {
    return res.json({ message: "No rollback-eligible actions found", rollbacks: [] });
  }

  const results = [];
  for (const action of rollbackable) {
    const rollback = await createRollbackRecord(
      orgId, action.id, action.actionType, action.targetValue || "unknown"
    );
    const executed = await executeRollback(rollback.id, userId);
    results.push(executed);
    // Audit log each rollback
    await storage.createAuditLog({
      orgId, userId, userName,
      action: "response_action_rolled_back",
      resourceType: "response_action",
      resourceId: action.id,
      details: { originalAction: action.actionType, rollbackId: rollback.id, status: executed?.status },
    });
  }

  res.json({ rollbacks: results, count: results.length });
});
```

### Anti-Patterns to Avoid
- **Validating only at the route level:** Validation must happen inside `dispatchAction()` so playbook execution and autonomous actions also get validated.
- **Skipping audit for dry-run:** Dry-runs MUST still create audit log entries (with `dryRun: true` in details) for compliance.
- **Executing rollbacks in parallel:** Actions that modify the same target must be sequential to avoid conflicts.
- **Using `as` type casts without Zod validation:** The current pattern of `config as TicketingConfig` is unsafe. Replace with Zod `.parse()`.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Input validation | Custom validation functions per action | Zod schemas with `.safeParse()` | Zod provides structured error messages, type inference, composability |
| Reverse action mapping | Dynamic computation of rollback types | Static `ROLLBACK_ACTIONS` map in `rollback-engine.ts` | Already exists, explicit mapping is safer than inference |
| Chain-hash audit logging | Custom hash computation | Existing `createAuditLog()` in `storage/audit.ts` | Already implements SHA-256 chain-hash with sequence numbers |
| Concurrent execution guard | Custom mutex/semaphore | Database-level `FOR UPDATE` row lock on incident | PostgreSQL handles concurrency correctly with row-level locks |

**Key insight:** Almost all infrastructure exists. The work is wiring it together: add Zod validation layer, thread dry-run through dispatcher, add incident rollback route, centralize audit logging.

## Common Pitfalls

### Pitfall 1: Validation Bypass via Playbook Execution
**What goes wrong:** Playbooks call `dispatchAction()` with arbitrary config from the playbook definition. If validation only happens in the REST route, playbook-triggered actions skip validation.
**Why it happens:** Validation is placed at the wrong layer (route vs dispatcher).
**How to avoid:** Put Zod validation INSIDE `dispatchAction()`, before the action type switch statement.
**Warning signs:** Playbook execution logs showing malformed action configs.

### Pitfall 2: Rollback Creating Infinite Loop
**What goes wrong:** If a rollback action (e.g., "unisolate_host") is itself rollback-eligible, rolling back the rollback creates the original action again.
**Why it happens:** `canRollback()` returns true for rollback action types too.
**How to avoid:** Only roll back actions that were NOT themselves rollbacks. Track `isRollback: boolean` on the response_action record, or filter by original action types only.
**Warning signs:** Growing chain of rollback records for the same target.

### Pitfall 3: Missing Org Scoping on Rollback Queries
**What goes wrong:** Fetching response actions without orgId filter leaks data across tenants.
**Why it happens:** The `getResponseActions()` function has optional orgId.
**How to avoid:** Always pass orgId when querying from a route handler. The route handler gets orgId from `getOrgId(req)`.
**Warning signs:** Audit logs showing cross-org resource access.

### Pitfall 4: Duration Measurement Not Including Async Wait
**What goes wrong:** Measuring `Date.now()` before/after dispatch only captures wall-clock time, which is correct for async operations. But if the action returns "pending_approval", duration is near-zero and misleading.
**Why it happens:** High-risk actions are queued, not immediately executed.
**How to avoid:** Only record duration for actions that actually executed (status "completed" or "failed"). For "pending_approval" actions, record 0 or null for duration.
**Warning signs:** All actions showing 0ms duration.

### Pitfall 5: Concurrent Rollback of Same Incident
**What goes wrong:** Two users simultaneously trigger rollback on the same incident, executing reverse actions twice (e.g., unblocking an IP twice).
**Why it happens:** No locking or idempotency check on the rollback endpoint.
**How to avoid:** Before creating rollback records, check if pending/completed rollbacks already exist for each action. Use SELECT FOR UPDATE on the response_actions rows being rolled back.
**Warning signs:** Duplicate rollback records for the same original action.

## Code Examples

### Existing Dry-Run Pattern (from playbook execution)
```typescript
// server/routes/playbooks/execution.ts lines 97-104
if (isDryRun) {
  executedActions.push({
    nodeId,
    actionType: node.data.actionType,
    status: "simulated",
    message: `[Dry Run] Would execute: ${node.data.label}`,
    executedAt: new Date().toISOString(),
  });
} else {
  const result = await dispatchAction(node.data.actionType, node.data.config || {}, context);
  executedActions.push({ nodeId, ...result });
}
```

### Existing Rollback Engine
```typescript
// server/rollback-engine.ts
const ROLLBACK_ACTIONS: Record<string, string> = {
  isolate_host: "unisolate_host",
  block_ip: "unblock_ip",
  block_domain: "unblock_domain",
  quarantine_file: "restore_file",
  disable_user: "enable_user",
  kill_process: "restart_process",
};
```

### Existing Audit Log with Chain-Hash
```typescript
// server/storage/audit.ts
export async function createAuditLog(log: Partial<AuditLog>): Promise<AuditLog> {
  const ctx = currentContext();
  // ... enriches with requestId, userAgent, impersonatedBy
  const lastSeq = await getLatestAuditLogSequence(orgId);
  const sequenceNum = lastSeq ? lastSeq.sequenceNum + 1 : 1;
  const prevHash = lastSeq ? lastSeq.entryHash : "genesis";
  const entryHash = createHash("sha256").update(JSON.stringify({
    prevHash, action, userId, resourceType, resourceId, details, sequenceNum,
  })).digest("hex");
  // ... inserts with chain-hash
}
```

### Existing Risk Classification
```typescript
// server/action-dispatcher.ts
const HIGH_RISK_ACTIONS = ["isolate_host", "disable_user"];
const MEDIUM_RISK_ACTIONS = ["kill_process", "block_ip", "quarantine_file", "block_domain"];
```

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Vitest 4.x |
| Config file | `vitest.config.ts` |
| Quick run command | `npx vitest run server/__tests__/action-dispatcher.test.ts` |
| Full suite command | `npx vitest run` |

### Phase Requirements -> Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| RESP-01 | Dry-run validates inputs, checks permissions, logs without executing | unit | `npx vitest run server/__tests__/action-dispatcher.test.ts -t "dry-run"` | Wave 0 |
| RESP-02 | Rollback generates reverse operations with audit trail | unit | `npx vitest run server/__tests__/action-dispatcher.test.ts -t "rollback"` | Wave 0 |
| RESP-03 | Zod schemas validate each action type before dispatch | unit | `npx vitest run server/__tests__/action-dispatcher.test.ts -t "validation"` | Wave 0 |
| RESP-04 | Every action creates audit_logs entry with full context | unit | `npx vitest run server/__tests__/action-dispatcher.test.ts -t "audit"` | Wave 0 |
| RESP-05 | Test suite covers dry-run, rollback, permissions, concurrent execution | unit | `npx vitest run server/__tests__/action-dispatcher.test.ts` | Wave 0 |

### Sampling Rate
- **Per task commit:** `npx vitest run server/__tests__/action-dispatcher.test.ts`
- **Per wave merge:** `npx vitest run`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `server/__tests__/action-dispatcher.test.ts` -- covers RESP-01 through RESP-05
- [ ] `server/action-schemas.ts` -- Zod schemas for all action types (RESP-03)

## Sources

### Primary (HIGH confidence)
- Direct codebase analysis of `server/action-dispatcher.ts` (625 lines) -- full action dispatch logic
- Direct codebase analysis of `server/rollback-engine.ts` (81 lines) -- rollback mappings and execution
- Direct codebase analysis of `server/storage/response-actions.ts` (191 lines) -- CRUD for actions, rollbacks, approvals
- Direct codebase analysis of `server/storage/audit.ts` (80+ lines) -- chain-hash audit logging
- Direct codebase analysis of `server/routes/playbooks/execution.ts` -- existing dry-run pattern
- Direct codebase analysis of `server/routes/autonomous.ts` -- existing rollback endpoints
- Direct codebase analysis of `shared/schema.ts` -- `responseActions`, `responseActionRollbacks`, `responseActionApprovals`, `auditLogs` tables

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- no new dependencies, everything exists in the project
- Architecture: HIGH -- extending existing patterns (dry-run from playbooks, rollback from rollback-engine, audit from storage/audit.ts)
- Pitfalls: HIGH -- derived from codebase analysis (multi-tenant isolation, concurrent access, validation bypass vectors)

**Research date:** 2026-03-25
**Valid until:** 2026-04-25 (stable infrastructure phase, no external dependency changes)
