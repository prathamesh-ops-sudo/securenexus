# Phase 3: God File Decomposition - Research

**Researched:** 2026-03-25
**Domain:** TypeScript module decomposition / structural refactoring
**Confidence:** HIGH

## Summary

Phase 3 decomposes three god files (storage.ts at 6,243 lines, routes/ai.ts at 3,544 lines, routes/playbooks.ts at 3,541 lines -- totaling 13,328 lines) into domain modules with barrel exports preserving backward compatibility. This is a pure structural refactoring with zero behavioral changes.

The critical complexity is in storage.ts: it exports an `IStorage` interface (893 lines, ~280 method signatures), a `DatabaseStorage` class implementing it (~4,960 lines, ~554 async methods), and a singleton `const storage = new DatabaseStorage()`. It is imported by 53+ files across the codebase. The barrel index.ts must re-export `storage`, `IStorage`, and `DatabaseStorage` identically.

A key discovery is that `server/storage/` directory already exists with `cold-query.ts` and `tiering-manager.ts`. These files import from `../db` (not from `../storage`), so they are independent and will coexist naturally with the new domain modules. The split requires renaming `storage.ts` to `storage/index.ts` -- since Node.js bundler resolution resolves `./storage` to `./storage/index.ts` when the directory exists and no `.ts` file is present.

**Primary recommendation:** Split each file into domain modules where each module contains only the implementation functions. The `IStorage` interface stays intact in a single `types.ts` file. The `DatabaseStorage` class in `index.ts` delegates to domain module functions. Barrel `index.ts` re-exports everything consumers currently import.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
No locked decisions -- all implementation choices at Claude's discretion.

### Claude's Discretion
All implementation choices are at Claude's discretion -- structural refactoring phase. Key guidance:
- storage.ts -> server/storage/ directory with domain modules + barrel index.ts
- routes/ai.ts -> domain modules (triage, narrative, correlation, context-optimization, embeddings)
- routes/playbooks.ts -> domain modules (crud, execution, scheduling, templates)
- Barrel exports must preserve all existing import paths (backward compatibility)
- No single file in split domains should exceed 800 lines
- No route contract changes -- all endpoints keep same paths and behavior
- No behavioral changes -- this is purely structural

### Deferred Ideas (OUT OF SCOPE)
None -- discussion stayed within phase scope.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| SPLIT-01 | Split server/routes/ai.ts (3,542 lines) into domain modules (triage, narrative, correlation, context-optimization, embeddings) | Route endpoint analysis identifies 35+ endpoints groupable into 6-7 domain modules. Helper function `persistAttackGraph` is file-local and moves to the investigation module. |
| SPLIT-02 | Split server/routes/playbooks.ts (3,541 lines) into domain modules (crud, execution, scheduling, templates) | Route endpoint analysis identifies clear groupings: CRUD (get/create/update/delete playbooks), execution (execute/resume/rollback), versions/simulation/blast-radius, approvals. |
| SPLIT-03 | Split server/storage.ts (6,222 lines) into domain modules (alerts, incidents, connectors, auth, etc.) with barrel export for backward compatibility | Method grouping analysis identifies 44 domains. Consolidation to ~12-15 modules keeps each under 800 lines. No private class methods -- all methods are public interface implementations. |
</phase_requirements>

## Architecture Patterns

### Recommended Structure: storage.ts Split

```
server/
  storage.ts               # DELETE (replaced by storage/index.ts)
  storage/
    index.ts               # Barrel: DatabaseStorage class + re-exports storage, IStorage
    types.ts               # IStorage interface (~900 lines -- single interface is OK)
    alerts.ts              # Alert CRUD + search + pagination (~166 lines)
    incidents.ts           # Incident CRUD + comments + SLA + PIR (~225 lines)
    connectors.ts          # Connector CRUD + health checks + job runs + metrics (~250 lines)
    organizations.ts       # Org CRUD + memberships + invitations + SSO/SCIM (~320 lines)
    auth.ts                # API keys + sessions + password reset (~111 lines)
    playbooks.ts           # Playbook CRUD + executions + approvals + versions (~208 lines)
    compliance.ts          # Policies + controls + mappings + DSAR + evidence (~300 lines)
    ai.ts                  # AI feedback + deployment config + chat + generated rules (~102 lines)
    ioc.ts                 # IOC feeds + entries + watchlists + match rules + matches (~163 lines)
    cspm.ts                # CSPM accounts + scans + findings + drift + attack paths (~151 lines)
    dashboard.ts           # Dashboard stats + analytics + cached metrics (~232 lines)
    predictive.ts          # Anomalies + attack surface + risk forecasts + hardening (~172 lines)
    jobs.ts                # Job queue + outbox events + SLI/SLO (~296 lines)
    response-actions.ts    # Response actions + rollbacks + investigations (~200 lines)
    reports.ts             # Report templates + schedules + runs (~120 lines)
    misc.ts                # Tags, notifications, integrations, views, billing, etc. (~500 lines)
    cold-query.ts          # EXISTING - keep as-is
    tiering-manager.ts     # EXISTING - keep as-is
```

### Pattern: Standalone Functions (Recommended for storage.ts)

Each domain module exports standalone functions that receive the `db` dependency directly. The DatabaseStorage class in index.ts delegates to these functions.

**Why this pattern:** The DatabaseStorage class has zero private methods and zero shared state between methods. Every method is a standalone Drizzle query. The class is purely organizational -- methods can be extracted as standalone functions trivially.

```typescript
// server/storage/alerts.ts
import { db } from "../db";
import { eq, desc, sql, and, ilike, or } from "drizzle-orm";
import { alerts } from "@shared/schema";
import type { Alert, InsertAlert } from "@shared/schema";

export async function getAlerts(orgId?: string): Promise<Alert[]> {
  if (orgId) {
    return db.select().from(alerts).where(eq(alerts.orgId, orgId)).orderBy(desc(alerts.createdAt));
  }
  return db.select().from(alerts).orderBy(desc(alerts.createdAt));
}

export async function createAlert(alert: InsertAlert): Promise<Alert> {
  const [created] = await db.insert(alerts).values(alert).returning();
  return created;
}
// ... etc
```

```typescript
// server/storage/index.ts
import type { IStorage } from "./types";
import * as alertFns from "./alerts";
import * as incidentFns from "./incidents";
// ... etc

export type { IStorage };

export class DatabaseStorage implements IStorage {
  // Alerts
  getAlerts = alertFns.getAlerts;
  getAlert = alertFns.getAlert;
  createAlert = alertFns.createAlert;
  // ... etc (method assignment, not delegation wrapper)
}

export const storage = new DatabaseStorage();
```

### Pattern: Route Module Split (for ai.ts and playbooks.ts)

Each domain module exports a `register*Routes(app: Express)` function. The parent barrel calls all sub-registrations.

```typescript
// server/routes/ai/index.ts
import type { Express } from "express";
import { registerAiTriageRoutes } from "./triage";
import { registerAiNarrativeRoutes } from "./narrative";
// ...

export function registerAiRoutes(app: Express): void {
  registerAiTriageRoutes(app);
  registerAiNarrativeRoutes(app);
  // ...
}
```

```typescript
// server/routes/ai/triage.ts
import type { Express, Request, Response } from "express";
import { getOrgId, logger, p, storage, strictLimiter } from "../shared";
// ...

export function registerAiTriageRoutes(app: Express): void {
  app.post("/api/ai/triage", isAuthenticated, ...);
  // ...
}
```

### Recommended Structure: routes/ai.ts Split

```
server/routes/
  ai.ts                    # DELETE (replaced by ai/index.ts)
  ai/
    index.ts               # Barrel: registerAiRoutes delegates to sub-registrations
    setup.ts               # Setup status, health, config, circuit alerts (~150 lines)
    triage.ts              # Triage, correlation/apply (~200 lines)
    narrative.ts           # Narrative generation, streaming, investigation (~400 lines)
    feedback.ts            # AI feedback CRUD + analytics + inline feedback (~350 lines)
    prompts.ts             # Prompt catalog, history, audit, A/B tests, variables, categories, quality (~400 lines)
    active-learning.ts     # Auto-examples, suppression status, feedback analytics (~200 lines)
    deployment.ts          # AI deployment config, model gateway (~300 lines)
    investigation.ts       # Deep investigation, multi-turn, attack graphs, chat, history (~500 lines)
    context-optimization.ts # Context optimization, hallucination check (~200 lines)
    models.ts              # Model listing, data sources (~250 lines)
    detection-rules.ts     # Generated rules (~100 lines)
    helpers.ts             # persistAttackGraph helper + event listener setup (~100 lines)
```

### Recommended Structure: routes/playbooks.ts Split

```
server/routes/
  playbooks.ts             # DELETE (replaced by playbooks/index.ts)
  playbooks/
    index.ts               # Barrel: registerPlaybooksRoutes delegates to sub-registrations
    crud.ts                # GET/POST/PATCH/DELETE playbooks (~200 lines)
    execution.ts           # Execute, resume, rollback, execution history (~400 lines)
    approvals.ts           # Approval workflow (list, approve, reject) (~200 lines)
    versions.ts            # Playbook versioning, blast radius, simulation, rollback plans (~500 lines)
    scheduling.ts          # Scheduling-related routes if any (~100 lines)
```

### Anti-Patterns to Avoid

- **Splitting the IStorage interface across files:** The interface is a single contract. Splitting it creates circular dependency risk and makes the type harder to maintain. Keep it in one `types.ts` file even at ~900 lines.
- **Wrapping delegated methods:** Do NOT write `getAlerts(...args) { return alertFns.getAlerts(...args); }`. Use direct assignment: `getAlerts = alertFns.getAlerts;`. Avoids boilerplate and preserves identical behavior.
- **Creating intermediate barrel re-exports in domain modules:** Each domain module should export functions directly. Only `index.ts` re-exports for the public API.
- **Moving the singleton instantiation:** `const storage = new DatabaseStorage()` must stay in `index.ts`. Moving it to a separate file creates import ordering issues.
- **Changing import paths in consumer files:** The whole point of barrel exports is that `import { storage } from "./storage"` continues to work. Zero consumer file changes.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Module re-export typing | Manual type duplication | `export type { IStorage } from "./types"` | TypeScript handles re-exported types natively |
| Method assignment type checking | Manual signatures | `getAlerts = alertFns.getAlerts` property assignment | TS infers and validates against IStorage interface automatically |
| Barrel export completeness | Manual list of every export | `export { storage, DatabaseStorage } from "./index"` + `export type { IStorage } from "./types"` | Let TS compiler catch missing implementations |

## Common Pitfalls

### Pitfall 1: File vs Directory Resolution Conflict
**What goes wrong:** If `server/storage.ts` and `server/storage/index.ts` both exist, bundler resolution is ambiguous. Some bundlers prefer the file, others prefer the directory.
**Why it happens:** The project uses `"moduleResolution": "bundler"` in tsconfig.json. Esbuild (used for production build) resolves `./storage` to `storage.ts` over `storage/index.ts` when both exist.
**How to avoid:** DELETE `server/storage.ts` before (or atomically with) creating `server/storage/index.ts`. Never have both simultaneously in a committed state. The existing `server/storage/cold-query.ts` and `tiering-manager.ts` currently coexist because no `index.ts` exists in that directory.
**Warning signs:** Build fails with "duplicate module" or runtime imports resolve to wrong file.

### Pitfall 2: Circular Imports Between Domain Modules
**What goes wrong:** If `alerts.ts` imports from `incidents.ts` and vice versa, you get circular dependency.
**Why it happens:** Some storage methods might reference types or tables from other domains.
**How to avoid:** All domain modules import only from `../db`, `drizzle-orm`, and `@shared/schema`. They never import from each other. Shared Drizzle imports (db, operators) come from external packages, not from sibling modules.
**Warning signs:** Runtime `undefined` values on imported symbols.

### Pitfall 3: The IStorage Interface Must Match Exactly
**What goes wrong:** If a function signature in a domain module doesn't match the IStorage interface, TypeScript reports the error at the class level, not at the function level. This makes debugging harder.
**How to avoid:** Keep `IStorage` in `types.ts` and use `satisfies` or explicit typing where helpful. The class-level `implements IStorage` catches any mismatches at compile time.
**Warning signs:** TypeScript errors like "Property 'getAlerts' is incompatible with index signature."

### Pitfall 4: Event Listener Registration in AI Routes
**What goes wrong:** The `registerAiRoutes` function starts by registering an event listener on `eventBus`. If split carelessly, this listener could be registered multiple times or not at all.
**Why it happens:** The circuit breaker event listener at line 147 of ai.ts is called once during route registration.
**How to avoid:** Put the event listener registration in the barrel `index.ts` for ai routes, not in a sub-module.
**Warning signs:** Duplicate alerts for circuit breaker events, or missing alerts.

### Pitfall 5: Existing storage/ Directory Files
**What goes wrong:** Forgetting that `server/storage/cold-query.ts` and `server/storage/tiering-manager.ts` already exist and have their own imports relative to `../db`.
**Why it happens:** These files import from `../db`, `../logger`, `../s3`, and `@shared/schema` -- all of which remain valid after the split.
**How to avoid:** Leave these files untouched. They are independent modules that happen to be in the storage directory. Do NOT include them in the barrel export.
**Warning signs:** Build errors in cold-query.ts or tiering-manager.ts.

## Storage.ts Domain Grouping Analysis

Analysis of 554 async methods grouped by domain (method count, approximate line count):

| Domain | Methods | ~Lines | Target Module |
|--------|---------|--------|---------------|
| organizations (+ memberships, invitations, SSO, SCIM, domains) | 34 | 225 | organizations.ts |
| playbooks (+ executions, approvals, versions, simulation) | 32 | 208 | playbooks.ts |
| compliance (+ controls, mappings, DSAR, evidence locker, helpers) | 28 | 167 | compliance.ts |
| ioc (feeds, entries, watchlists, match rules, matches) | 26 | 163 | ioc.ts |
| cspm (accounts, scans, findings, drift, attack paths, remediations) | 27 | 151 | cspm.ts |
| incidents (+ comments, post-incident reviews, PIR) | 22 | 194 | incidents.ts |
| connectors (+ health checks, job runs, metrics) | 19 | 200 | connectors.ts |
| billing (plans, subscriptions, invoices, usage metering) | 21 | 141 | billing.ts |
| predictive (anomalies, attack surface, risk forecasts, hardening) | 19 | 142 | predictive.ts |
| war-room (rooms, participants, messages, action items, handoffs) | 19 | 125 | war-room.ts |
| dashboard (stats, analytics, cached metrics) | 4 | 232 | dashboard.ts |
| evidence (items, hypotheses, tasks, chain entries, attachments) | 19 | 129 | evidence.ts |
| reports (templates, schedules, runs, template versions) | 18 | 120 | reports.ts |
| response-actions (+ rollbacks, incident approvals) | 16 | 114 | response-actions.ts |
| auth (API keys, sessions, password reset) | 16 | 111 | auth.ts |
| jobs (job queue, SLI/SLO, outbox) | 31 | 296 | jobs.ts |
| alerts (+ search, pagination, daily stats, dedup clusters) | 21 | 220 | alerts.ts |
| ai (feedback, deployment, chat, generated rules) | 13 | 102 | ai.ts |
| investigations (runs, steps) | 16 | 89 | response-actions.ts (merge) |
| audit (logs + count) | 7 | 107 | audit.ts |
| notifications (channels, preferences, delivery log) | 9 | 105 | notifications.ts |
| remaining misc (tags, integrations, views, feature flags, etc.) | ~60 | ~350 | misc.ts |

**Consolidation plan:** Merge small domains into larger ones to target 12-15 files. Examples:
- `investigations` + `response-actions` -> `response-actions.ts` (~200 lines)
- `audit` + `tags` -> fold into `misc.ts`
- `notifications` + `integrations` -> `misc.ts`
- `war-room`, `evidence`, `reports` stay separate (cohesive domain boundaries)

### Final Target Module Count: ~18 domain modules

All well under 800 lines individually. The largest would be `misc.ts` at ~500 lines and `jobs.ts` at ~300 lines.

## AI Routes Grouping Analysis

35+ route endpoints in ai.ts grouped by function:

| Group | Endpoints | ~Lines | Target Module |
|-------|-----------|--------|---------------|
| Setup/Health | setup-status, circuit-alerts, health, config, inference-metrics | ~170 | setup.ts |
| Triage/Correlation | triage (POST), correlate/apply (POST) | ~200 | triage.ts |
| Narrative/Streaming | narrative generation, streaming endpoints | ~300 | narrative.ts |
| Feedback | feedback CRUD, analytics, inline feedback | ~350 | feedback.ts |
| Prompts | catalog, history, audit, A/B tests, variables, categories, quality | ~400 | prompts.ts |
| Active Learning | auto-examples, suppression-status, feedback analytics | ~200 | active-learning.ts |
| Deployment/Models | deployment config, model gateway, model listing, data sources | ~400 | deployment.ts |
| Investigation | deep investigation, multi-turn, attack graphs, chat, history | ~500 | investigation.ts |
| Context/Hallucination | context-optimization, hallucination-check | ~200 | context.ts |
| Detection Rules | generated rules | ~100 | detection-rules.ts |
| Helper Functions | persistAttackGraph, event listener | ~150 | (in index.ts and investigation.ts) |

## Playbooks Routes Grouping Analysis

Endpoints in playbooks.ts grouped by function:

| Group | Endpoints | ~Lines | Target Module |
|-------|-----------|--------|---------------|
| CRUD | GET/POST/PATCH/DELETE /api/playbooks | ~200 | crud.ts |
| Execution | POST execute, resume, status, history | ~400 | execution.ts |
| Approvals | GET approvals, POST approve/reject | ~200 | approvals.ts |
| Versions | GET/POST/PATCH versions, blast radius, simulation, rollback plans | ~500 | versions.ts |

## Import Site Analysis

### storage.ts Consumers (53+ files)

Every consumer imports one of:
- `{ storage }` -- the singleton instance (51 files)
- `{ IStorage }` or `type { IStorage }` -- the interface type (2 files: action-dispatcher.ts, predictive-engine.ts)

**Zero files import individual methods or `DatabaseStorage` directly.** This means the barrel only needs to export `storage`, `IStorage`, and `DatabaseStorage` (for completeness).

### routes/ai.ts Consumers

Only `server/routes/index.ts` imports from `./ai` (the `registerAiRoutes` function). No other files import from this route module.

### routes/playbooks.ts Consumers

Only `server/routes/index.ts` imports from `./playbooks` (the `registerPlaybooksRoutes` function). No other files import from this route module.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Vitest 4.x |
| Config file | vitest.config.ts |
| Quick run command | `npx vitest run --reporter=verbose` |
| Full suite command | `npx vitest run --coverage` |

### Phase Requirements -> Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| SPLIT-01 | AI routes still respond correctly after split | smoke | `npx vitest run --reporter=verbose` (existing tests) | Partial -- no dedicated ai route tests |
| SPLIT-02 | Playbook routes still respond correctly after split | smoke | `npx vitest run --reporter=verbose` (existing tests) | Partial -- no dedicated playbook route tests |
| SPLIT-03 | Storage methods still work after split | unit | `npx vitest run --reporter=verbose` (existing tests) | Yes -- org-boundary.test.ts, rbac.test.ts use storage |

### Sampling Rate
- **Per task commit:** `npx vitest run --reporter=verbose` + `npx tsc --noEmit`
- **Per wave merge:** `npx vitest run --coverage`
- **Phase gate:** Full suite green + TypeScript compilation clean

### Wave 0 Gaps
None -- this is a structural refactoring. Existing tests validate behavior. The primary validation is `npx tsc --noEmit` (TypeScript compilation) which will catch any broken imports or type mismatches. If existing tests pass and TypeScript compiles, the split is correct.

## Code Examples

### Barrel index.ts pattern for storage

```typescript
// server/storage/index.ts
export type { IStorage } from "./types";
export { DatabaseStorage } from "./database-storage";

import { DatabaseStorage } from "./database-storage";
export const storage = new DatabaseStorage();
```

### Domain module pattern for storage

```typescript
// server/storage/alerts.ts
import { db } from "../db";
import { eq, desc, sql, and, ilike, or, gte } from "drizzle-orm";
import { alerts, alertTags, tags } from "@shared/schema";
import type { Alert, InsertAlert } from "@shared/schema";

export async function getAlerts(orgId?: string): Promise<Alert[]> {
  if (orgId) {
    return db.select().from(alerts).where(eq(alerts.orgId, orgId)).orderBy(desc(alerts.createdAt));
  }
  return db.select().from(alerts).orderBy(desc(alerts.createdAt));
}

// ... all alert-related methods as standalone functions
```

### Route sub-module pattern

```typescript
// server/routes/ai/triage.ts
import type { Express, Request, Response } from "express";
import { getOrgId, storage } from "../shared";
import { isAuthenticated } from "../../auth";
import { resolveOrgContext, requireOrgId } from "../../rbac";
import { triageAlert, correlateAlerts } from "../../ai";

export function registerAiTriageRoutes(app: Express): void {
  app.post("/api/ai/triage", isAuthenticated, resolveOrgContext, requireOrgId, async (req: Request, res: Response) => {
    // ... handler body unchanged
  });

  app.post("/api/ai/correlate/apply", isAuthenticated, async (req, res) => {
    // ... handler body unchanged
  });
}
```

## Execution Order Recommendation

1. **SPLIT-03 first (storage.ts):** It is the most critical -- 53+ files depend on it. Doing it first means route splits (which also use storage) are tested against the new structure. Also the largest file.
2. **SPLIT-01 second (ai.ts):** Second largest, more complex route groupings.
3. **SPLIT-02 third (playbooks.ts):** Simplest split with clearest domain boundaries.

## Open Questions

1. **Method assignment vs wrapper delegation in DatabaseStorage**
   - What we know: Direct property assignment (`getAlerts = alertFns.getAlerts`) is simpler and avoids argument forwarding
   - What's unclear: TypeScript may require explicit type annotations when using property assignment on a class implementing an interface -- need to verify during implementation
   - Recommendation: Try property assignment first; fall back to one-line wrappers if TS complains

## Sources

### Primary (HIGH confidence)
- Direct codebase analysis of server/storage.ts (6,243 lines), server/routes/ai.ts (3,544 lines), server/routes/playbooks.ts (3,541 lines)
- Import site grep across 53+ consumer files
- Method grouping analysis via AST-like line scanning
- tsconfig.json verification for module resolution strategy
- Existing server/storage/ directory contents (cold-query.ts, tiering-manager.ts)

### Secondary (MEDIUM confidence)
- Node.js/esbuild module resolution behavior for file-vs-directory disambiguation

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - pure refactoring, no new libraries needed
- Architecture: HIGH - based on direct analysis of all three files and their consumers
- Pitfalls: HIGH - identified through concrete codebase analysis (existing directory, resolution rules, event listeners)

**Research date:** 2026-03-25
**Valid until:** 2026-04-25 (stable -- structural patterns don't change)
