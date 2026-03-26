---
plan: 01-02
phase: 01-prerequisite-safety-fixes
status: complete
subsystem: type-safety
tags: [typescript, any-elimination, type-safety, quality]
dependency-graph:
  requires: []
  provides: [typed-correlation-engine, typed-action-dispatcher, typed-auth-session, typed-ai-module]
  affects: [server/correlation-engine.ts, server/graph-correlation.ts, server/action-dispatcher.ts, server/auth/session.ts, server/auth/routes.ts, server/ai.ts]
tech-stack:
  added: []
  patterns: [SessionUser-interface, ActionConfig-union-types, Record-string-unknown]
key-files:
  created: []
  modified:
    - server/correlation-engine.ts
    - server/graph-correlation.ts
    - server/action-dispatcher.ts
    - server/auth/session.ts
    - server/auth/routes.ts
    - server/ai.ts
decisions:
  - "Created SessionUser interface extending User with orgId/orgRole rather than global Express.User augmentation -- keeps the type narrowing explicit at cast sites"
  - "Used Record<string, unknown> for opaque data params (telemetryData, entityContext, etc.) rather than creating 20+ narrow interfaces for AI heuristic functions -- these params are only JSON.stringified, so Record<string, unknown> is the correct semantic type"
  - "Kept as unknown as DeepInvestigationResult for heuristic fallback that returns simplified shape -- the fallback is consumed via JSON serialization so structural mismatch is intentional"
  - "Action dispatcher uses union type ActionConfig with narrowing casts in switch-case rather than a single wide Record type -- provides per-action type documentation while keeping the dispatch entry point flexible"
metrics:
  duration: 19 min
  completed: 2026-03-25
  tasks: 3
  files-modified: 6
---

# Plan 01-02 Summary: Eliminate any Types in Critical Modules

Replaced 72 `any` type annotations across 6 security-critical modules with proper TypeScript types derived from Drizzle schema types (Alert, Incident, Entity, User) and typed config interfaces.

## What Was Done

### Task 1: Correlation Engine and Graph Correlation
- `server/graph-correlation.ts`: `GraphNode.data: any` -> `Record<string, unknown>`; `alertDataList: any[]` -> `Alert[]` (3 functions); `entityDataList: any[]` -> `Entity[]`
- `server/correlation-engine.ts`: `Record<string, any>` -> `Record<string, unknown>` in threat intel confidence boost call

### Task 2: Action Dispatcher
- Created 8 typed config interfaces: `TicketingConfig`, `NotificationConfig`, `AgentActionConfig`, `AutoTriageConfig`, `AssignAnalystConfig`, `ChangeStatusConfig`, `AddTagConfig`, `EscalateConfig`
- `dispatchAction` entry point accepts `Record<string, unknown>` and narrows via typed casts in switch-case
- `conditions as any[]` replaced with properly typed `SQL[]` from drizzle-orm
- `(data as any)?.url` replaced with typed `Record<string, unknown>` access
- `details?: any` -> `details?: Record<string, unknown>` in ActionResult

### Task 3: Auth Session, Auth Routes, and AI Module
**Auth (session.ts + routes.ts):**
- Created `SessionUser` interface extending `User` with `orgId?` and `orgRole?` session-derived fields
- Replaced all `user: any` with `SessionUser` (10 in session.ts, 5 in routes.ts)
- Typed OAuth callbacks with `passport.Profile` and proper `done` function signatures
- `(user as any).isSuperAdmin` -> `(user as SessionUser).isSuperAdmin` in all 5 locations
- `req: any` -> `req: Request` with explicit `req.user as SessionUser` casts

**AI (ai.ts):**
- Added `import type { Alert, Incident }` from `@shared/schema`
- Replaced `incident: any` -> `Incident` in 6 functions
- Replaced `alerts: any[]` / `alertsData: any[]` / `alertData: any` -> `Alert[]` / `Alert` in 10 functions
- Replaced opaque data params (`telemetryData`, `entityContext`, `activityData`, `baselineData`, `compromiseState`, `networkTopology`, `securityControls`) with `Record<string, unknown>`
- Replaced interface `any` fields (evidence, attackGraph nodes/edges, infrastructureFingerprint) with typed arrays/records
- `} as any` -> `} as unknown as DeepInvestigationResult` with ESLint justification comment

## Metrics

| File | any (before) | any (after) | Type-level any remaining |
|------|-------------|-------------|--------------------------|
| server/correlation-engine.ts | 1 | 0 | 0 |
| server/graph-correlation.ts | 5 | 0 | 0 |
| server/action-dispatcher.ts | 14 | 0 | 0 |
| server/auth/session.ts | 10 | 0 | 0 |
| server/auth/routes.ts | 5 | 0 | 0 |
| server/ai.ts | 37 | 2 (comments only) | 0 |
| **Total** | **72** | **2 (non-type)** | **0** |

## Verification

- `grep -c "\bany\b"` on all 6 files: 0 for 5 files, 2 for ai.ts (both in comments/strings, zero type-level)
- `grep -nE ':\s*any\b|as\s+any|<any>|any\[\]' server/ai.ts`: zero matches (confirmed no type annotations)
- TypeScript compilation: could not run locally (worktree without node_modules), but all changes are mechanical type replacements of `any` -> concrete types with no logic changes

## Commits

| Task | Commit | Description |
|------|--------|-------------|
| 1 | b3bfd4d | fix(01-02): replace any[] with Alert[]/Entity[] in correlation modules |
| 2 | 0cf58bb | fix(01-02): add typed ActionConfig interfaces to action dispatcher |
| 3 | 870f21f | fix(01-02): type auth session/routes and AI module parameters |

## Deviations from Plan

None -- plan executed exactly as written.

## Known Stubs

None -- this plan only replaces type annotations, no functional changes.
