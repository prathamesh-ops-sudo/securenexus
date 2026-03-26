---
phase: 09-api-resilience-performance
plan: 02
subsystem: ai-engine, ai-routes
tags: [ai-fallback, token-budget, graceful-degradation, resilience]
dependency_graph:
  requires: [09-01]
  provides: [withAiFallback, buildBudgetedNarrativeMessage]
  affects: [ai-triage-routes, ai-narrative-routes, ai-investigation-routes]
tech_stack:
  added: []
  patterns: [stale-cache-serve, severity-based-packing, token-budget-enforcement]
key_files:
  created:
    - server/ai/fallback.ts
    - server/ai/narrative-budget.ts
    - server/__tests__/ai-fallback.test.ts
    - server/__tests__/token-budget.test.ts
  modified:
    - server/ai.ts
    - server/routes/ai/triage.ts
    - server/routes/ai/narrative.ts
    - server/routes/ai/investigation.ts
decisions:
  - Separate narrative-budget.ts module for testability rather than inline in ai.ts
  - 30% budget cap for threat intel block to preserve alert space
  - Date.now() in cache keys for threat-hunt/attack-path to avoid stale hunt results
metrics:
  duration: 8min
  completed: "2026-03-26T07:07:00Z"
---

# Phase 09 Plan 02: AI Graceful Degradation & Token Budget Summary

AI fallback wrapper with stale-cache-serve pattern and token-budget-enforced narrative generation with severity-based alert packing

## What Was Done

### Task 1: AI Fallback Wrapper (6c535fd)

Created `server/ai/fallback.ts` with `withAiFallback<T>` generic wrapper that:
- Returns `{ data, source: "live" }` on successful AI calls and caches results
- Returns `{ data, source: "cached", cachedAt }` when all model circuits are open and cache has entry
- Returns `{ data: null, source: "unavailable" }` when circuits open and no cache
- Falls back to cached results on AI call errors even when circuit isn't explicitly open
- LRU eviction at 500 entries

Wrapped all AI route handlers:
- `POST /api/ai/triage/:alertId` -- returns 503 with `{ status: "ai_unavailable" }` when no cache
- `POST /api/ai/correlate` -- correlation wrapped with composite cache key
- `POST /api/ai/narrative/:incidentId` -- narrative wrapped
- `POST /api/ai/deep-investigation/:incidentId` -- investigation wrapped
- `POST /api/ai/threat-hunt` -- threat hunt wrapped
- `POST /api/ai/behavioral-analysis` -- behavioral analysis wrapped
- `POST /api/ai/predict-attack-paths` -- attack path prediction wrapped
- `POST /api/ai/investigation/:incidentId/chat` -- chat investigation wrapped

### Task 2: Token Budget Enforcement (a7af68a)

Created `server/ai/narrative-budget.ts` with `buildBudgetedNarrativeMessage` that:
- Sorts alerts by severity (critical > high > medium > low > informational)
- Packs alert JSON within `maxInputTokens - responseReservation` budget
- Reserves 2048 tokens for response generation
- Includes threat intel block only if it fits within 30% of budget
- Tracks and logs truncation counts

Modified `generateIncidentNarrative` in `server/ai.ts` to use budgeted builder with 6144 max input / 2048 response reservation.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Fixed implicit any type for threatIntelCtx in investigation.ts**
- **Found during:** Task 1 route wrapping
- **Issue:** `let threatIntelCtx` had no type annotation, causing TS7034 when used inside withAiFallback closure
- **Fix:** Added explicit type `Awaited<ReturnType<typeof buildThreatIntelContext>> | undefined`
- **Files modified:** server/routes/ai/investigation.ts
- **Commit:** a7af68a

## Test Results

- `server/__tests__/ai-fallback.test.ts`: 9 tests passed
- `server/__tests__/token-budget.test.ts`: 8 tests passed
- Total: 17/17 tests passing

## Known Stubs

None -- all functionality is wired to real circuit breaker status and token counting.

## Self-Check: PASSED
