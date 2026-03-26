---
phase: 09-api-resilience-performance
plan: 01
subsystem: api-middleware, entity-resolver
tags: [circuit-breaker, caching, resilience, performance]
dependency_graph:
  requires: []
  provides: [pool-circuit-breaker-middleware, entity-graph-caching]
  affects: [server/index.ts, server/entity-resolver.ts]
tech_stack:
  added: []
  patterns: [circuit-breaker, cache-aside-with-event-invalidation, inflight-dedup]
key_files:
  created:
    - server/middleware/pool-circuit-breaker.ts
    - server/__tests__/pool-circuit-breaker.test.ts
    - server/__tests__/entity-cache.test.ts
  modified:
    - server/index.ts
    - server/entity-resolver.ts
decisions:
  - Used module-level cached utilization with 1s refresh to avoid calling getPoolHealth on every request
  - Tenant-scoped cache keys using orgId prefix before hash for entity graph queries
  - Invalidate all entity-graph entries for an orgId on entity:resolved events (prefix-based)
  - Added optional orgId parameter to getEntitiesForAlert/getEntitiesForIncident (backward compatible)
  - Added _resetPoolCircuitBreakerCache test helper for deterministic test isolation
metrics:
  duration: 5min
  completed: "2026-03-26"
  tasks: 2
  files: 5
  tests_added: 12
---

# Phase 9 Plan 1: Pool Circuit Breaker & Entity Graph Caching Summary

Pool circuit breaker middleware returns 503 with Retry-After when DB pool utilization exceeds 80%, plus entity graph caching with 5-minute TTL and event-driven invalidation on entity:resolved events.

## Task Execution

### Task 1: Pool Circuit Breaker Middleware (TDD)

**Commit:** e4cd80e

Created `server/middleware/pool-circuit-breaker.ts` - Express middleware that:
- Checks pool utilization every 1 second (cached to avoid per-request overhead)
- Returns 503 with `Retry-After: 5` header and JSON body when utilization >= 80%
- Exempts `/api/health`, `/api/metrics`, `/api/ops/health`, `/api/ops/metrics` paths
- Logs rejected requests at warn level with orgId and path context

Registered in `server/index.ts` after `inFlightMiddleware` and before `requestTimeoutMiddleware`.

**Tests:** 7 tests covering normal pass-through, 503 rejection, path exemptions, cache refresh timing, and high utilization scenarios.

### Task 2: Entity Graph Caching with Event-Driven Invalidation (TDD)

**Commit:** 13aeec8

Modified `server/entity-resolver.ts` to:
- Wrap `getEntitiesForAlert` and `getEntitiesForIncident` with `cacheGetOrLoad` using `CACHE_TTL.ENTITY_GRAPH` (5 minutes)
- Use tenant-scoped cache keys: `entity-graph:{orgId}:alert:{alertId}` and `entity-graph:{orgId}:incident:{incidentId}`
- Register `eventBus.on("entity:resolved")` listener that invalidates all entity-graph cache entries for the affected orgId
- Added optional `orgId` parameter to both functions (backward compatible with existing callers)

The `cacheGetOrLoad` from `query-cache.ts` provides built-in inflight request deduplication, preventing thundering herd when multiple concurrent requests target the same entity graph.

**Tests:** 5 tests covering cache hits, TTL behavior, event-driven invalidation, tenant isolation, and concurrent request dedup.

## Deviations from Plan

None - plan executed exactly as written.

## Verification Results

- 12/12 tests pass across both suites
- No type errors introduced (pre-existing errors in ai.ts, auth/routes.ts, connector-health-loop.ts are out of scope)
- Pool circuit breaker middleware imported and registered in server/index.ts
- Entity resolver imports cacheGetOrLoad and CACHE_TTL from query-cache

## Known Stubs

None.

## Self-Check: PASSED
