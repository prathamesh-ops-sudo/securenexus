---
phase: 09-api-resilience-performance
plan: 03
subsystem: ai-triage, job-queue, event-bus, db-performance
tags: [async-triage, 202-accepted, job-queue, performance-budgets, sse]
dependency_graph:
  requires: [09-02]
  provides: [async-triage-endpoint, ai-triage-job-handler, ai-performance-budgets]
  affects: [ai-routes, job-queue-handlers, sse-events]
tech_stack:
  added: [supertest]
  patterns: [async-job-queue, 202-accepted-pattern, poll-for-result]
key_files:
  created:
    - server/__tests__/async-triage.test.ts
    - server/__tests__/ai-perf-budgets.test.ts
  modified:
    - server/routes/ai/triage.ts
    - server/job-queue.ts
    - server/event-bus.ts
    - server/db-performance.ts
decisions:
  - Exported getAiTriageHandler() from triage.ts for direct testing and registration in JOB_HANDLERS via dynamic import
  - Job handler uses dynamic import for ai.ts and event-bus.ts to avoid circular dependency issues
  - Dedup handling returns 202 with null jobId and message when triage already queued
metrics:
  duration: 5min
  completed: 2026-03-26
  tasks: 2
  files: 6
  tests: 18
---

# Phase 9 Plan 3: Async AI Triage & Performance Budgets Summary

Converted AI triage from synchronous to async 202-Accepted flow with job queue polling and SSE notification; added performance budgets for all AI endpoints.

## Task Completion

| Task | Name | Commit | Key Changes |
|------|------|--------|-------------|
| 1 | Async triage endpoint with job queue handler and SSE notification | cbc2fcc, 18f0838 | POST returns 202 with jobId/pollUrl, GET polling endpoint, ai_triage job handler with SSE broadcast |
| 2 | AI endpoint performance budgets | cb3a256 | 5 AI endpoint budgets in PERFORMANCE_BUDGETS, 6 tests |

## Changes Made

### Task 1: Async Triage Endpoint

- **server/routes/ai/triage.ts**: Converted `POST /api/ai/triage/:alertId` from synchronous (calling triageAlert inline) to async (enqueuing `ai_triage` job via `enqueueJob`, returning 202 with `{ jobId, status, pollUrl }`). Added `GET /api/ai/triage/jobs/:jobId` polling endpoint that returns job status (pending/completed/failed) with org isolation check. Exported `getAiTriageHandler()` for the job worker.
- **server/job-queue.ts**: Registered `ai_triage` handler in `JOB_HANDLERS` that delegates to `getAiTriageHandler()` via dynamic import.
- **server/event-bus.ts**: Added `"ai:triage_complete"` to the `EventType` union type.
- **server/__tests__/async-triage.test.ts**: 12 tests covering 202 response shape, 404 for missing/wrong-org alerts, polling endpoint for all states (pending/completed/failed/not-found/wrong-org), job handler execution, SSE broadcast, and error handling.

### Task 2: AI Performance Budgets

- **server/db-performance.ts**: Added 5 AI endpoint entries to `PERFORMANCE_BUDGETS`: triage (1500ms prod), narrative (2000ms), correlate (2000ms), investigate (2000ms), and job polling (300ms).
- **server/__tests__/ai-perf-budgets.test.ts**: 6 tests verifying budget definitions and constraints.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed job.error type error**
- **Found during:** Task 1 verification (tsc --noEmit)
- **Issue:** Job type has `lastError` not `error` field; code referenced `job.error` which doesn't exist on the type
- **Fix:** Changed to use `job.lastError` only
- **Files modified:** server/routes/ai/triage.ts
- **Commit:** 18f0838

## Known Stubs

None -- all endpoints are fully wired to the job queue and return real data.

## Verification Results

- 18/18 tests passing (12 async-triage + 6 ai-perf-budgets)
- TypeScript: no errors in modified files (pre-existing errors in ai.ts, auth/routes.ts, connector-health-loop.ts are out of scope)
- EventType includes "ai:triage_complete"
- JOB_HANDLERS includes ai_triage handler
- POST /api/ai/triage/:alertId returns 202
- GET /api/ai/triage/jobs/:jobId endpoint exists
- PERFORMANCE_BUDGETS includes all 5 AI endpoint entries

## Self-Check: PASSED

All 6 files found on disk. All 3 commit hashes verified in git log.
