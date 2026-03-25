---
phase: 05-correlation-engine-hardening
plan: 02
subsystem: database, testing
tags: [drizzle, transactions, isolation-levels, vitest, correlation, serializable, retry]

requires:
  - phase: 05-01
    provides: "correlation-aggregator.ts with weighted voting, TypedGraphNode types, needsReview/algorithmScores schema columns"
provides:
  - "Transaction-wrapped correlation writes with repeatable read and serializable isolation"
  - "Serialization failure retry logic (code 40001) for promoteClusterToIncident"
  - "Aggregator wired into correlation pipeline"
  - "Test fixtures: alert factories (CrowdStrike, Splunk, GuardDuty) and entity factories (IP, host, user)"
  - "Unit tests for all three correlation algorithms (temporal+entity, graph, physical)"
affects: [correlation-integration-tests, incident-creation, alert-pipeline]

tech-stack:
  added: []
  patterns:
    - "db.transaction with isolationLevel option for critical write paths"
    - "Serialization failure retry with exponential backoff and jitter for serializable transactions"
    - "Alert/entity factory functions in __tests__/fixtures/correlation/ for reusable test data"

key-files:
  created:
    - "server/__tests__/fixtures/correlation/alert-factories.ts"
    - "server/__tests__/fixtures/correlation/entity-factories.ts"
    - "server/__tests__/graph-correlation.test.ts"
    - "server/__tests__/physical-correlation.test.ts"
  modified:
    - "server/correlation-engine.ts"
    - "server/graph-correlation.ts"
    - "server/__tests__/correlation-engine.test.ts"

key-decisions:
  - "Used repeatable read (not serializable) for correlateAlert and runGraphCorrelation to minimize lock contention"
  - "Reserved serializable isolation only for promoteClusterToIncident where race conditions could create duplicate incidents"
  - "3-attempt retry with exponential backoff + jitter for serialization failures (code 40001)"
  - "Added algorithmScore to CorrelationResult interface so callers can pass scores downstream"

patterns-established:
  - "Transaction pattern: read-only logic outside tx, writes inside tx with isolationLevel"
  - "Retry pattern: for/try/catch loop with pg error code 40001 check and jitter delay"
  - "Test factory pattern: makeXxxAlert/makeXxxEntity with Partial<T> overrides in fixtures/"

requirements-completed: [CORR-01, CORR-04]

duration: 8min
completed: 2026-03-25
---

# Phase 5 Plan 2: Transaction Safety and Correlation Unit Tests Summary

**Transaction-wrapped correlation writes with repeatable read/serializable isolation, plus 23 unit tests across all three correlation algorithms with shared test fixtures**

## Performance

- **Duration:** 8 min
- **Started:** 2026-03-25T12:44:43Z
- **Completed:** 2026-03-25T12:52:46Z
- **Tasks:** 2
- **Files modified:** 7

## Accomplishments
- All correlation cluster creation and alert updates wrapped in database transactions with appropriate isolation levels
- promoteClusterToIncident uses serializable isolation with 3-attempt retry on code 40001 for race condition safety
- Aggregator wired into pipeline: buildAlgorithmScore called in correlateAlert, AggregatedScore accepted by promoteClusterToIncident
- Test fixtures provide reusable factory functions for CrowdStrike, Splunk, GuardDuty alerts and IP/host/user entities
- 23 unit tests across 3 test files, all passing: temporal+entity (9 tests), graph (7 tests), physical (7 tests)

## Task Commits

Each task was committed atomically:

1. **Task 1: Wrap correlation writes in transactions and wire aggregator** - `69d5008` (feat)
2. **Task 2: Create test fixtures and unit tests for all three correlation algorithms** - `679771f` (test)

## Files Created/Modified
- `server/correlation-engine.ts` - Transaction-wrapped correlateAlert (repeatable read) and promoteClusterToIncident (serializable with retry), aggregator integration
- `server/graph-correlation.ts` - Transaction-wrapped runGraphCorrelation writes (repeatable read), added logger import
- `server/__tests__/correlation-engine.test.ts` - Expanded with transaction verification, algorithmScore, serializable retry, aggregatedScore tests
- `server/__tests__/graph-correlation.test.ts` - New: computePathConfidence, findAttackPaths, generateCampaignFingerprint tests
- `server/__tests__/physical-correlation.test.ts` - New: BUILT_IN_RULES validation, after-hours correlation, tailgate, impossible travel tests
- `server/__tests__/fixtures/correlation/alert-factories.ts` - New: makeCrowdStrikeAlert, makeSplunkAlert, makeGuardDutyAlert, makeBaseAlert
- `server/__tests__/fixtures/correlation/entity-factories.ts` - New: makeIPEntity, makeHostEntity, makeUserEntity

## Decisions Made
- Used repeatable read for correlateAlert and graph correlation writes since concurrent correlation of different alerts rarely touches the same rows, and serializable would cause excessive retries
- Reserved serializable isolation only for promoteClusterToIncident where two clusters could race to create overlapping incidents
- Added algorithmScore field to CorrelationResult interface to flow temporal+entity scores downstream without breaking existing callers (optional field)
- Mocked db.transaction in tests by executing the callback with a local tx object, verifying isolationLevel via the second argument

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
- Physical correlation test for after-hours badge events initially failed because the mock did not account for the digital alerts query using a different chain (where -> limit, no orderBy) than the badge events query (where -> orderBy -> limit). Fixed by providing both `orderBy` and `limit` on the mock's where return value.

## Known Stubs
None - all code is fully functional, no placeholder data or stubs.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Transaction-safe correlation engine ready for integration testing (Plan 03)
- Test fixtures in place and reusable for integration test scenarios
- Aggregator integration enables Plan 03 to test full multi-algorithm scoring pipeline

---
*Phase: 05-correlation-engine-hardening*
*Completed: 2026-03-25*
