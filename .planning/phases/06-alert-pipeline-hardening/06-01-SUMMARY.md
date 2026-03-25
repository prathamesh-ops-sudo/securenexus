---
phase: 06-alert-pipeline-hardening
plan: 01
subsystem: api
tags: [deduplication, alerts, ingestion, drizzle, temporal-window]

# Dependency graph
requires:
  - phase: 03-god-file-decomposition
    provides: alerts.ts storage module split from monolithic storage.ts
provides:
  - Temporal alert deduplication with configurable time window
  - occurrenceCount and lastSeenAt columns on alerts table
  - isDuplicate return field from upsertAlert for caller awareness
  - "deduped" alert status in ALERT_STATUSES enum
affects: [alert-pipeline-hardening, connector-engine, correlation-engine]

# Tech tracking
tech-stack:
  added: []
  patterns: [temporal-dedup-window, upsert-with-coalesce-increment]

key-files:
  created:
    - server/__tests__/dedup.test.ts
  modified:
    - shared/schema.ts
    - server/storage/alerts.ts
    - server/storage/types.ts
    - server/routes/ingestion.ts

key-decisions:
  - "Used COALESCE(occurrence_count, 1) + 1 SQL pattern to handle existing rows with null occurrenceCount"
  - "Default dedup window is 60 minutes, configurable per-call via dedupWindowMinutes parameter"
  - "Alerts outside dedup window with same sourceEventId create new records (not updates)"

patterns-established:
  - "Temporal dedup: compare ingestedAt/createdAt against configurable cutoff window before deciding update vs insert"
  - "Return isDuplicate alongside isNew for callers that need to distinguish dedup-hit from first-seen-but-existing"

requirements-completed: [DEDUP-01]

# Metrics
duration: 5min
completed: 2026-03-25
---

# Phase 06 Plan 01: Temporal Alert Deduplication Summary

**Temporal dedup with configurable 60min window using COALESCE increment on occurrenceCount, wired into single and bulk ingestion routes**

## Performance

- **Duration:** 5 min
- **Started:** 2026-03-25T13:24:15Z
- **Completed:** 2026-03-25T13:29:31Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments
- Added occurrenceCount and lastSeenAt columns to alerts and alertsArchive schema tables
- Implemented temporal dedup in upsertAlert: duplicates within configurable window update existing record instead of creating new ones
- Wired isDuplicate and occurrenceCount into single and bulk ingestion API responses
- 6 unit tests covering all dedup behaviors pass

## Task Commits

Each task was committed atomically:

1. **Task 1: Schema migration + temporal dedup logic with tests** - `b3cc78a` (feat)
2. **Task 2: Wire temporal dedup into ingestion routes** - `bca023f` (feat)

## Files Created/Modified
- `shared/schema.ts` - Added occurrenceCount, lastSeenAt columns to alerts and alertsArchive; added "deduped" to ALERT_STATUSES
- `server/storage/alerts.ts` - Temporal dedup logic in upsertAlert with configurable dedupWindowMinutes parameter
- `server/storage/types.ts` - Updated IStorage interface for new upsertAlert signature
- `server/routes/ingestion.ts` - Updated single and bulk ingestion to use isDuplicate and return occurrenceCount
- `server/__tests__/dedup.test.ts` - 6 unit tests for temporal dedup behaviors

## Decisions Made
- Used COALESCE(occurrence_count, 1) + 1 SQL pattern to safely increment even for existing rows with null occurrenceCount
- Default dedup window is 60 minutes, configurable per-call to support different connector cadences
- Alerts outside the dedup window with the same sourceEventId create new records rather than updating old ones -- this preserves the ability to track alert recurrence patterns over time

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical] Updated IStorage interface type**
- **Found during:** Task 2 (ingestion route wiring)
- **Issue:** storage/types.ts had the old upsertAlert signature without isDuplicate and dedupWindowMinutes
- **Fix:** Updated interface to match new implementation signature
- **Files modified:** server/storage/types.ts
- **Verification:** npx tsc --noEmit shows zero errors in changed files
- **Committed in:** bca023f (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (1 missing critical)
**Impact on plan:** Type interface update was necessary for correctness. No scope creep.

## Issues Encountered
- Husky pre-commit hook has exec format error on Windows (pre-existing infrastructure issue, not related to changes)
- Pre-existing TypeScript errors in ai.ts and test fixtures are unrelated to this plan's changes

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Temporal dedup is wired into all ingestion paths
- Connector engine callers (job-queue.ts, connectors.ts) use Promise.allSettled and don't destructure the result, so they work without changes
- Ready for 06-02 (alert suppression rules) and 06-03 (connector health checks)

---
*Phase: 06-alert-pipeline-hardening*
*Completed: 2026-03-25*
