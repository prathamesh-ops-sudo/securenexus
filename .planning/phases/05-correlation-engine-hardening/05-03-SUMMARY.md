---
phase: 05-correlation-engine-hardening
plan: 03
subsystem: testing, ui
tags: [vitest, correlation, integration-test, confidence-badge, tooltip, mitre-attack]

requires:
  - phase: 05-01
    provides: "AlgorithmScore/AggregatedScore types, needsReview/algorithmScores schema columns"
  - phase: 05-02
    provides: "Transaction-wrapped correlation writes, aggregator wiring"
provides:
  - "12-alert lateral movement campaign integration test fixture"
  - "Full correlation pipeline integration test suite (7 test cases)"
  - "ConfidenceBadge component with color thresholds and algorithm tooltip"
  - "Needs Review filter on incidents list page"
affects: [06-alert-pipeline, ui-testing]

tech-stack:
  added: []
  patterns: ["Entity relationship map builder for realistic correlation mocking", "TooltipProvider pattern for badge hover details"]

key-files:
  created:
    - server/__tests__/fixtures/correlation/scenario-lateral-movement.ts
    - server/__tests__/correlation-integration.test.ts
  modified:
    - client/src/pages/incident-detail.tsx
    - client/src/pages/incidents.tsx

key-decisions:
  - "Used transaction mock proxy pattern to test db.transaction callbacks without real DB"
  - "ConfidenceBadge defined inline in incident-detail.tsx rather than separate component file (small, page-specific)"
  - "Used (incident as any).needsReview in incidents.tsx for type access since Incident type already includes needsReview from schema"

patterns-established:
  - "Entity relationship map builder: buildEntityRelationMap() for realistic multi-source correlation test scenarios"
  - "Transaction proxy mock pattern for db.transaction in vitest"

requirements-completed: [CORR-03, CORR-06]

duration: 6min
completed: 2026-03-25
---

# Phase 5 Plan 3: Correlation Integration Tests & Confidence UI Summary

**12-alert lateral movement integration test across CrowdStrike/Splunk/GuardDuty with color-coded confidence badges and algorithm-score tooltips on incident pages**

## Performance

- **Duration:** 6 min
- **Started:** 2026-03-25T12:44:28Z
- **Completed:** 2026-03-25T12:50:55Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments
- Integration test suite with 7 test cases validating correlation pipeline: lateral movement campaign, cross-org isolation, uncorrelated alerts, multi-source clustering
- 12-alert lateral movement campaign fixture spanning 6 MITRE ATT&CK tactics across 3 security tool sources
- ConfidenceBadge component with green (>75%), yellow (50-75%), red (<50%) color coding and per-algorithm tooltip breakdown
- "Needs Review" filter toggle and badge on incidents list page

## Task Commits

Each task was committed atomically:

1. **Task 1: Create lateral movement scenario fixture and integration test** - `1c7c0c7` (test)
2. **Task 2: Add confidence badge with tooltip and Review badge to incident UI** - `7ddf752` (feat)

## Files Created/Modified
- `server/__tests__/fixtures/correlation/scenario-lateral-movement.ts` - 12-alert lateral movement campaign fixture with entity links and expected grouping
- `server/__tests__/correlation-integration.test.ts` - 7 integration test cases for correlation pipeline
- `client/src/pages/incident-detail.tsx` - ConfidenceBadge with color thresholds, algorithm tooltip, Review badge
- `client/src/pages/incidents.tsx` - Review badge on list rows, Needs Review filter, confidence percentage inline

## Decisions Made
- Used transaction mock proxy to test db.transaction callbacks without requiring real database connection
- Defined ConfidenceBadge inline in incident-detail.tsx rather than as a separate component file (small, page-specific)
- Used buildEntityRelationMap() to derive realistic entity relationships from the scenario fixture data

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Added db.transaction mock to test setup**
- **Found during:** Task 1 (integration test)
- **Issue:** correlation-engine.ts was updated in Plan 02 to use db.transaction(), but the mock didn't include a transaction method
- **Fix:** Added transaction proxy mock that captures the callback and provides insert/update chain mocks
- **Files modified:** server/__tests__/correlation-integration.test.ts
- **Verification:** All 7 tests pass
- **Committed in:** 1c7c0c7 (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** Auto-fix necessary to match Plan 02's transaction refactoring. No scope creep.

## Issues Encountered
None beyond the transaction mock deviation.

## Known Stubs
None - all data flows are wired to schema fields added in Plan 01.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Correlation engine now has integration test coverage and visible confidence scoring in UI
- Ready for Phase 6 (alert pipeline) work
- Future plans may want to add real-DB integration tests behind DATABASE_URL guard

---
*Phase: 05-correlation-engine-hardening*
*Completed: 2026-03-25*
