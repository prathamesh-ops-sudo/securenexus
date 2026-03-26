---
phase: "06"
plan: "02"
subsystem: alert-pipeline
tags: [suppression, ingestion, dashboard, dedup-metrics]
dependency_graph:
  requires: []
  provides: [suppression-engine, suppression-evaluation, dashboard-dedup-metrics]
  affects: [ingestion-pipeline, compliance-routes, dashboard-stats]
tech_stack:
  added: []
  patterns: [first-match-short-circuit, matcher-condition-evaluation, expiry-enforcement]
key_files:
  created:
    - server/suppression-engine.ts
    - server/__tests__/suppression.test.ts
  modified:
    - server/storage/misc.ts
    - server/routes/ingestion.ts
    - server/routes/compliance.ts
    - server/storage/dashboard.ts
decisions:
  - "First-match short-circuit: evaluateSuppression returns on first matching rule, does not evaluate further"
  - "Suppressed alerts stored via createAlert (not upsert) to avoid dedup logic, marked suppressed=true"
  - "Expiry defaults to 7 days if not provided, max 30 days enforced on both create and update"
  - "Regex validation happens at CRUD time (fail fast) and at evaluation time (fail safe with warning)"
metrics:
  duration: "6min"
  completed: "2026-03-25"
  tasks_completed: 2
  tasks_total: 2
  files_changed: 6
---

# Phase 06 Plan 02: Suppression Rules Engine Summary

Suppression engine with source/severity/regex matcher evaluation, 30-day max expiry enforcement, and dashboard dedup/suppression metrics.

## What Was Done

### Task 1: Suppression engine + active rules query + unit tests (TDD)

Created `server/suppression-engine.ts` with `evaluateSuppression()` that fetches active rules for the org and applies first-match short-circuit evaluation. Rules can match by source, severity, category, or matcher conditions (eq, contains, regex with AND logic). Invalid regex patterns are caught and logged as warnings without throwing.

Added `getActiveSuppressionRules(orgId)` to `server/storage/misc.ts` that filters by `enabled=true` and `expiresAt > NOW()` (or null). Added `incrementSuppressionMatchCount(ruleId)` to track match counts.

8 unit tests covering: source match, severity match, regex match, no match, expired rules, disabled rules, invalid regex safety, and first-match short-circuit.

**Commit:** ccb8b4b

### Task 2: Wire suppression into ingestion + expiry validation + dashboard metrics

Wired `evaluateSuppression` into both single (`/api/ingest/:source`) and bulk (`/api/ingest/:source/bulk`) ingestion handlers. Suppressed alerts are stored via `createAlert` (bypassing upsert/dedup) with `suppressed=true`, `suppressedBy="rule"`, and `suppressionRuleId` set. Suppressed alerts skip entity resolution and correlation.

Added expiry validation to suppression rule CRUD in compliance routes: max 30 days, default 7 days. Added regex pattern validation on matcher conditions at create/update time.

Added `alertsDeduplicatedToday` and `alertsSuppressedToday` counts to `getDashboardStats` in `server/storage/dashboard.ts`.

**Commit:** 63b2adf

## Deviations from Plan

None - plan executed exactly as written.

## Decisions Made

1. **First-match evaluation**: Returns on first matching rule for performance; rules ordered by createdAt DESC (newest first).
2. **Suppressed alerts bypass upsert**: Use `createAlert` directly so suppressed alerts don't trigger dedup logic or update occurrence counts.
3. **Dual regex validation**: Validated at CRUD time (400 error) and at evaluation time (log warning, return false) for defense in depth.
4. **Logger import fix**: Used named import `{ logger }` instead of default import per project convention (Rule 1 auto-fix).

## Known Stubs

None - all functionality is fully wired with real data queries.

## Verification Results

- 8/8 suppression unit tests pass
- Zero type errors in modified files (pre-existing errors in ai.ts/action-dispatcher.ts are out of scope)
- `evaluateSuppression` called in both single and bulk ingestion handlers
- `MAX_SUPPRESSION_DAYS=30` and `DEFAULT_SUPPRESSION_DAYS=7` enforced in compliance routes
- `alertsDeduplicatedToday` and `alertsSuppressedToday` present in dashboard stats

## Self-Check: PASSED

All 6 files found. Both commits (ccb8b4b, 63b2adf) verified.
