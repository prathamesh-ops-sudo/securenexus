---
phase: "06"
plan: "03"
subsystem: alert-pipeline
tags: [stubs, database-queries, dashboard, job-queue, ingestion]
dependency_graph:
  requires: [06-01, 06-02]
  provides: [real-document-counts, real-dashboard-kpis, real-queue-metrics, real-ingestion-quality]
  affects: [server/routes/ai/context.ts, server/routes/phase2-routes.ts, server/routes/admin.ts, server/routes/ingestion.ts]
tech_stack:
  added: []
  patterns: [drizzle-count-queries, promise-all-parallel, per-source-aggregation]
key_files:
  created: []
  modified:
    - server/routes/ai/context.ts
    - server/routes/phase2-routes.ts
    - server/routes/admin.ts
    - server/routes/ingestion.ts
decisions:
  - "Computed Pending Reviews from incidents in investigating/open status using existing storage.getIncidents data"
  - "MTTD calculated from alert detectedAt-createdAt delta for today's alerts; returns 0 when no data"
  - "MTTR calculated from incident createdAt-resolvedAt delta for resolved incidents"
  - "Alert Coverage defined as active connectors / total connectors percentage"
  - "Job queue metrics query uses date_trunc hour bucketing with zero-fill for empty hours"
  - "Field extraction rate computed as alertsCreated/alertsReceived per source from ingestion_logs"
metrics:
  duration: "6min"
  completed: "2026-03-25"
  tasks_completed: 2
  tasks_total: 2
  files_modified: 4
---

# Phase 06 Plan 03: Stub Endpoint Elimination Summary

Replaced all HIGH and MEDIUM priority Math.random() stubs and hardcoded-zero KPIs across four route files with real database queries against existing tables.

## What Changed

### Task 1: AI Context-Optimization Real Document Counts (e146111)

Replaced `Math.floor(Math.random() * 20) + 1` on line 64 of `server/routes/ai/context.ts` with real count queries against alerts, incidents, entities, iocEntries, and endpointTelemetry tables. Queries run in parallel via `Promise.all`. Sources without backing tables (osint, ueba, network_flows, cloud_configs) return 0.

### Task 2: Dashboard KPIs, Queue Metrics, Ingestion Quality (c8cd8af)

**phase2-routes.ts (Dashboard Role):**
- "Pending Reviews" widget: real count of incidents in `investigating` or `open` status
- "Mean Time to Detect" KPI: average minutes between `detectedAt` and `createdAt` for today's alerts
- "Mean Time to Respond" KPI: average minutes between `createdAt` and `resolvedAt` for resolved incidents
- "Alert Coverage" KPI: percentage of active connectors vs total connectors

**admin.ts (Job Queue Metrics):**
- Replaced four Math.random() calls generating fake throughput, wait time, execution time, and failure rate
- Now queries `job_queue` table with `date_trunc('hour', completed_at)` for real hourly bucketed metrics
- Empty hours filled with zeros to maintain 24-bucket structure

**ingestion.ts (Data Quality):**
- Replaced `95 + Math.round(Math.random() * 5)` field extraction rate with real per-source calculation
- Queries `ingestion_logs` grouped by source to compute `alertsCreated / alertsReceived * 100`
- Quality classification: good (>=95%), degraded (>=80%), poor (<80%)

## Deviations from Plan

None -- plan executed exactly as written.

## Known Stubs

No stubs remain in the four modified files. All Math.random() stub calls and hardcoded-zero KPI values have been replaced with real database queries.

## Verification

- `grep -rn "Math.random" server/routes/ai/context.ts server/routes/phase2-routes.ts server/routes/admin.ts server/routes/ingestion.ts | grep -v "toString(36)" | grep -v "auto_"` -- zero matches
- `grep "value: 0" server/routes/phase2-routes.ts` -- zero matches for KPI/widget stubs
- `npx tsc --noEmit` -- no new errors in modified files (pre-existing errors in unrelated files only)

## Self-Check: PASSED

- All 4 modified files exist on disk
- Commit e146111 (task 1) found in git log
- Commit c8cd8af (task 2) found in git log
- SUMMARY.md created at .planning/phases/06-alert-pipeline-hardening/06-03-SUMMARY.md
