# Phase 14: Analytics and Metrics Detailed Implementation Report

## Objective
Provide advanced SOC KPIs and trend intelligence with consistent formulas and record-level drilldowns.

## Current Baseline
- Basic dashboard analytics exist.

## Critical Gaps
- KPI coverage is limited.
- Historical segmentation and drilldown depth are limited.

## Required Fixes
- Define KPI formulas (MTTD, MTTA, MTTR, dwell time, reopen rate, false positive rate, SLA breach rate).
- Build metrics snapshot pipeline.
- Build segmented trend endpoints and drilldown queries.

## Data Model
- `metric_definitions`
- `metric_snapshots`

## API Plan
- `GET /api/metrics/kpis`
- `GET /api/metrics/trends`
- `GET /api/metrics/segments`
- `GET /api/metrics/drilldown`

## UI Plan
- KPI board with period deltas.
- Trend charts with filter controls.
- Drilldown drawers.

## Testing
- Formula correctness tests.
- Time-window boundary tests.
- Drilldown query tests.

## Definition of Done
- KPI outputs are trusted and actionable for operations and leadership.
