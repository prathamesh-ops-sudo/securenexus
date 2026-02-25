# Phase 14: Analytics and Metrics Detailed Implementation Report

## 1. Executive Summary
Phase 14 expands SOC analytics from basic visualizations to decision-grade operational intelligence, including performance KPIs, trend diagnostics, and comparative benchmarking.

## 2. Objectives
- Calculate advanced SOC KPIs with consistent definitions.
- Provide segmented and trend-based analytics.
- Enable drill-down from metric to underlying incidents/alerts.

## 3. Baseline
- Dashboard contains basic charts and MTTR metric.
- Missing full KPI suite and historical snapshot strategy.

## 4. KPI Definitions
- MTTD: detection time from first event to alert creation.
- MTTA: assignment time from incident open to analyst ownership.
- MTTR: resolution time from incident open to resolved.
- Dwell time: attacker presence estimate window.
- Reopen rate, false positive rate, and SLA breach rate.

## 5. Data Model
- `metric_snapshots`
- `id`, `orgId`, `windowStart`, `windowEnd`, `metricKey`, `metricValue`, `segmentKey`, `segmentValue`, `computedAt`.
- `metric_definitions`
- source of truth for formula metadata.

## 6. Computation Pipeline
- Nightly batch for stable metrics.
- Intra-day incremental refresh for operational panels.
- Validation job compares computed outputs against sanity thresholds.

## 7. API Endpoints
- `GET /api/metrics/kpis`
- `GET /api/metrics/trends`
- `GET /api/metrics/segments`
- `GET /api/metrics/drilldown`

## 8. UI/UX
- Analytics workspace with widget grid.
- KPI cards with period-over-period delta.
- Drilldown drawer from chart points to records.
- Filter bar: time range, severity, source, analyst, tenant.

## 9. Governance
- KPI formulas documented and versioned.
- Metric computation changes tracked in release notes.

## 10. Testing
- Formula unit tests with deterministic fixtures.
- Time-window boundary tests.
- UI snapshot tests for trend rendering.

## 11. Definition of Done
- KPI endpoints stable and accurate.
- Advanced dashboard visible and filterable.
- Drilldown links metrics to source records.
