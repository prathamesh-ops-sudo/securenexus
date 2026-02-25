# Phase 14: Analytics and Metrics Detailed Report

## Goal
Deliver advanced SOC KPIs and trend analytics with drilldown into underlying records.

## What Must Be Fixed
- Current analytics lacks full KPI coverage and segmented historical views.

## Required Work
- Define and compute KPI set: MTTD, MTTA, MTTR, dwell time, reopen rate, false positive rate, SLA breach rate.
- Add metric snapshot pipeline and dashboard drilldowns.

## Data and API Scope
- Tables: `metric_definitions`, `metric_snapshots`.
- APIs: KPI overview, trends, segmentation, drilldown.

## UI Scope
- Analytics workspace with configurable widgets and period-over-period deltas.

## Testing
- Formula unit tests.
- Time-window boundary tests.

## Definition of Done
- KPIs are accurate, queryable, and actionable.
