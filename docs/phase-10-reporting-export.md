# Phase 10: Reporting and Export Detailed Report

## Goal
Deliver scheduled and on-demand SOC reporting with CSV/JSON/PDF outputs.

## What Must Be Fixed
- Export routes are incomplete.
- No template-based report generation or scheduling.

## Required Work
- Create report templates for incidents, SLA, MITRE, connector health, analyst productivity.
- Add asynchronous report runner and run history.
- Add scheduled delivery (email/S3).

## Data and API Scope
- Tables: `reports`, `report_runs`, `report_schedules`.
- APIs: create/update/list report, run report, download artifact, schedule report.

## UI Scope
- Report builder, run history, schedule manager.

## Security
- Signed expiring download URLs.
- Tenant-safe query enforcement.

## Testing
- Format conformance tests for CSV/JSON/PDF.

## Definition of Done
- Reports are reliable, permission-safe, and production usable.
