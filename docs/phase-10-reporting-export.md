# Phase 10: Reporting and Export Detailed Implementation Report

## 1. Executive Summary
Phase 10 must deliver enterprise-grade reporting with repeatable templates, scheduled distribution, and trustworthy data exports for governance and executive communication.

## 2. Objectives
- Create reusable report templates across SOC operations.
- Support export to CSV, JSON, and PDF.
- Add schedule and delivery automation (email/S3).
- Ensure tenant-safe and permission-checked report access.

## 3. Baseline
- Route placeholders exist in `server/routes.ts`.
- No complete report generation pipeline currently deployed.

## 4. Report Catalog
- Incident summary report.
- SLA and MTTR performance report.
- MITRE coverage report.
- Connector reliability report.
- Analyst productivity and queue aging report.

## 5. Data Model
- `reports`
- `id`, `orgId`, `name`, `type`, `filtersJson`, `columnsJson`, `createdBy`, `createdAt`, `updatedAt`.
- `report_runs`
- `id`, `reportId`, `orgId`, `status`, `requestedBy`, `outputType`, `outputLocation`, `startedAt`, `completedAt`, `error`.
- `report_schedules`
- `id`, `reportId`, `orgId`, `cronExpr`, `deliveryType`, `deliveryConfig`, `isActive`, `lastRunAt`.

## 6. API Design
- `POST /api/reports`
- `GET /api/reports`
- `GET /api/reports/:id`
- `PATCH /api/reports/:id`
- `POST /api/reports/:id/run`
- `GET /api/reports/runs/:runId`
- `GET /api/reports/runs/:runId/download`
- `POST /api/reports/:id/schedule`

## 7. Generation Engine
- Async report execution queue.
- Pagination-safe dataset extraction.
- Deterministic output rendering by schema.
- PDF template engine with branded sections.

## 8. UI/UX
- Reports page with template gallery.
- Builder UI for filters and columns.
- Run history with status and duration.
- Download actions with expiration.

## 9. Security and Compliance
- Signed short-lived download URLs.
- Org scope enforcement in report queries.
- Redaction options for sensitive fields.

## 10. Testing
- Snapshot validation for output schemas.
- Export format conformance tests.
- Permission tests for cross-tenant access.

## 11. Definition of Done
- Reports can be created, run, scheduled, and downloaded.
- Outputs are accurate and tenant-safe.
- PDF exports are stable for executive use.
