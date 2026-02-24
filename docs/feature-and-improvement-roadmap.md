# SecureNexus Codebase-Driven Upgrade Roadmap

This roadmap is derived from current client routes/pages, backend APIs, and schema capabilities, and focuses on **next upgrades** across product, UI/UX, platform, and data design.

## 1) What the Codebase Signals Right Now

- The app already exposes many advanced workspaces (Threat Intel, MITRE, Entity/Attack Graph, Predictive Defense, Autonomous Response, CSPM, Endpoint Telemetry).
- Core list pages currently rely on client-side filtering/search and all-record loading patterns.
- Settings includes role/plan presentation but not end-to-end role enforcement and lifecycle management.
- Command palette supports navigation + a few quick actions; it can become a high-throughput SOC command center.
- Backend has broad domain modules (correlation, enrichment, rollback, policies, posture) and is a good foundation for deeper production hardening.

## 2) Priority Upgrade Themes

### Theme A — Analyst Throughput (Immediate)
**Goal:** Reduce clicks/time per triage action.

Deliver:
1. Split-pane alert/incident workflow with right-side detail drawer.
2. Saved filters/views + share to team.
3. Bulk operations (assign/tag/status/escalate/suppress).
4. SLA timers and queue states (new, aging, breached).
5. Keyboard shortcut model for triage actions.

### Theme B — Automation Safety (Immediate)
**Goal:** Increase automation without losing analyst control.

Deliver:
1. Approval gates for response actions.
2. Dry-run simulation with predicted blast radius.
3. Rollback eligibility hints before execute.
4. Action-level cooldown/rate controls.
5. Action runbook audit timeline.

### Theme C — Governance + Multi-Tenancy (Near-Term)
**Goal:** Enterprise readiness.

Deliver:
1. RBAC tables + permission checks in routes.
2. Team/user lifecycle management.
3. Data retention policy editor + legal hold.
4. Audit integrity verification UI.
5. API key governance: scope templates + rotation cadence.

### Theme D — Scale & Reliability (Near-Term)
**Goal:** Handle larger SOC loads safely.

Deliver:
1. Server-side pagination/filter/sort endpoints.
2. Background queue for sync/enrichment/reports.
3. Idempotency keys and replay-safe ingestion.
4. Connector run history and retry/backoff transparency.
5. SLO dashboards for API/ingestion/AI.

### Theme E — AI Trust + Outcome Quality (Near-Term)
**Goal:** Improve analyst confidence and measurable value.

Deliver:
1. Explainability panel for triage/correlation outcomes.
2. In-workflow AI feedback (accept/reject/correct).
3. Drift and quality monitoring for model outputs.
4. AI-assisted runbook generation with human confirmation.
5. Root-cause synthesis using entity + graph correlation.

## 3) UI/UX Upgrade Backlog (Detailed)

### Navigation
- Add role-aware navigation visibility.
- Add favorites/pinned pages in sidebar.
- Add global “recently viewed” switcher.

### Table/List Experience
- Add pagination + column chooser + density options.
- Add sticky action bar on multi-select.
- Add “open in new panel” interaction for fast comparison.

### Detail Pages
- Add timeline components with actor + event-type badges.
- Add side-by-side raw/normalized/enriched evidence panels.
- Add one-click pivots to related entities/alerts/incidents.

### Forms
- Add draft autosave for complex forms.
- Add config linting before test/save.
- Add guided remediation when connector/integration tests fail.

### Accessibility
- Add full keyboard operability across major workflows.
- Add better semantic labeling for chart-heavy sections.
- Add contrast pass for key badges/alerts and status chips.

## 4) API & Data Contract Upgrades

1. Introduce `/v1` versioned API namespace.
2. Publish OpenAPI schema and generate typed frontend client.
3. Standardize response envelope (`data`, `meta`, `errors`).
4. Add cursor/offset pagination contract for list endpoints.
5. Add webhook subscription management endpoints.

## 5) Suggested Implementation Sequence

### Wave 1 (Weeks 1–3)
- Pagination + saved views + bulk actions.
- SLA tracking + queue presets.
- Command palette operational actions.

### Wave 2 (Weeks 4–6)
- RBAC schema + route guards.
- Approval workflows for autonomous response.
- Connector run history + retry observability.

### Wave 3 (Weeks 7–10)
- Background workers + idempotency keys.
- AI explainability + feedback analytics.
- API versioning + OpenAPI + typed SDK.

### Wave 4 (Weeks 11–12)
- Onboarding flows + usage metering.
- Executive reports and scheduled distribution.
- Audit integrity verification dashboard.

## 6) Metrics to Prove Upgrade Value

- MTTA/MTTR reduction.
- Alerts processed per analyst per day.
- False-positive suppression rate.
- Connector sync success/error budget.
- % actions executed with approval and successful rollback.
- Analyst satisfaction and command palette adoption.
