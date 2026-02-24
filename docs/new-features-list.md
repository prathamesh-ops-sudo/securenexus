# SecureNexus Upgrade List — New Features, UI/UX, and System Changes

This list is based on the current codebase structure and app surface and is focused on **what to add next** (not what is already implemented).

## A) New Features to Add (Product)

### 1) SOC Workflow Features
1. **Triage Queue Mode** with SLA timers (MTTA, containment, closure).
2. **Saved views** for alerts/incidents (per analyst + shared team views).
3. **Case notebook** inside incident detail (hypotheses, evidence snippets, decisions).
4. **Incident handoff package** export (timeline + IOCs + actions + analyst notes).
5. **Bulk actions** for alerts/incidents (assign, tag, suppress, escalate).
6. **Watchlists** for entities (IP/user/host/hash/domain) with change notifications.

### 2) AI / Detection Features
7. **Explainability panel** for every AI decision (signals + confidence rationale).
8. **AI feedback loop** at point-of-use (approve/reject/correct outcome).
9. **Guardrailed AI playbook authoring** (AI proposes actions, analyst approves).
10. **Anomaly subscriptions** (notify when model detects risk deltas).
11. **Forecast quality scoring** (precision/recall trend of predictive modules).
12. **Auto root-cause summarization** from correlated alerts + entity graph.

### 3) Integration & Response Features
13. **Bi-directional ticket sync** (Jira/ServiceNow status + comments mirroring).
14. **Webhook event subscriptions** by event type and severity threshold.
15. **Connector run history** with per-run diagnostics and replay option.
16. **Connector secret rotation workflow** with expiry reminders.
17. **Approval workflows for response actions** (single/dual approver).
18. **Response simulation mode** (dry-run impact preview before execution).

### 4) Security & Governance Features
19. **RBAC enforcement** with scoped permissions (org admin, SOC manager, analyst, viewer).
20. **Team and user management** (invite, deactivate, role change audit trail).
21. **Data retention policy editor** by table/type with legal-hold exception.
22. **Tamper-evident audit verification UI** for chain integrity checks.
23. **Compliance control mapping assistant** (evidence to control linkage).
24. **DSAR workflow automation** with completion SLA tracking.

### 5) Commercial / Operations Features
25. **Usage metering dashboard** (events, connectors, AI tokens, automation runs).
26. **Plan limits + soft/hard thresholds** in-product warnings.
27. **In-app guided onboarding** checklist (first connector, first incident, first playbook).
28. **Workspace templates** (SMB SOC, Enterprise SOC, Cloud-first).

## B) UI/UX Changes to Add (Comprehensive)

### 1) Alerts & Incidents UX
- Add split-view layout: list on left, details drawer on right.
- Add keyboard triage shortcuts (`A` assign, `E` escalate, `R` resolve).
- Add persistent filter chips + quick-clear.
- Add in-row mini timeline and last-activity actor.
- Add table virtualization/pagination for large datasets.

### 2) Dashboard UX
- Add customizable widgets (pin/move/hide + saved layout presets).
- Add anomaly banners with direct deep links to affected entities/incidents.
- Add “what changed since last 24h” summary widget.

### 3) Navigation & Command UX
- Expand command palette beyond navigation to actual operations (create incident, assign, run playbook, open entity).
- Add recent context stack (jump between last 10 viewed records).
- Add global quick-create (`+`) for alert note, incident task, integration channel.

### 4) Forms & Configuration UX
- Add form validation hints before submit for connectors/integrations.
- Add test-result cards with failure remediation guidance.
- Add secrets UX improvements: masked state, reveal timeout, rotate action.

### 5) Accessibility & Quality UX
- Add full accessibility pass (focus order, ARIA labels, contrast).
- Add empty-state design system with “next best action”.
- Add loading skeleton consistency and optimistic updates where safe.

## C) Platform / Architecture Changes to Add

1. Add **server-side pagination/filter/sort** for high-cardinality endpoints.
2. Add **query-level caching strategy** for expensive analytics endpoints.
3. Add **background worker queue** for connector sync, enrichment, report jobs.
4. Add **idempotency keys** for ingestion and response action APIs.
5. Add **outbox/event replay pattern** for reliable downstream integrations.
6. Add **OpenAPI spec + typed API client generation**.
7. Add **per-endpoint latency/error SLOs** and alerting.
8. Add **multi-region backup/restore drills** and RPO/RTO docs.
9. Add **feature flag framework** for progressive rollout.
10. Add **integration/contract test suites** for connectors and automation actions.

## D) Data & Model Changes to Add

1. Add explicit **organization membership + role tables** for true RBAC.
2. Add **saved views table** for per-user/per-team filters and column presets.
3. Add **suppression rules table** (scope, matcher, expiry, reason, owner).
4. Add **action approval records** table (approver, decision, timestamp, reason).
5. Add **SLA tracking fields** on incidents (ackDueAt, containDueAt, breach flags).
6. Add **connector run logs** table with checkpoints and retry metadata.
7. Add **audit verification metadata** for tamper-evidence validation jobs.

## E) 90-Day Delivery Plan (Practical)

### Days 1–30 (Foundation)
- Server-side pagination + saved views + bulk actions.
- SLA timers + queue views.
- Connector run history + diagnostics.

### Days 31–60 (Automation & Governance)
- RBAC + team management + approval workflow.
- Suppression rules + explainability panel.
- Ticket bi-directional sync.

### Days 61–90 (Scale & Differentiation)
- Worker queue + idempotency + OpenAPI/SDK.
- Guided onboarding + usage metering.
- Forecast quality dashboard + model feedback analytics.
