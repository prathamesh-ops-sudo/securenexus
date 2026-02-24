# Upgrade Roadmap Status (Codebase-Driven)

This document maps the requested roadmap themes to current implementation status and near-term gaps.

## Theme A — Analyst Throughput

- ✅ Split workflows exist across list/detail pages (alerts, incidents), with deep-link details.
- ✅ **New in this change:** Alerts bulk operations (status/suppress/unsuppress) and multi-select.
- ✅ **New in this change:** Saved alert views (local persisted filter/search presets).
- ✅ **New in this change:** Keyboard triage model (`J/K` row focus, `T` triage selected).
- ✅ Queue state enhancement now includes aging/breached queue views directly on the alert list.

## Theme B — Automation Safety

- ✅ Approval gates exist for playbook execution flows.
- ✅ Dry-run execution mode already exists in playbook execution model.
- ✅ Rollback engine and rollback records are present.
- ✅ Unified cooldown/rate control panel is available to apply controls across active autonomous policies.
- ✅ Action audit timeline is now consolidated in a dedicated timeline pane in Autonomous Response.

## Theme C — Governance + Multi-Tenancy

- ✅ RBAC data model and org/team routes exist.
- ✅ Retention and compliance policy structures exist.
- ✅ API key model supports scopes; audit logs are broadly captured.
- 🟡 Additional enforcement consistency across all endpoints remains ongoing hardening work.

## Theme D — Scale & Reliability

- ✅ Background jobs/queue, idempotency keys, webhook/connector logs, and SLI/SLO schema support exist.
- ✅ Added `/api/v1/alerts` and `/api/v1/incidents` server-side pagination/filter/sort endpoints with standardized envelope (`data`, `meta`, `errors`).
- 🟡 Existing legacy `/api/alerts` and `/api/incidents` clients still use all-record loading and should be migrated incrementally.

## Theme E — AI Trust + Outcome Quality

- ✅ Explainability panels and AI feedback loop are present in incident/alert workflows.
- ✅ Forecast quality snapshots and trend endpoint are implemented.
- ✅ Guardrailed AI playbook authoring proposal endpoint and UI panel are implemented.
- ✅ Auto root-cause summarization endpoint for incidents is implemented.

## Recommended Next Increment

1. Convert alert/incident list APIs to server-side pagination/filter/sort and update UI query params.
2. Add shared "Saved Views" backend model for team-shared filters (currently local in alerts page).
3. Expand keyboard shortcuts into global command palette actions with discoverability modal.
4. Add team-shared anomaly subscription templates and escalation defaults by severity queue.
