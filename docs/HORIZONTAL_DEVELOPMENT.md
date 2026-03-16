# SecureNexus — Horizontal Development Priorities

> **Context:** Vertical feature development is complete. This document focuses exclusively on **horizontal improvements** — making existing features more reliable, polished, integrated, and production-ready. No new feature categories should be added without a strong product justification.

---

## What We Mean by Horizontal Development

Vertical development = building new feature towers (UEBA, Supply Chain, Deception, etc.)
Horizontal development = making every existing tower solid, interconnected, and genuinely usable

The goal is depth over breadth. A user should be able to go into any feature and find it *actually works* end-to-end — not a stub, not a disconnected UI, not an AI endpoint that needs manual env vars nobody documented.

---

## Priority 1 — AI Engine Reliability & Observability

The AI is the core differentiator but currently has the most failure-silent paths.

### 1.1 — First-Run Experience for AI

**Problem:** New deployments get no AI output. There is no clear "AI is not configured" state surfaced in the UI. Users see empty results or generic errors with no guidance.

**What to build:**
- A setup health banner on the AI Engine page (`/ai-engine`) that checks Bedrock access and tells the user exactly what's missing (region, model access, credentials) with a direct link to fix it.
- A `GET /api/ai/setup-status` endpoint that returns a structured checklist: `{ bedrock_reachable: bool, models_enabled: { sonnet: bool, opus: bool }, budget_set: bool, prompts_initialized: bool }`.
- Show this checklist banner until all items are green.

**Files involved:** `server/routes/ai.ts`, `client/src/pages/ai-engine.tsx`, `server/ai/model-gateway.ts`

---

### 1.2 — AI Inference Failures Should Surface as Incidents

**Problem:** When the AI correlation fails silently (circuit breaker, budget, API error), nobody knows. Alerts pile up uncorrelated.

**What to build:**
- When the circuit breaker trips, publish a `system.ai_circuit_open` event to the event bus.
- Create a default system alert in the alerts table for this event.
- Add a dismissible banner on the Alerts and Dashboard pages when AI triage has been paused for >30 minutes.

**Files involved:** `server/ai/model-gateway.ts`, `server/event-bus.ts`, `server/routes/ai.ts`

---

### 1.3 — AI Model Health Page is Useful but Incomplete

**Problem:** `/ai-model-health` shows circuit breaker status but not: per-prompt success rates, per-tier latency percentiles, or a timeline of recent failures.

**What to build:**
- Persist `inferenceLog` entries to the database (currently in-memory, capped at 1000 — lost on restart).
- Add a `GET /api/ai/inference-history?tier=triage&limit=500` endpoint.
- Show a 7-day latency + error rate chart on the Model Health page.

**Files involved:** `server/ai.ts`, `server/routes/ai.ts`, `client/src/pages/ai-model-health.tsx`

---

### 1.4 — Prompt Registry Needs a Diff/Preview UI

**Problem:** Version history exists in the backend (`getPromptVersionHistory`) but the frontend prompt registry page has no way to compare two prompt versions side-by-side or preview what a prompt actually sends to the model.

**What to build:**
- Add a diff view between any two versions of a prompt on the Prompt Registry page.
- Add a "Test Prompt" button that lets an admin paste a sample alert and see the raw model output without triggering production triage.

**Files involved:** `client/src/pages/ai-prompt-registry.tsx`, `server/routes/ai.ts`

---

## Priority 2 — Connector Reliability & Debuggability

### 2.1 — Dead Letter Queue UX

**Problem:** Dead letters exist (`GET /api/connectors/dead-letters`) but there is no UI for them. Failed sync jobs disappear silently.

**What to build:**
- A **Dead Letters** tab on the Connectors page showing failed jobs with: timestamp, connector name, error message, raw payload (truncated).
- A **Retry** button per dead-letter entry.
- Alert email to org admins when dead-letter count exceeds 10 in 1 hour.

**Files involved:** `client/src/pages/connectors.tsx`, `server/routes/connectors.ts`

---

### 2.2 — Connector Sync History / Audit

**Problem:** Users have no visibility into what the connector synced, how many alerts came in, or if the last sync was healthy.

**What to build:**
- A per-connector sync history panel showing last 20 syncs: timestamp, alerts received, alerts created, deduped count, errors.
- Store `ConnectorJobRun` results with enough detail to render this.

**Files involved:** `server/connector-engine.ts`, `server/routes/connectors.ts`

---

### 2.3 — Connector Test Results are Too Vague

**Problem:** The "Test" button returns `{ success: true, message: "Connected", latencyMs: 42 }` but nothing about what data it can actually see (can it see alerts? what's the date range?).

**What to build:**
- Extend `ConnectorTestResult` to include a `preview` field: a sample of the last 3 events from the source, confirming the scope of data accessible.
- Show this preview in the UI after a successful test.

**Files involved:** `server/connectors/connector-plugin.ts`, individual connector plugins, `client/src/pages/connectors.tsx`

---

## Priority 3 — Onboarding & First-Value Flow

### 3.1 — Onboarding Wizard is Incomplete

**Problem:** The wizard tracks `completedSteps` but never actually validates completion. Users can skip the CSPM/endpoint step with no guidance on what they're missing.

**What to build:**
- Each wizard step should have a real completion check:
  - "Integrations" step: verified by `GET /api/integrations` count > 0.
  - "Ingestion" step: verified by at least 1 alert in the system.
  - "Endpoints" step: verified by at least 1 CSPM account or endpoint asset.
- Show a "What you're missing" breakdown if a step is skipped.
- Add a post-wizard checklist widget on the main dashboard (`/dashboard`) that persists until all 4 steps are green.

**Files involved:** `server/routes/onboarding.ts`, `client/src/pages/onboarding-wizard.tsx`, `client/src/components/onboarding-checklist.tsx`

---

### 3.2 — API Key Generation UX Friction

**Problem:** Users creating their first ingestion key have to navigate to the Developer Portal or Settings → API Keys. This path is non-obvious for someone following the onboarding docs.

**What to build:**
- Add a "Generate Ingestion Key" shortcut button directly on the Connectors page (for users who want to push data themselves rather than use a connector).
- Embed the ingestion API code example (curl) inline on the same page after key creation.

**Files involved:** `client/src/pages/connectors.tsx`, `client/src/pages/developer-portal.tsx`

---

## Priority 4 — Cross-Feature Data Flow Gaps

### 4.1 — UEBA Anomalies Don't Create Alerts

**Problem:** UEBA scores entities and detects anomalies, but high-risk entity scores do not automatically create alerts in the main alert stream. The UEBA feature operates in a silo.

**What to build:**
- When a UEBA entity score crosses `critical` (≥80), auto-create an alert with:
  - `source: "SecureNexus UEBA"`
  - `category: "credential_access"` (or appropriate)
  - `severity: "high"` or `"critical"` based on score
  - Link back to the UEBA entity profile
- Add a toggle in UEBA settings: "Auto-create alerts for critical risk scores".

**Files involved:** `server/routes/ueba.ts`, `server/routes/alerts.ts`

---

### 4.2 — Threat Hunting Results Don't Link Back to Incidents

**Problem:** Hunt results appear in the Threat Hunting page but there is no way to escalate a hunt finding directly to an incident or attach it to an existing incident.

**What to build:**
- Add a "Create Incident from Hunt Result" button on hunt result entries.
- Add a "Link to Incident" option that attaches the hunt result to an existing incident's evidence.

**Files involved:** `client/src/pages/threat-hunting.tsx`, `server/routes/threat-hunting.ts`

---

### 4.3 — Supply Chain Findings Don't Feed Vuln Scanner

**Problem:** SBOM upload creates supply chain findings but these are separate from the Vuln Scanner findings. A developer has to check both pages to understand their full vulnerability exposure.

**What to build:**
- When SBOM processing finds a CVE match, also create a corresponding `vulnFinding` record so it appears in the Vuln Scanner unified view.
- Add a "Source" filter on the Vuln Scanner page: `sbom`, `native_sensor`, `connector`, `manual`.

**Files involved:** `server/supply-chain-engine.ts`, `server/routes/supply-chain.ts`, `server/routes/vuln-scanner.ts`

---

### 4.4 — Deception Hits Don't Auto-Escalate to Incidents

**Problem:** When a canary token fires or a honeypot is triggered, a high-severity alert is created. But there is no automatic escalation to an incident or playbook trigger for deception hits.

**What to build:**
- Add a dedicated `deception_hit` alert category.
- Create a default playbook template: "Deception Hit Response" that auto-triggers on `deception_hit` category alerts.
- Add a Deception Hit dashboard widget on the main dashboard showing recent hits in the last 24h.

**Files involved:** `server/deception-engine.ts`, `server/routes/deception.ts`, `client/src/pages/dashboard.tsx`

---

## Priority 5 — Performance & Scale

### 5.1 — Alert List Performance Degrades at Scale

**Problem:** `getAlerts(orgId)` loads all alerts into memory and slices in application code. At >50k alerts per org this causes memory pressure and slow responses.

**What to build:**
- Move all pagination to the database layer (already done for `getAlertsPaginatedWithSort` at `/api/v1/alerts` — but many UI components still use the legacy `/api/alerts` endpoint).
- Audit all route files for in-memory pagination patterns and migrate them to the v1 paginated endpoints.
- Add a database index on `(org_id, created_at DESC)` for the alerts table if not already present.

**Files involved:** `server/routes/alerts.ts`, `server/storage.ts`, `migrations/`

---

### 5.2 — AI Inference Log Memory Leak

**Problem:** `inferenceLog` in `server/ai.ts` is an in-memory array capped at 1000 entries, pruned to 500 on overflow. This data is valuable for debugging but is lost on every restart. Under load it holds significant heap.

**What to build:**
- Move inference log to a database table with a 30-day TTL.
- Use the existing `retentionScheduler` to purge old entries.
- Remove the in-memory array fallback once DB persistence is confirmed working.

**Files involved:** `server/ai.ts`, `server/retention-scheduler.ts`, `migrations/`

---

### 5.3 — Real-Time WebSocket Events Need Backpressure

**Problem:** The event bus broadcasts all events to all connected WebSocket clients. Under high alert ingestion rates (e.g., during a CrowdStrike mass-event sync) this can flood slow clients.

**What to build:**
- Add per-client message queuing with a configurable max-queue-depth (default: 100 messages).
- Drop oldest messages and send a `{ type: "backpressure_drop", dropped: N }` message when the queue fills.
- Expose queue depth in the connection stats for monitoring.

**Files involved:** `server/event-bus.ts`

---

## Priority 6 — UI/UX Polish

### 6.1 — Empty States Are Missing or Generic Across the Platform

**Problem:** Most feature pages show blank space or a generic "No data" message when no assets have been onboarded. Users have no idea what to do next.

**What to build:**
- Audit all pages with empty states. For each, implement a contextual empty state that:
  - Explains **why** it's empty (e.g., "No UEBA anomalies found — this feature requires entity behavior data")
  - Provides **one clear action** to fix it (e.g., "Connect CrowdStrike or Okta to start ingesting behavior data" with a link to Connectors)
- The `empty-state.tsx` component exists — it just needs to be used consistently everywhere.

**High-priority pages for empty state fixes:** UEBA, Threat Hunting, Deception, Supply Chain, Ransomware Defense, OT Security, Physical Security

**Files involved:** `client/src/components/empty-state.tsx`, all feature page components

---

### 6.2 — Dashboard Is Not Personalized

**Problem:** The main dashboard shows the same widgets regardless of which features are configured. An org with only CrowdStrike connected sees widgets for CSPM, OT Security, and other empty features.

**What to build:**
- Make dashboard widgets contextually aware: only show CSPM widget if at least one CSPM account is configured; only show UEBA widget if UEBA has baselines.
- Add a "Customize Dashboard" button that lets users pin/unpin widgets.

**Files involved:** `client/src/pages/dashboard.tsx`, `client/src/pages/dashboard-stunning.tsx`

---

### 6.3 — No In-App Notification for Critical Alerts

**Problem:** Critical severity alerts are created but users only know about them if they're actively watching the Alerts page. There is no in-app toast/banner for new critical alerts.

**What to build:**
- Add a real-time notification bell in the top bar that shows new critical alerts as they arrive via WebSocket.
- Clicking the notification navigates directly to the alert detail.
- Add browser push notification support (with opt-in) for critical alerts when the tab is not focused.

**Files involved:** `client/src/components/` (new notification component), `client/src/App.tsx`

---

## Priority 7 — Security Hardening

### 7.1 — API Keys Don't Enforce Scope on Ingestion Endpoints

**Problem:** API keys have a `scopes` field (`ingest:write`, `alerts:read`, etc.) but the ingestion endpoint `POST /api/ingest` only checks that the key is valid — it does not verify the `ingest:write` scope. An `alerts:read`-only key can currently push data.

**What to build:**
- Add scope enforcement on all API key authenticated routes.
- Create a `requireScope(scope)` middleware similar to `requirePermission`.
- Audit all routes using `apiKeyAuth` and add appropriate scope guards.

**Files involved:** `server/routes/ingestion.ts`, `server/auth/index.ts`, new `server/middleware/scope-enforcement.ts`

---

### 7.2 — Playbook Actions Execute Without Blast-Radius Preview in the UI

**Problem:** The `InsertBlastRadiusPreviewSchema` exists and blast-radius preview is supported in the backend, but the playbook UI does not show the blast radius before executing an action.

**What to build:**
- Before executing any `isolate_host`, `block_ip`, or `disable_user` action, show an inline blast-radius preview: "This will isolate 1 host: prod-server-01, which runs 3 critical services."
- Require explicit confirmation before proceeding.

**Files involved:** `client/src/pages/playbooks.tsx`, `server/routes/playbooks.ts`

---

### 7.3 — Session Tokens Don't Rotate After Privilege Escalation

**Problem:** When a user's role is elevated by an admin, their existing session token still reflects the old role until they log out and back in.

**What to build:**
- When a user's role is changed, invalidate their existing sessions via `session.destroy()` or by setting a `sessionVersion` field that's checked on each request.
- Notify the user via WebSocket: "Your role has been updated. Please refresh."

**Files involved:** `server/auth/index.ts`, `server/routes/orgs.ts`

---

## Priority 8 — Observability & Ops

### 8.1 — No Centralized Error Tracking

**Problem:** Errors are logged via `logger` but there is no structured error aggregation. Finding the root cause of a production issue requires reading raw logs.

**What to build:**
- Integrate an error tracking SDK (Sentry or similar) to capture unhandled exceptions with full stack traces and request context.
- Group errors by route, user, org, and model invocation.
- Add a Platform Admin page section for recent error rates.

---

### 8.2 — Job Queue Has No UI

**Problem:** `job-queue.ts` and the outbox processor run background tasks but there is no way to see what's queued, running, or failed without database access.

**What to build:**
- The Job Queue Dashboard page (`/job-queue-dashboard`) exists but appears to be a stub.
- Implement the full UI showing: queue depth, in-progress jobs, recently completed, recently failed.
- Add a "Retry Failed Job" button.

**Files involved:** `client/src/pages/job-queue-dashboard.tsx`, `server/job-queue.ts`, `server/outbox-processor.ts`

---

### 8.3 — Metrics Rollup Runs but Results Aren't Used

**Problem:** `metrics-rollup.ts` calculates security metrics and stores them, but almost no frontend page displays this rolled-up data — most pages fetch raw counts directly.

**What to build:**
- Use pre-computed metrics rollup data on the main dashboard for MTTD, MTTR, alert volume trend, false positive rate.
- This will dramatically reduce dashboard load time.

**Files involved:** `server/routes/metrics-rollup.ts`, `client/src/pages/dashboard.tsx`, `client/src/pages/metrics-rollup.tsx`

---

## Non-Negotiable Quality Improvements

These are not features — they are table-stakes improvements that should be done regardless of roadmap priority.

| Item | Why |
|------|-----|
| All feature pages need proper loading skeletons | Currently many pages flash blank content while loading |
| Form validation errors should be inline, not toast-only | Users can't tell which field failed |
| Connector credentials should never appear in browser console | Some error responses log the full config object |
| AI responses need a timeout indicator | Long investigations have no progress feedback |
| Mobile viewport on critical pages (Alerts, Incidents, Dashboard) | These pages are broken on mobile |
| Comprehensive E2E tests for the onboarding flow | The wizard is the most important flow and has zero E2E coverage |
| All `phase2-stubs` routes should either be implemented or removed | Stub routes confuse developers and add dead weight |

---

## What We Are NOT Building (for now)

To be explicit about scope:

- No new connector types unless a customer specifically requires one and no existing connector serves the need
- No new compliance frameworks beyond what's already mapped
- No new AI models or backends — stabilize what we have first
- No mobile app — optimize the web experience for mobile instead
- No new dashboard pages — consolidate existing ones

---

*This document should be reviewed at every sprint planning session. Items that are completed should be crossed off and this doc updated. New horizontal improvements discovered during development should be added here, not handled as ad-hoc tickets.*
