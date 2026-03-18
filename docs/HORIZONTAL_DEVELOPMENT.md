# SecureNexus — Horizontal Development & Completeness Roadmap

**Version:** 1.0
**Generated:** March 2026
**Purpose:** Feature-by-feature improvement plan to bring every existing capability to production-perfect quality. This document does NOT propose new features — it systematically identifies gaps, missing polish, incomplete integrations, and improvements needed in every existing feature to achieve completeness.

**How to read this document:** Each section covers one page/feature area in the platform, following the sidebar navigation order. For each feature, improvements are organized into categories:

- **UI/UX Polish** — visual consistency, loading states, empty states, responsive design, accessibility
- **Backend Completeness** — real data vs stubs, missing endpoints, error handling, edge cases
- **Data Integrity** — validation, pagination, filtering, sorting, search
- **Real-time & Performance** — WebSocket updates, caching, lazy loading, query optimization
- **Integration Gaps** — cross-feature links, navigation flows, data sharing between modules
- **Testing Coverage** — E2E tests, unit tests, edge case coverage
- **Security Hardening** — input validation, RBAC enforcement, org-scoping, CSRF
- **Production Readiness** — error boundaries, retry logic, offline handling, audit logging

---

## Table of Contents

1. [Dashboard](#1-dashboard)
2. [Alerts](#2-alerts)
3. [Incidents](#3-incidents)
4. [Threat Intel Feeds](#4-threat-intel-feeds)
5. [OSINT Monitoring](#5-osint-monitoring)
6. [IOC Management](#6-ioc-management)
7. [CVE Database](#7-cve-database)
8. [Campaigns](#8-campaigns)
9. [MITRE ATT&CK](#9-mitre-attck)
10. [Kill Chain](#10-kill-chain)
11. [Security Graph](#11-security-graph)
12. [Attack Paths](#12-attack-paths)
13. [Entity Explorer](#13-entity-explorer)
14. [Entity Resolution](#14-entity-resolution)
15. [War Room](#15-war-room)
16. [Threat Hunting](#16-threat-hunting)
17. [Investigation Timeline](#17-investigation-timeline)
18. [Evidence Chain](#18-evidence-chain)
19. [Evidence Locker](#19-evidence-locker)
20. [Playbooks](#20-playbooks)
21. [Autonomous Response](#21-autonomous-response)
22. [Rollback History](#22-rollback-history)
23. [Playbook Library](#23-playbook-library)
24. [Runbook Library](#24-runbook-library)
25. [CSPM](#25-cspm)
26. [Endpoint Telemetry](#26-endpoint-telemetry)
27. [Vulnerability Management](#27-vulnerability-management)
28. [JIT Access](#28-jit-access)
29. [Secret Rotation](#29-secret-rotation)
30. [AI Engine](#30-ai-engine)
31. [SOC Co-Pilot](#31-soc-co-pilot)
32. [Prompt Builder](#32-prompt-builder)
33. [Model Gateway](#33-model-gateway)
34. [Prompt Registry](#34-prompt-registry)
35. [Feedback Loop](#35-feedback-loop)
36. [Budget & Limits](#36-budget--limits)
37. [Connectors](#37-connectors)
38. [Integration Marketplace](#38-integration-marketplace)
39. [Native Collectors](#39-native-collectors)
40. [Webhooks](#40-webhooks)
41. [Ingestion Status](#41-ingestion-status)
42. [Job Queue](#42-job-queue)
43. [Outbox Monitor](#43-outbox-monitor)
44. [Data Lake](#44-data-lake)
45. [Asset Inventory](#45-asset-inventory)
46. [Risk Register](#46-risk-register)
47. [Native Sensors](#47-native-sensors)
48. [Detection Rules](#48-detection-rules)
49. [Vuln Scanner](#49-vuln-scanner)
50. [Agent Response](#50-agent-response)
51. [UEBA Analytics](#51-ueba-analytics)
52. [Supply Chain Security](#52-supply-chain-security)
53. [Identity Governance](#53-identity-governance)
54. [Deception Technology](#54-deception-technology)
55. [OT/ICS Security](#55-otics-security)
56. [Mobile Security](#56-mobile-security)
57. [API Security](#57-api-security)
58. [Ransomware Defense](#58-ransomware-defense)
59. [Community Threat Intel](#59-community-threat-intel)
60. [Security Posture Score](#60-security-posture-score)
61. [Security Chaos Engineering](#61-security-chaos-engineering)
62. [AI Detection Rules](#62-ai-detection-rules)
63. [Autonomous SOC](#63-autonomous-soc)
64. [Developer Security](#64-developer-security)
65. [TPRM](#65-tprm)
66. [Dark Web Monitoring](#66-dark-web-monitoring)
67. [Physical Security](#67-physical-security)
68. [Phishing & Awareness](#68-phishing--awareness)
69. [Quantum Readiness](#69-quantum-readiness)
70. [Privacy Engineering](#70-privacy-engineering)
71. [DNS Security](#71-dns-security)
72. [Email Security](#72-email-security)
73. [MSSP Dashboard](#73-mssp-dashboard)
74. [Partner Portal](#74-partner-portal)
75. [Assessments](#75-assessments)
76. [Threat Reports](#76-threat-reports)
77. [Advanced Reports](#77-advanced-reports)
78. [Compliance Center](#78-compliance-center)
79. [Trust Center](#79-trust-center)
80. [Gap Analysis](#80-gap-analysis)
81. [Audit Log](#81-audit-log)
82. [Policy Packs](#82-policy-packs)
83. [Reports](#83-reports)
84. [Data Residency](#84-data-residency)
85. [Board Dashboard](#85-board-dashboard)
86. [Onboarding](#86-onboarding)
87. [Team & Invites](#87-team--invites)
88. [Org Settings](#88-org-settings)
89. [Developer Portal](#89-developer-portal)
90. [Billing](#90-billing)
91. [Usage & Metering](#91-usage--metering)
92. [Plans & Packaging](#92-plans--packaging)
93. [Settings](#93-settings)
94. [Landing Page](#94-landing-page)
95. [Cross-Cutting Platform Concerns](#95-cross-cutting-platform-concerns)

---

## 1. Dashboard

**Source:** `client/src/pages/dashboard.tsx` (1,584 lines) | `server/routes/dashboard.ts`
**Current state:** Functional with 8 configurable widgets, layout presets, MTTD/MTTR metrics, connector health. Uses real backend data.

### UI/UX Polish

| #   | Improvement                                                | Priority | Detail                                                                                                                                                                                                                         |
| --- | ---------------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1.1 | **Add skeleton loading for each widget independently**     | HIGH     | Currently the entire dashboard shows a single loading state. Each widget (Severity Distribution, Alert Trend, MITRE Tactics, etc.) should have its own `<Skeleton>` placeholder so widgets load progressively as data arrives. |
| 1.2 | **Drag-and-drop widget reordering**                        | MEDIUM   | Widget order is configurable via the Settings panel, but users cannot drag-and-drop to rearrange. Add `@dnd-kit/sortable` or similar to allow visual reordering of the 8 widget cards.                                         |
| 1.3 | **Time range selector for all widgets**                    | HIGH     | Dashboard currently shows a fixed time window. Add a global time range picker (Last 1h / 4h / 24h / 7d / 30d / custom) that filters all widget queries simultaneously. This is table-stakes for any SOC dashboard.             |
| 1.4 | **Responsive layout for mobile/tablet**                    | MEDIUM   | Dashboard grid uses fixed column layouts. On mobile viewports (<768px), widgets should stack vertically. On tablet (768–1024px), use 2-column grid. Currently not optimized for smaller screens.                               |
| 1.5 | **Auto-refresh toggle with configurable interval**         | HIGH     | SOC dashboards need auto-refresh (30s / 1m / 5m). Add a visible toggle button showing the current refresh interval, with a dropdown to change it. Currently relies on manual refresh or page reload.                           |
| 1.6 | **Dark/light theme consistency on charts**                 | LOW      | Recharts tooltips and axis labels may not fully respect the dark theme. Audit all chart colors, gridlines, and tooltip backgrounds to ensure they match the platform's dark theme palette.                                     |
| 1.7 | **"What Changed" widget — link each change to its source** | MEDIUM   | The "What Changed (24h)" widget shows deltas but items are not clickable. Each change (e.g., "+5 critical alerts") should link to a filtered view of the relevant page (e.g., Alerts filtered to critical, last 24h).          |
| 1.8 | **Keyboard shortcuts for common actions**                  | LOW      | Add keyboard shortcuts: `R` to refresh, `S` to open settings, number keys `1-8` to toggle widgets. Document these in a `?` help overlay.                                                                                       |

### Backend Completeness

| #    | Improvement                                                 | Priority | Detail                                                                                                                                                                                                                     |
| ---- | ----------------------------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1.9  | **Server-side time range filtering on dashboard endpoints** | HIGH     | `/api/dashboard/stats` currently returns all-time aggregates. Add `?from=&to=` query parameters so the dashboard can request time-bounded data without over-fetching.                                                      |
| 1.10 | **Cache dashboard aggregates with TTL**                     | MEDIUM   | Dashboard queries hit the database on every load. Add a 30-second server-side cache for aggregate queries (severity counts, trend data) to reduce DB load during high-traffic periods.                                     |
| 1.11 | **WebSocket push for real-time counter updates**            | HIGH     | Alert count, incident count, and connector health should update in real-time via WebSocket instead of requiring page refresh. The WebSocket infrastructure exists (`server/ws.ts`) but is not wired to dashboard counters. |

### Integration Gaps

| #    | Improvement                                             | Priority | Detail                                                                                                                                                                                             |
| ---- | ------------------------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1.12 | **Link MTTD/MTTR cards to Security Metrics page**       | MEDIUM   | MTTD and MTTR values are shown but clicking them does nothing. They should navigate to `/metrics-rollup` with the relevant metric pre-selected.                                                    |
| 1.13 | **Connector health widget → Connectors page deep-link** | LOW      | Clicking a connector in the health widget should navigate to `/connectors` with that connector pre-selected/highlighted.                                                                           |
| 1.14 | **Security Posture Score widget**                       | MEDIUM   | Dashboard should include the org's overall security posture score (from `/posture-trust-center`) as a prominent top-level metric. Currently this data exists but is not surfaced on the dashboard. |

### Testing Coverage

| #    | Improvement                                      | Priority | Detail                                                                                                                                                                                                   |
| ---- | ------------------------------------------------ | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1.15 | **E2E test: dashboard loads with all widgets**   | HIGH     | No E2E test exists for the dashboard. Add a Playwright test that verifies: page loads, all 8 default widgets render, stat cards show numeric values (not NaN/undefined), and charts render SVG elements. |
| 1.16 | **E2E test: widget toggle and preset switching** | MEDIUM   | Test that toggling a widget off/on via the settings panel persists across page reload (localStorage), and that switching layout presets correctly shows/hides the right widgets.                         |

---

## 2. Alerts

**Source:** `client/src/pages/alerts.tsx` (2,068 lines), `client/src/pages/alert-detail.tsx` (1,086 lines) | `server/routes/alerts.ts`
**Current state:** Full-featured alert management with 19 queries/mutations, bulk operations, severity filtering, MITRE tactic mapping, IOC matching, suppression rules, and AI-powered triage. Client-side pagination (200 alerts per fetch, PAGE_SIZE slicing).

### UI/UX Polish

| #   | Improvement                                         | Priority | Detail                                                                                                                                                                                                                                                                                    |
| --- | --------------------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 2.1 | **Server-side pagination**                          | CRITICAL | Alerts currently fetches up to 200 records and paginates client-side with `filtered.slice(page * PAGE_SIZE, ...)`. For orgs with 10K+ alerts, this causes slow initial load and high memory usage. Implement cursor-based or offset/limit server-side pagination with total count header. |
| 2.2 | **Column resizing and reordering**                  | MEDIUM   | Alert table columns have fixed widths. Allow users to resize columns by dragging borders and reorder columns by drag-and-drop. Persist preferences to localStorage.                                                                                                                       |
| 2.3 | **Saved filter presets**                            | HIGH     | Analysts frequently use the same filter combinations (e.g., "Critical + Unresolved + Last 24h"). Add ability to save, name, and recall filter presets. Store in localStorage or user preferences API.                                                                                     |
| 2.4 | **Bulk action confirmation with count**             | MEDIUM   | Bulk operations (resolve, escalate, suppress) should show a confirmation dialog: "You are about to resolve 47 alerts. This action cannot be undone. Proceed?" Currently executes immediately on click.                                                                                    |
| 2.5 | **Keyboard navigation in alert table**              | MEDIUM   | Add `j`/`k` for next/previous alert, `Enter` to open detail, `Escape` to close detail panel, `r` to resolve, `e` to escalate. Essential for SOC analysts processing hundreds of alerts per shift.                                                                                         |
| 2.6 | **Alert detail side panel (instead of navigation)** | HIGH     | Clicking an alert currently navigates to `/alerts/:id`. For faster triage, implement a slide-over panel (Sheet component) that shows alert detail without leaving the alert list. Keep full-page detail as an option via "Open in new tab" link.                                          |
| 2.7 | **Sound notification for critical alerts**          | LOW      | Optional browser notification + sound when a new critical/high alert arrives via WebSocket. Configurable in user settings.                                                                                                                                                                |

### Backend Completeness

| #    | Improvement                                             | Priority | Detail                                                                                                                                                                                               |
| ---- | ------------------------------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 2.8  | **Full-text search on alert title and description**     | HIGH     | Current filtering is by severity, status, source, and MITRE tactic. Add full-text search across alert title, description, and raw payload. Use PostgreSQL `tsvector` or `ILIKE` with index.          |
| 2.9  | **Alert deduplication engine**                          | HIGH     | Identical alerts from the same source within a short window should be deduplicated into a single alert with a count badge. Currently every ingested event creates a separate alert row.              |
| 2.10 | **Alert correlation — link related alerts**             | HIGH     | Alerts sharing the same source IP, destination, user, or IOC should be visually grouped or linked. Add a "Related Alerts" section to the alert detail view using entity-based correlation.           |
| 2.11 | **SLA tracking — time-to-acknowledge, time-to-resolve** | MEDIUM   | Track timestamps for each alert lifecycle stage (created → acknowledged → investigating → resolved). Display SLA compliance status (e.g., "Critical alerts must be acknowledged within 15 minutes"). |
| 2.12 | **Alert enrichment pipeline**                           | MEDIUM   | When an alert is created, automatically enrich it with: geo-IP lookup, WHOIS data, VirusTotal reputation, MITRE tactic auto-tagging. Currently enrichment is manual via AI triage button.            |

### Data Integrity

| #    | Improvement                           | Priority | Detail                                                                                                                                                     |
| ---- | ------------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 2.13 | **Validate alert status transitions** | MEDIUM   | Enforce valid status transitions server-side (e.g., cannot go from "resolved" back to "new" without reopening). Currently any status can be set via PATCH. |
| 2.14 | **Prevent duplicate suppress rules**  | LOW      | Users can create multiple suppression rules with identical criteria. Add a uniqueness check on (source + severity + pattern) combination.                  |

### Integration Gaps

| #    | Improvement                                   | Priority | Detail                                                                                                                                                                                       |
| ---- | --------------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 2.15 | **Alert → Incident escalation with pre-fill** | HIGH     | "Escalate to Incident" button should pre-populate the incident creation form with alert details (title, description, severity, affected assets, IOCs). Currently creates a minimal incident. |
| 2.16 | **Alert → Playbook trigger**                  | MEDIUM   | From alert detail, allow triggering a playbook with the alert context pre-filled. Show available playbooks filtered by alert type/severity.                                                  |
| 2.17 | **Alert → War Room link**                     | LOW      | If an alert is escalated to an incident that has a war room, show a "Join War Room" button on the alert detail page.                                                                         |

### Testing Coverage

| #    | Improvement                                                          | Priority | Detail                                                                                                                                                                     |
| ---- | -------------------------------------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 2.18 | **E2E test: alert lifecycle (create → triage → escalate → resolve)** | HIGH     | Existing `e2e/alert-triage.spec.ts` covers basic triage. Extend to cover: bulk select + resolve, suppression rule creation, filter persistence, and pagination navigation. |
| 2.19 | **E2E test: alert detail page renders all sections**                 | MEDIUM   | Verify that alert detail shows: metadata, raw payload, IOC matches, MITRE mapping, AI triage results, timeline, and related alerts (once implemented).                     |

---

## 3. Incidents

**Source:** `client/src/pages/incidents.tsx` (1,292 lines), `client/src/pages/incident-detail.tsx` (3,967 lines) | `server/routes/incidents.ts`
**Current state:** Rich incident management with 10+ tabs in detail view (Overview, Timeline, Alerts, Evidence, Response, AI Investigation, Attack Graph, Post-Incident Review), 40 queries/mutations on detail page. Full CRUD with status workflow.

### UI/UX Polish

| #   | Improvement                                       | Priority | Detail                                                                                                                                                                                                        |
| --- | ------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 3.1 | **Incident list — Kanban view option**            | HIGH     | Add a Kanban board view alongside the table view, with columns for each status (New → Investigating → Containment → Eradication → Recovery → Resolved). Drag-and-drop cards between columns to update status. |
| 3.2 | **Incident detail — tab state persistence**       | MEDIUM   | When navigating away and back to an incident, the last active tab should be remembered. Currently always opens to the Overview tab. Use URL hash or localStorage.                                             |
| 3.3 | **Incident detail — split-screen layout**         | LOW      | For the AI Investigation tab, allow a split-screen view: left panel shows the AI analysis, right panel shows the raw alert data or evidence. Useful for analysts verifying AI findings.                       |
| 3.4 | **Timeline tab — visual timeline with swimlanes** | HIGH     | Current timeline is a simple chronological list. Upgrade to a visual timeline with swimlanes (one per actor/system), zoom controls, and clickable events that expand to show detail.                          |
| 3.5 | **Post-incident review — template system**        | MEDIUM   | The post-incident review tab should offer structured templates (5 Whys, Blameless Postmortem, RCA Template) instead of a free-form text area. Each template should have guided fields.                        |

### Backend Completeness

| #   | Improvement                              | Priority | Detail                                                                                                                                                                                               |
| --- | ---------------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 3.6 | **Server-side incident search**          | HIGH     | Incident list filtering should support full-text search on title, description, and associated alert content. Currently relies on client-side filtering.                                              |
| 3.7 | **Incident metrics aggregation**         | MEDIUM   | Track and expose incident metrics: MTTR by severity, incidents per category over time, resolution rate, reopened incident count. Feed into the Security Metrics page.                                |
| 3.8 | **Automated incident classification**    | MEDIUM   | When an incident is created (manually or via alert escalation), auto-classify its type (data breach, malware, phishing, insider threat, etc.) using rules or AI. Currently classification is manual. |
| 3.9 | **Incident status change notifications** | HIGH     | When an incident status changes, notify all assigned team members via in-app notification and email. Currently no notifications are sent on status changes.                                          |

### Integration Gaps

| #    | Improvement                                | Priority | Detail                                                                                                                                                                |
| ---- | ------------------------------------------ | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 3.10 | **Incident → JIRA/ServiceNow ticket sync** | MEDIUM   | Allow creating a linked ticket in JIRA or ServiceNow from the incident detail page. Bi-directional sync: status changes in either system should reflect in the other. |
| 3.11 | **Incident → Compliance mapping**          | LOW      | Tag incidents with affected compliance frameworks (SOC 2, ISO 27001, etc.) and auto-generate compliance impact reports. Link to the Compliance Center.                |
| 3.12 | **Incident → Threat Intel feedback loop**  | MEDIUM   | IOCs extracted during incident investigation should be automatically submitted back to the IOC Management system for future matching against incoming alerts.         |

### Testing Coverage

| #    | Improvement                                           | Priority | Detail                                                                                                                                             |
| ---- | ----------------------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| 3.13 | **E2E test: incident creation from alert escalation** | HIGH     | Test the full flow: create alert → escalate → verify incident created with correct details → navigate to incident detail → verify alert is linked. |
| 3.14 | **E2E test: incident detail tabs all render**         | HIGH     | Navigate to each of the 10+ tabs and verify they render without errors. Test with both populated and empty data states.                            |

---

## 4. Threat Intel Feeds

**Source:** `client/src/pages/threat-intel-feeds.tsx` (730 lines) | `server/routes/threat-intel.ts`, `server/threat-intel-feeds.ts`
**Current state:** Feed management with 9 queries, STIX/TAXII ingestion, AlienVault OTX integration, manual feed addition. No tabs.

### UI/UX Polish

| #   | Improvement                                    | Priority | Detail                                                                                                                                                       |
| --- | ---------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 4.1 | **Feed health status indicators**              | HIGH     | Each feed should show a colored status dot (green = active/syncing, yellow = stale/behind, red = error/unreachable). Currently shows text-based status only. |
| 4.2 | **Feed ingestion statistics per feed**         | HIGH     | Show how many IOCs each feed has contributed (total, last 24h, last 7d). Helps analysts evaluate feed quality and decide which feeds to keep.                |
| 4.3 | **Feed preview — sample IOCs before enabling** | MEDIUM   | When adding a new feed, show a preview of the first 10 IOCs it would ingest before committing. Prevents adding low-quality feeds.                            |
| 4.4 | **Feed comparison table**                      | LOW      | Side-by-side comparison of feed coverage: how many unique IOCs each feed provides, overlap percentage between feeds, false positive rate per feed.           |

### Backend Completeness

| #   | Improvement                                               | Priority | Detail                                                                                                                                                                               |
| --- | --------------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 4.5 | **Scheduled feed polling**                                | CRITICAL | Feeds should auto-poll on a configurable schedule (every 1h, 6h, 24h). Currently feeds are polled on-demand via manual trigger. Implement a cron-like scheduler using the job queue. |
| 4.6 | **Feed deduplication across sources**                     | HIGH     | When the same IOC appears in multiple feeds, it should be stored once with multiple source attributions, not duplicated. Add a dedup layer to the ingestion pipeline.                |
| 4.7 | **STIX 2.1 full object support**                          | MEDIUM   | Currently ingests indicators only. Add support for ingesting full STIX objects: Threat Actors, Campaigns, Malware, Tools, Attack Patterns, and their relationships.                  |
| 4.8 | **Feed authentication — API key and certificate support** | MEDIUM   | Some TAXII servers require client certificates or API keys. Add authentication configuration options per feed (API key, bearer token, mTLS certificate upload).                      |

### Integration Gaps

| #    | Improvement                              | Priority | Detail                                                                                                                                                                 |
| ---- | ---------------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 4.9  | **Feed IOCs → automatic alert matching** | HIGH     | Newly ingested IOCs should automatically be matched against existing alerts and entities. Currently IOC matching is triggered separately from the IOC Management page. |
| 4.10 | **Feed → Campaign auto-linking**         | MEDIUM   | When feed data includes campaign/threat actor attribution, automatically link ingested IOCs to existing campaigns on the Campaigns page.                               |

---

## 5. OSINT Monitoring

**Source:** `client/src/pages/osint-feeds-config.tsx` (611 lines) | `server/routes/threat-intel.ts`
**Current state:** OSINT feed configuration with 8 queries, Shodan/Censys/VirusTotal source management. Keyword monitoring setup.

### UI/UX Polish

| #   | Improvement                       | Priority | Detail                                                                                                                                                                                              |
| --- | --------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 5.1 | **OSINT result visualization**    | HIGH     | OSINT query results are shown as a flat list. Add visualization options: geographic map for IP results, domain relationship graph, temporal timeline of discoveries.                                |
| 5.2 | **Alert rules on OSINT findings** | HIGH     | Allow setting up alert rules: "Alert me when any OSINT source finds a new exposed service on our IP ranges" or "Alert when our domain appears in a paste site." Currently requires manual checking. |
| 5.3 | **OSINT source health dashboard** | MEDIUM   | Show connectivity status, API quota remaining, last successful query time for each OSINT source (Shodan, Censys, VirusTotal).                                                                       |

### Backend Completeness

| #   | Improvement                                         | Priority | Detail                                                                                                                                                              |
| --- | --------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 5.4 | **Scheduled OSINT scans**                           | CRITICAL | OSINT queries should run on a schedule (daily, weekly) and store results for trend analysis. Currently all queries are manual/on-demand.                            |
| 5.5 | **OSINT result deduplication and change detection** | HIGH     | When a scheduled scan runs, compare results to the previous scan and highlight changes (new exposures, resolved issues). Currently each scan result is independent. |
| 5.6 | **API quota management**                            | MEDIUM   | Track API calls per source and warn when approaching quota limits. Implement rate limiting to prevent quota exhaustion. Show quota usage in the UI.                 |

### Integration Gaps

| #   | Improvement                                      | Priority | Detail                                                                                                                                                         |
| --- | ------------------------------------------------ | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 5.7 | **OSINT findings → Asset Inventory correlation** | HIGH     | OSINT-discovered IPs and domains should automatically be matched against the Asset Inventory. Flag any OSINT findings that correspond to known assets.         |
| 5.8 | **OSINT → Attack Surface monitoring**            | MEDIUM   | Create a dedicated attack surface view that aggregates OSINT findings across all sources, showing the organization's external exposure in a unified dashboard. |

---

## 6. IOC Management

**Source:** `client/src/pages/ioc-ingestion-matching.tsx` (1,558 lines) | `server/routes/threat-intel.ts`
**Current state:** IOC ingestion, matching against alerts, 12 queries, 11 tabs covering IOC types (IPs, domains, hashes, URLs, emails, etc.), bulk upload, STIX import.

### UI/UX Polish

| #   | Improvement                              | Priority | Detail                                                                                                                                                                      |
| --- | ---------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 6.1 | **IOC confidence scoring visualization** | HIGH     | IOCs should display confidence scores (1-100) with color-coded badges. High-confidence IOCs should be visually prominent. Currently all IOCs are displayed equally.         |
| 6.2 | **IOC expiration and aging**             | HIGH     | IOCs should have configurable TTL (time-to-live). Expired IOCs should be visually grayed out and excluded from active matching. Show "expires in X days" badges.            |
| 6.3 | **IOC relationship graph**               | MEDIUM   | Visualize relationships between IOCs: which IPs resolve to which domains, which hashes communicate with which C2 servers. Use the entity graph infrastructure.              |
| 6.4 | **Bulk export (CSV, STIX, OpenIOC)**     | MEDIUM   | Add export functionality for IOC lists in multiple formats. Currently IOCs can only be viewed in the UI. Analysts need to export for sharing with partners and other tools. |

### Backend Completeness

| #   | Improvement                               | Priority | Detail                                                                                                                                                               |
| --- | ----------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 6.5 | **IOC retroactive matching on ingestion** | CRITICAL | When a new IOC is added, automatically scan all historical alerts (configurable lookback window) for matches. Currently only matches against future incoming alerts. |
| 6.6 | **IOC auto-enrichment**                   | HIGH     | When an IOC is added, automatically enrich it with: VirusTotal reputation, WHOIS data, passive DNS, geo-IP. Currently enrichment is manual.                          |
| 6.7 | **IOC false positive tracking**           | MEDIUM   | Track false positive rates per IOC and per feed source. Auto-suppress IOCs with high FP rates. Feed this data back to the Active Learning system.                    |

### Integration Gaps

| #   | Improvement                              | Priority | Detail                                                                                                                                                   |
| --- | ---------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 6.8 | **IOC → Detection Rule auto-generation** | HIGH     | High-confidence IOCs should optionally auto-generate detection rules (Sigma/YARA). Link to the AI Detection Rules system for LLM-assisted rule creation. |
| 6.9 | **IOC → Community Intel sharing**        | MEDIUM   | Allow submitting IOCs to the Community Threat Intel network for anonymous sharing with industry peers.                                                   |

---

## 7. CVE Database

**Source:** `client/src/pages/cve-browser.tsx` (223 lines) | `server/routes/threat-intel.ts`
**Current state:** Basic CVE browser with 2 queries. Minimal implementation — shows CVE list with search.

### UI/UX Polish

| #   | Improvement                               | Priority | Detail                                                                                                                                                                                 |
| --- | ----------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 7.1 | **CVE detail page with full information** | CRITICAL | Currently shows a flat list. Each CVE needs a detail view with: description, CVSS score breakdown, affected products, known exploits, references, remediation guidance, and timeline.  |
| 7.2 | **CVSS score visual indicators**          | HIGH     | Show CVSS scores with color-coded severity badges (Critical 9.0-10.0 red, High 7.0-8.9 orange, Medium 4.0-6.9 yellow, Low 0.1-3.9 green). Add a CVSS vector string tooltip.            |
| 7.3 | **CVE search with advanced filters**      | HIGH     | Add filters: by CVSS range, by vendor/product, by publication date range, by exploit availability (known exploit vs. theoretical), by CWE category. Current search is basic text-only. |
| 7.4 | **CVE trending/dashboard**                | MEDIUM   | Show trending CVEs: most discussed, recently exploited in the wild, highest severity this week. Add charts for CVE publication trends over time.                                       |

### Backend Completeness

| #   | Improvement                                        | Priority | Detail                                                                                                                                                                                                |
| --- | -------------------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 7.5 | **NVD/NIST CVE database sync**                     | CRITICAL | Implement automated sync with the NIST NVD database (CVE JSON feed v2.0). Currently CVEs appear to be manually added or very limited. The page is only 223 lines — it needs substantial backend work. |
| 7.6 | **EPSS (Exploit Prediction Scoring) integration**  | HIGH     | Add EPSS scores alongside CVSS. EPSS provides a probability of exploitation in the next 30 days, which is more actionable than CVSS alone.                                                            |
| 7.7 | **KEV (Known Exploited Vulnerabilities) flagging** | HIGH     | Cross-reference CVEs against CISA's KEV catalog. CVEs in the KEV should be prominently flagged with a "Known Exploited" badge.                                                                        |

### Integration Gaps

| #    | Improvement                                 | Priority | Detail                                                                                                                                                                                                |
| ---- | ------------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 7.8  | **CVE → Asset Inventory matching**          | CRITICAL | Match CVEs against the software inventory in Asset Inventory. Show which assets are affected by each CVE and vice versa. This is the core value proposition of a CVE database in a security platform. |
| 7.9  | **CVE → Vulnerability Scanner correlation** | HIGH     | Link CVEs to scan findings from the Vuln Scanner. Show which vulnerabilities have been detected vs. which are theoretical based on software versions.                                                 |
| 7.10 | **CVE → Patch management tracking**         | MEDIUM   | Track patch status for each CVE per asset: unpatched, patch available, patch applied, compensating control in place.                                                                                  |

---

## 8. Campaigns

**Source:** `client/src/pages/campaign-viewer.tsx` (242 lines) | `server/routes/threat-intel.ts`
**Current state:** Basic campaign viewer with 2 queries. Minimal implementation — extremely thin page.

### UI/UX Polish

| #   | Improvement                         | Priority | Detail                                                                                                                                                                                                                             |
| --- | ----------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 8.1 | **Campaign detail page**            | CRITICAL | The page is only 242 lines and likely shows a flat list. Each campaign needs a rich detail view with: threat actor attribution, targeted industries/regions, TTPs used, associated IOCs, timeline of activity, kill chain mapping. |
| 8.2 | **Campaign timeline visualization** | HIGH     | Show campaign activity on a visual timeline: first seen, peak activity, current status (active/dormant/concluded). Allow zooming into specific time periods.                                                                       |
| 8.3 | **Campaign relationship map**       | MEDIUM   | Visualize relationships between campaigns: shared infrastructure, shared malware families, attributed to the same threat actor group. Use a graph visualization.                                                                   |

### Backend Completeness

| #   | Improvement                           | Priority | Detail                                                                                                                                                                        |
| --- | ------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 8.4 | **Campaign CRUD with full lifecycle** | CRITICAL | Add ability to create campaigns manually (for tracking internal investigations) and automatically (from threat intel feeds). Currently appears to be read-only.               |
| 8.5 | **Campaign-alert correlation**        | HIGH     | Automatically correlate incoming alerts with known campaigns based on IOC matches, TTP matches, and behavioral patterns. Show a "Possible Campaign" badge on matching alerts. |
| 8.6 | **Threat actor profiles**             | HIGH     | Build and maintain threat actor profiles linked to campaigns. Include: known aliases, motivation, capability level, targeted sectors, attributed TTPs, historical campaigns.  |

### Integration Gaps

| #   | Improvement                           | Priority | Detail                                                                                                                                         |
| --- | ------------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| 8.7 | **Campaign → MITRE ATT&CK mapping**   | HIGH     | Each campaign should map its observed TTPs to the MITRE ATT&CK framework. Show coverage on the ATT&CK matrix view.                             |
| 8.8 | **Campaign → Kill Chain progression** | MEDIUM   | Show which kill chain phases have been observed for each campaign, helping analysts understand the campaign's maturity and predict next steps. |

---

## 9. MITRE ATT&CK

**Source:** `client/src/pages/mitre-attack.tsx` (397 lines) | `server/routes/threat-intel.ts`
**Current state:** MITRE ATT&CK matrix view with 2 queries, 2 tabs. Shows tactic/technique coverage heatmap.

### UI/UX Polish

| #   | Improvement                                       | Priority | Detail                                                                                                                                                                                             |
| --- | ------------------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 9.1 | **Full ATT&CK matrix with sub-techniques**        | HIGH     | Current matrix may show only tactics and top-level techniques. Add collapsible sub-techniques (T1059.001, T1059.003, etc.) matching the official MITRE ATT&CK matrix structure.                    |
| 9.2 | **Heatmap intensity based on detection coverage** | HIGH     | Color intensity should represent detection coverage: dark = multiple detection rules covering this technique, light = limited coverage, white/gray = no coverage. Currently may use static colors. |
| 9.3 | **Technique detail popup/panel**                  | HIGH     | Clicking a technique should show: description, detection rules covering it, recent alerts matching it, affected assets, recommended mitigations. Currently may only show basic info.               |
| 9.4 | **Coverage gap highlighting**                     | CRITICAL | Prominently highlight techniques with NO detection coverage. These are the org's blind spots. Show a summary: "23 of 201 techniques have no detection coverage (89% coverage)."                    |
| 9.5 | **ATT&CK Navigator export**                       | MEDIUM   | Export the coverage heatmap in ATT&CK Navigator JSON format for use with MITRE's official Navigator tool.                                                                                          |

### Backend Completeness

| #   | Improvement                             | Priority | Detail                                                                                                                                                                                 |
| --- | --------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 9.6 | **ATT&CK data freshness**               | HIGH     | Implement automated sync with MITRE ATT&CK STIX data (updated quarterly). Track which ATT&CK version is loaded and alert when updates are available.                                   |
| 9.7 | **Technique-to-detection-rule mapping** | CRITICAL | Build and maintain a mapping between ATT&CK techniques and the org's detection rules. This is the foundation for coverage gap analysis. Currently mapping may be manual or incomplete. |

### Integration Gaps

| #   | Improvement                                           | Priority | Detail                                                                                                                                                                |
| --- | ----------------------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 9.8 | **ATT&CK → Detection Rules gap → AI rule generation** | HIGH     | For uncovered techniques, offer a "Generate Detection Rule" button that sends the technique description to the AI Detection Rules system for automated rule creation. |
| 9.9 | **ATT&CK → Chaos Engineering simulation**             | MEDIUM   | Link uncovered or weakly covered techniques to the Security Chaos Engineering module. Allow launching BAS (Breach & Attack Simulation) tests for specific techniques. |

---

## 10. Kill Chain

**Source:** `client/src/pages/kill-chain.tsx` (589 lines) | `server/routes/threat-intel.ts`
**Current state:** Kill chain visualization with 3 queries, 1 tab. Shows Cyber Kill Chain phases with associated activity.

### UI/UX Polish

| #    | Improvement                          | Priority | Detail                                                                                                                                                                                              |
| ---- | ------------------------------------ | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 10.1 | **Interactive kill chain phases**    | HIGH     | Each phase (Reconnaissance → Weaponization → Delivery → Exploitation → Installation → C2 → Actions on Objectives) should be clickable, expanding to show alerts and incidents mapped to that phase. |
| 10.2 | **Kill chain progression animation** | MEDIUM   | For active campaigns/incidents, show an animated progression through kill chain phases. Highlight the current phase and show time spent in each phase.                                              |
| 10.3 | **Multi-framework support**          | MEDIUM   | Support additional kill chain models beyond Lockheed Martin: Diamond Model, Unified Kill Chain, MITRE ATT&CK for ICS Kill Chain. Allow switching between frameworks.                                |

### Backend Completeness

| #    | Improvement                              | Priority | Detail                                                                                                                                                                                                             |
| ---- | ---------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 10.4 | **Auto-map alerts to kill chain phases** | HIGH     | When alerts are created, automatically classify them into kill chain phases based on MITRE ATT&CK tactic mapping (Reconnaissance → Initial Access → Execution → ...). Currently may require manual classification. |
| 10.5 | **Kill chain analytics**                 | MEDIUM   | Track statistics: which phases have the most detections, average dwell time per phase, breakout time (lateral movement speed). Feed into Security Metrics.                                                         |

### Integration Gaps

| #    | Improvement                                   | Priority | Detail                                                                                                                                                              |
| ---- | --------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 10.6 | **Kill chain → Incident correlation**         | HIGH     | Show which incidents have progressed through multiple kill chain phases. Highlight incidents that have reached late stages (C2, Actions on Objectives) as critical. |
| 10.7 | **Kill chain → Autonomous Response triggers** | MEDIUM   | Configure automatic response actions when activity is detected in specific kill chain phases (e.g., auto-isolate endpoint when C2 beaconing is detected).           |

---

## 11. Security Graph

**Source:** `client/src/pages/unified-security-graph.tsx` (1,653 lines) | `server/routes/security-graph.ts`
**Current state:** Graph visualization with 7 queries, 13 tabs. Shows entity relationships, attack paths, and security topology.

### UI/UX Polish

| #    | Improvement                                           | Priority | Detail                                                                                                                                                                                                      |
| ---- | ----------------------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 11.1 | **Graph performance optimization for large datasets** | CRITICAL | With thousands of entities, the graph visualization may become sluggish. Implement level-of-detail rendering: show clusters at high zoom, individual nodes on zoom-in. Use WebGL rendering for 1000+ nodes. |
| 11.2 | **Graph layout algorithms**                           | HIGH     | Offer multiple layout options: force-directed (current), hierarchical, radial, circular, grid. Different layouts work better for different analysis tasks.                                                  |
| 11.3 | **Node/edge filtering and highlighting**              | HIGH     | Add a filter panel to show/hide node types (users, IPs, domains, files, processes) and edge types (connected-to, accessed, executed). Highlight paths matching specific criteria.                           |
| 11.4 | **Graph search with path finding**                    | HIGH     | "Find path between Entity A and Entity B" — show all connection paths with shortest-path highlighting. Essential for lateral movement analysis and blast radius assessment.                                 |
| 11.5 | **Graph snapshot and comparison**                     | MEDIUM   | Save graph state at a point in time and compare with current state to see what changed. Useful for tracking infrastructure changes and detecting anomalies.                                                 |

### Backend Completeness

| #    | Improvement                               | Priority | Detail                                                                                                                                                                                            |
| ---- | ----------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 11.6 | **Graph query language**                  | MEDIUM   | Allow analysts to query the graph using a structured query language (similar to Cypher/Gremlin): "FIND User WHERE loginCount > 100 AND lastSeen < 7d CONNECTED_TO Server WHERE isExposed = true". |
| 11.7 | **Real-time graph updates via WebSocket** | HIGH     | When new entities or relationships are discovered, update the graph in real-time instead of requiring a full refresh.                                                                             |

### Integration Gaps

| #    | Improvement                      | Priority | Detail                                                                                                                                                  |
| ---- | -------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 11.8 | **Graph → Incident creation**    | MEDIUM   | Right-click a suspicious subgraph to create an incident from selected entities. Pre-populate incident with the selected entities as affected resources. |
| 11.9 | **Graph → UEBA anomaly overlay** | MEDIUM   | Overlay UEBA anomaly scores on graph nodes. Nodes with high anomaly scores should pulse or have a warning indicator.                                    |

---

## 12. Attack Paths

**Source:** `client/src/pages/attack-graph.tsx` (649 lines) | `server/routes/security-graph.ts`
**Current state:** Attack path visualization with 4 queries, 5 tabs. Shows potential attack paths through infrastructure.

### UI/UX Polish

| #    | Improvement                              | Priority | Detail                                                                                                                                                                                                         |
| ---- | ---------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 12.1 | **Attack path risk scoring**             | CRITICAL | Each attack path should have a calculated risk score based on: number of hops, vulnerability severity at each hop, blast radius of the target, existing compensating controls. Paths should be ranked by risk. |
| 12.2 | **Attack path simulation**               | HIGH     | "What-if" analysis: simulate what happens if a specific vulnerability is exploited or a control is removed. Show how the attack path landscape changes.                                                        |
| 12.3 | **Remediation recommendations per path** | HIGH     | For each attack path, suggest the most impactful fix: which single vulnerability to patch or control to add that would eliminate the most paths. Cost-benefit analysis.                                        |

### Backend Completeness

| #    | Improvement                             | Priority | Detail                                                                                                                                                                             |
| ---- | --------------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 12.4 | **Automated attack path discovery**     | CRITICAL | Run scheduled analysis to discover new attack paths whenever the asset inventory, vulnerability data, or network topology changes. Currently paths may be computed on-demand only. |
| 12.5 | **Attack path to MITRE ATT&CK mapping** | HIGH     | Map each step in an attack path to the corresponding MITRE ATT&CK technique. This connects theoretical paths to real detection capabilities.                                       |

### Integration Gaps

| #    | Improvement                                             | Priority | Detail                                                                                                                                                                                     |
| ---- | ------------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 12.6 | **Attack paths → CSPM findings correlation**            | HIGH     | Cloud misconfigurations discovered by CSPM should feed into attack path analysis. An exposed S3 bucket connected to a database creates a critical attack path.                             |
| 12.7 | **Attack paths → Vulnerability Scanner prioritization** | HIGH     | Use attack path analysis to prioritize vulnerability remediation. A medium-severity vulnerability on a path to crown jewels is more critical than an isolated high-severity vulnerability. |

---

## 13. Entity Explorer

**Source:** `client/src/pages/entity-graph.tsx` (1,320 lines) | `server/routes/entities.ts`
**Current state:** Entity management with 8 queries, entity search, relationship visualization. Shows users, IPs, domains, files, processes.

### UI/UX Polish

| #    | Improvement                       | Priority | Detail                                                                                                                                                                                                          |
| ---- | --------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 13.1 | **Entity profile pages**          | HIGH     | Each entity should have a rich profile page showing: all known attributes, activity timeline, associated alerts, risk score history, peer comparison, first/last seen dates. Currently may show minimal detail. |
| 13.2 | **Entity search with type-ahead** | HIGH     | Search should offer type-ahead suggestions as the user types, showing matching entities across all types (users, IPs, domains) with type icons. Include recent searches.                                        |
| 13.3 | **Entity risk scoring**           | HIGH     | Calculate a dynamic risk score for each entity based on: associated alert severity, anomaly score (UEBA), exposure level (OSINT), privilege level, access patterns. Show score trend over time.                 |

### Backend Completeness

| #    | Improvement                                 | Priority | Detail                                                                                                                                                                          |
| ---- | ------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 13.4 | **Entity enrichment from multiple sources** | HIGH     | Automatically enrich entities: Users → AD/Okta profile, IPs → geo-IP + WHOIS + reputation, Domains → DNS records + certificate info, Files → hash reputation + sandbox results. |
| 13.5 | **Entity deduplication and merging**        | MEDIUM   | Detect duplicate entities (same user with different email formats, same IP in different notations) and suggest merges. Link to the Entity Resolution page.                      |

### Integration Gaps

| #    | Improvement                       | Priority | Detail                                                                                                                                                                   |
| ---- | --------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 13.6 | **Entity → Alert/Incident pivot** | HIGH     | From any entity, one-click pivot to all associated alerts and incidents. This is the core investigation workflow: "Show me everything suspicious about this IP address." |
| 13.7 | **Entity → Threat Hunting pivot** | MEDIUM   | From entity detail, launch a threat hunt query pre-populated with the entity's attributes. "Hunt for all activity involving this user across all data sources."          |

---

## 14. Entity Resolution

**Source:** `client/src/pages/entity-merge-alias.tsx` (801 lines) | `server/routes/entities.ts`
**Current state:** Entity merge and alias management with 7 queries. Handles entity deduplication and identity resolution.

### UI/UX Polish

| #    | Improvement                                    | Priority | Detail                                                                                                                                                                          |
| ---- | ---------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 14.1 | **Merge preview with side-by-side comparison** | HIGH     | Before merging entities, show a side-by-side comparison of both entities' attributes, highlighting conflicts. Let the user choose which attribute value to keep for each field. |
| 14.2 | **Merge history and undo**                     | HIGH     | Maintain a log of all entity merges with the ability to undo a merge (split entities back apart). Currently merges may be irreversible.                                         |
| 14.3 | **Auto-suggested merges**                      | MEDIUM   | Use heuristics (fuzzy name matching, shared attributes, temporal correlation) to suggest likely entity merges. Show suggestions as a review queue with confidence scores.       |

### Backend Completeness

| #    | Improvement                                 | Priority | Detail                                                                                                                                                                                        |
| ---- | ------------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 14.4 | **Cascading merge — update all references** | CRITICAL | When entities are merged, all references across the platform (alerts, incidents, playbooks, hunt results) must be updated to point to the merged entity. Verify this cascade works correctly. |
| 14.5 | **Alias management**                        | HIGH     | Allow adding aliases to entities (e.g., user@company.com is also admin@company.com). Alerts matching any alias should be attributed to the canonical entity.                                  |

---

## 15. War Room

**Source:** `client/src/pages/war-room.tsx` (1,125 lines) | `server/routes/war-room.ts`
**Current state:** Real-time collaborative investigation workspace with 18 queries. Persistent chat, evidence pinning, timeline, team presence.

### UI/UX Polish

| #    | Improvement                                | Priority | Detail                                                                                                                                                                              |
| ---- | ------------------------------------------ | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 15.1 | **Rich text editor for war room messages** | HIGH     | Replace plain text input with a rich text editor supporting: markdown, code blocks with syntax highlighting, inline images, file attachments, @mentions with user autocomplete.     |
| 15.2 | **Message threading**                      | HIGH     | Support threaded replies on war room messages. Long investigations generate hundreds of messages — threading helps organize parallel discussion tracks.                             |
| 15.3 | **War room templates**                     | MEDIUM   | Pre-configured war room templates for common incident types (ransomware response, data breach, phishing campaign). Templates pre-create channels, checklists, and role assignments. |
| 15.4 | **Audio/video call integration**           | LOW      | Add a "Start Call" button that launches a video conference (integrate with Google Meet, Zoom, or WebRTC-based solution) within the war room context.                                |
| 15.5 | **War room activity log**                  | MEDIUM   | Separate from chat messages, maintain an automatic activity log: who joined/left, what evidence was pinned/unpinned, what status changes occurred, what playbooks were triggered.   |

### Backend Completeness

| #    | Improvement                           | Priority | Detail                                                                                                                                                                                  |
| ---- | ------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 15.6 | **War room persistence and archival** | HIGH     | Completed war rooms should be archived with full history preserved. Support searching archived war rooms for historical reference. Add export to PDF/HTML for compliance documentation. |
| 15.7 | **Role-based access in war rooms**    | MEDIUM   | Support roles within a war room: Incident Commander (full control), Analyst (can add evidence and post), Observer (read-only). Currently all members may have equal access.             |

### Integration Gaps

| #    | Improvement                                         | Priority | Detail                                                                                                                                                                                 |
| ---- | --------------------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 15.8 | **War room → Playbook execution**                   | HIGH     | Trigger playbooks directly from the war room with results posted back to the chat. "I'm running the 'Isolate Endpoint' playbook on 10.0.0.5" → playbook output appears in war room.    |
| 15.9 | **War room → Post-incident review auto-generation** | MEDIUM   | When a war room is closed, auto-generate a post-incident review document from the chat history, evidence pins, and timeline. Pre-fill with key decisions, actions taken, and timeline. |

---

## 16. Threat Hunting

**Source:** `client/src/pages/threat-hunting.tsx` (1,963 lines) | `server/routes/threat-hunting.ts`, `server/hunt-engine.ts`
**Current state:** Full-featured threat hunting workbench with 33 queries/mutations, 15 tabs, 3 charts. Query engine with custom hunt language, hunt library, pivot interface, MITRE ATT&CK navigator, scheduled hunts.

### UI/UX Polish

| #    | Improvement                                   | Priority | Detail                                                                                                                                                                                                            |
| ---- | --------------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 16.1 | **Query editor with syntax highlighting**     | HIGH     | The hunt query editor should have syntax highlighting, auto-complete for field names, and inline error markers. Use CodeMirror or Monaco editor with a custom language definition for the hunt query language.    |
| 16.2 | **Query result visualization options**        | HIGH     | Hunt results should be viewable as: table (current), timeline, graph (entity relationships), geographic map (for IP results), bar chart (for aggregations). Let the analyst choose the best view for their query. |
| 16.3 | **Hunt notebook — multi-step investigations** | MEDIUM   | Support notebook-style investigations where analysts chain multiple queries. Each step's output feeds the next step's input. Save as a reusable hunt template. Similar to Jupyter notebooks for security.         |
| 16.4 | **Collaborative hunting**                     | MEDIUM   | Multiple analysts should be able to work on the same hunt simultaneously, seeing each other's cursors and results in real-time. Similar to collaborative document editing.                                        |

### Backend Completeness

| #    | Improvement                               | Priority | Detail                                                                                                                                                                        |
| ---- | ----------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 16.5 | **Query optimization and execution plan** | HIGH     | For complex queries, show an execution plan (which data sources will be queried, estimated time, estimated row count) before executing. Allow canceling long-running queries. |
| 16.6 | **Hunt result caching**                   | MEDIUM   | Cache hunt query results server-side for a configurable TTL. Repeated queries with the same parameters should return cached results instantly. Show cache hit/miss status.    |
| 16.7 | **Scheduled hunts with drift detection**  | HIGH     | Scheduled hunts should compare current results with previous execution results and alert on significant changes (new IOCs found, new entities appearing, behavioral shifts).  |

### Integration Gaps

| #     | Improvement                          | Priority | Detail                                                                                                                                                                                                                                            |
| ----- | ------------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 16.8  | **Hunt → Incident escalation**       | HIGH     | When a hunt discovers malicious activity, provide a one-click "Escalate to Incident" that creates an incident pre-populated with the hunt findings, query, and affected entities. Currently implemented but verify the data transfer is complete. |
| 16.9  | **Hunt → Detection Rule conversion** | HIGH     | When a hunt query reliably detects threats, convert it into a permanent detection rule. Provide a "Save as Detection Rule" button that translates the hunt query into a Sigma rule.                                                               |
| 16.10 | **Hunt library → Community sharing** | LOW      | Allow publishing hunt queries to the Community Threat Intel network for sharing with industry peers. Include anonymized statistics on detection rates.                                                                                            |

---

## 17. Investigation Timeline

**Source:** `client/src/pages/investigation-timeline.tsx` (364 lines) | `server/routes/investigation-timeline.ts`
**Current state:** Basic timeline view with 7 queries. Shows chronological investigation events.

### UI/UX Polish

| #    | Improvement                           | Priority | Detail                                                                                                                                                                                                                     |
| ---- | ------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 17.1 | **Visual timeline with zoom and pan** | CRITICAL | At 364 lines, this page is minimal. Upgrade to a rich visual timeline: horizontal time axis with zoom (minutes → hours → days), swimlanes per actor/system, event clustering for busy periods, color-coding by event type. |
| 17.2 | **Event detail expansion**            | HIGH     | Each timeline event should expand on click to show full detail: raw log data, associated alert, analyst notes, automated actions taken. Currently may show only summary text.                                              |
| 17.3 | **Timeline annotation**               | HIGH     | Analysts should be able to add annotations and markers on the timeline: "Attack started here", "Containment initiated", "All-clear". Annotations should persist and be visible to all team members.                        |
| 17.4 | **Multi-incident timeline overlay**   | MEDIUM   | Compare timelines of multiple incidents side-by-side to identify patterns or coordinated attacks across incidents.                                                                                                         |

### Backend Completeness

| #    | Improvement                                      | Priority | Detail                                                                                                                                                                                                            |
| ---- | ------------------------------------------------ | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 17.5 | **Auto-populate timeline from all data sources** | HIGH     | Timeline should automatically aggregate events from: alerts, incident status changes, playbook executions, analyst actions, war room messages, entity discoveries. Currently may only show manually added events. |
| 17.6 | **Timeline export**                              | MEDIUM   | Export timeline to: PDF (for reports), CSV (for analysis), STIX (for sharing). Include all events, annotations, and evidence references.                                                                          |

---

## 18. Evidence Chain

**Source:** `client/src/pages/evidence-chain-viewer.tsx` (533 lines) | `server/routes/evidence-custody.ts`
**Current state:** Evidence chain of custody viewer with 3 queries. Shows evidence items and their custody history.

### UI/UX Polish

| #    | Improvement                             | Priority | Detail                                                                                                                                                                                                 |
| ---- | --------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 18.1 | **Visual chain of custody graph**       | HIGH     | Show evidence chain as a visual flow diagram: who collected → who transferred → who analyzed → where stored. Each node shows timestamp, handler, and action. Useful for legal and compliance purposes. |
| 18.2 | **Evidence integrity verification**     | HIGH     | Display hash verification status for each evidence item. Show a green checkmark if the hash matches the original, red if tampered. Essential for forensic integrity.                                   |
| 18.3 | **Evidence tagging and categorization** | MEDIUM   | Add tags to evidence items (malware sample, network capture, memory dump, log file, screenshot). Filter evidence list by tag.                                                                          |

### Backend Completeness

| #    | Improvement                                    | Priority | Detail                                                                                                                                                                                         |
| ---- | ---------------------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 18.4 | **Evidence file upload with hash calculation** | HIGH     | When evidence files are uploaded, automatically calculate and store SHA-256 hash. Support large files via chunked upload. Store files in S3-compatible storage with server-side encryption.    |
| 18.5 | **Evidence retention policies**                | MEDIUM   | Configure retention policies per evidence type (e.g., malware samples kept for 2 years, network captures for 90 days). Auto-archive or delete evidence past retention period with audit trail. |

---

## 19. Evidence Locker

**Source:** `client/src/pages/evidence-custody.tsx` (478 lines) | `server/routes/evidence-custody.ts`
**Current state:** Evidence custody management with 8 queries. Handles evidence storage, access control, and chain of custody logging.

### UI/UX Polish

| #    | Improvement                 | Priority | Detail                                                                                                                                                             |
| ---- | --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 19.1 | **Evidence preview**        | HIGH     | Support inline preview of common evidence types: images, text files, JSON, CSV, PDF. Currently may require downloading to view. For binary files, show hex viewer. |
| 19.2 | **Access request workflow** | MEDIUM   | Sensitive evidence should require access approval. Implement a request → approve → access workflow with notification to the evidence custodian.                    |
| 19.3 | **Evidence comparison**     | LOW      | Side-by-side comparison of two evidence items (useful for comparing malware samples, configuration diffs, log file versions).                                      |

### Backend Completeness

| #    | Improvement                                      | Priority | Detail                                                                                                                                                                   |
| ---- | ------------------------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 19.4 | **Evidence access audit logging**                | CRITICAL | Log every access to every evidence item: who viewed, when, from what IP. This is required for legal admissibility. Verify comprehensive audit trail exists.              |
| 19.5 | **Evidence export with chain of custody report** | HIGH     | Export evidence item with a PDF chain of custody report attached. Include all handlers, timestamps, hash verifications, and access logs. Required for court submissions. |

---

## 20. Playbooks

**Source:** `client/src/pages/playbooks.tsx` (2,639 lines) | `server/routes/playbooks.ts`
**Current state:** Rich playbook system with 23 queries/mutations, 17 tabs, visual workflow editor, execution engine, condition branching, parallel steps, approval gates. One of the most feature-complete pages.

### UI/UX Polish

| #    | Improvement                                 | Priority | Detail                                                                                                                                                                                                                         |
| ---- | ------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 20.1 | **Visual workflow editor improvements**     | HIGH     | The workflow editor should support: undo/redo, copy/paste steps, zoom to fit, minimap for complex playbooks, step grouping (collapse multiple steps into a named group), and connection routing that avoids overlapping lines. |
| 20.2 | **Playbook execution monitoring dashboard** | HIGH     | Real-time view of all currently running playbook instances: which step is executing, time elapsed, any steps waiting for approval, any errors. Currently execution status may only be visible from individual playbook detail. |
| 20.3 | **Playbook version diffing**                | MEDIUM   | Compare two versions of a playbook side-by-side. Show added/removed/modified steps. Allow reverting to a previous version.                                                                                                     |
| 20.4 | **Playbook dry-run / simulation mode**      | HIGH     | Execute a playbook in simulation mode where actions are logged but not actually performed. Shows what would happen without making changes. Essential for testing new playbooks.                                                |

### Backend Completeness

| #    | Improvement                               | Priority | Detail                                                                                                                                                                                                                        |
| ---- | ----------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 20.5 | **Playbook step timeout handling**        | HIGH     | Each playbook step should have a configurable timeout. If a step exceeds its timeout, execute a fallback action (skip, retry, abort, notify). Currently steps may hang indefinitely if the underlying action doesn't respond. |
| 20.6 | **Playbook execution retry with backoff** | MEDIUM   | Failed playbook steps should support automatic retry with exponential backoff. Configure max retries and backoff parameters per step.                                                                                         |
| 20.7 | **Playbook execution analytics**          | MEDIUM   | Track and report: average execution time per playbook, success/failure rates, most commonly triggered playbooks, steps with highest failure rates. Feed into Security Metrics.                                                |

### Integration Gaps

| #     | Improvement                                  | Priority | Detail                                                                                                                                                                                                                                               |
| ----- | -------------------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 20.8  | **Playbook → All response action types**     | HIGH     | Ensure playbook steps can trigger every response action type: isolate endpoint, block IP/domain, disable user account, quarantine email, create firewall rule, update detection rule. Verify all connector actions are accessible as playbook steps. |
| 20.9  | **Playbook → Notification channels**         | MEDIUM   | Playbook steps should be able to send notifications via: email, Slack, Teams, PagerDuty, webhook. Allow configuring notification content templates with variable substitution.                                                                       |
| 20.10 | **Playbook → Change management integration** | LOW      | For playbooks that make infrastructure changes (firewall rules, account disables), integrate with change management: create a change ticket, require approval, log the change.                                                                       |

---

## 21. Autonomous Response

**Source:** `client/src/pages/autonomous-response.tsx` (903 lines) | `server/routes/autonomous.ts`
**Current state:** Autonomous response management with 14 queries/mutations, 9 tabs. Response action history, approval workflows, rollback capabilities.

### UI/UX Polish

| #    | Improvement                        | Priority | Detail                                                                                                                                                                                              |
| ---- | ---------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 21.1 | **Response action approval queue** | HIGH     | Pending response actions awaiting human approval should be shown in a prominent queue with one-click approve/deny. Show action details, affected assets, and risk assessment before approval.       |
| 21.2 | **Response action impact preview** | HIGH     | Before executing a response action, show a preview of its impact: "Isolating 10.0.0.5 will disconnect 3 active user sessions and affect 2 running services." Help analysts make informed decisions. |
| 21.3 | **Response action timeline**       | MEDIUM   | Show all response actions on a timeline view: when initiated, by whom/what, current status, duration, outcome. Filter by action type, target, and status.                                           |

### Backend Completeness

| #    | Improvement                       | Priority | Detail                                                                                                                                                                                                |
| ---- | --------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 21.4 | **Response action idempotency**   | HIGH     | Ensure response actions are idempotent: running "block IP" twice for the same IP should not create duplicate firewall rules or cause errors. Track action state to prevent duplicate execution.       |
| 21.5 | **Response action health checks** | HIGH     | After executing a response action, run a verification check: "Did the endpoint actually get isolated? Is the IP actually blocked?" Report verification status.                                        |
| 21.6 | **Graduated autonomous response** | MEDIUM   | Implement confidence-based automation: high-confidence detections (>95%) auto-execute, medium (70-95%) require approval, low (<70%) are suggested only. Make thresholds configurable per action type. |

### Integration Gaps

| #    | Improvement                          | Priority | Detail                                                                                                                                                                                                                                                                                |
| ---- | ------------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 21.7 | **Response → Connector execution**   | CRITICAL | Verify all response actions actually execute through the connector framework: EDR isolation (CrowdStrike, SentinelOne, Defender), firewall blocking (Palo Alto, FortiGate), identity disable (Okta, Azure AD). Currently actions may be logged but not executed against real systems. |
| 21.8 | **Response → Rollback verification** | HIGH     | When a response action is rolled back, verify the rollback succeeded: "Is the endpoint actually un-isolated? Is the IP actually unblocked?"                                                                                                                                           |

---

## 22. Rollback History

**Source:** `client/src/pages/rollback-history.tsx` (271 lines) | `server/routes/autonomous.ts`
**Current state:** Basic rollback history with 3 queries. Shows previous rollback actions.

### UI/UX Polish

| #    | Improvement                  | Priority | Detail                                                                                                                                                                                          |
| ---- | ---------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 22.1 | **Rollback detail view**     | HIGH     | At 271 lines, this page is minimal. Each rollback should show: original action, rollback action, who initiated, why, before/after state comparison, verification status.                        |
| 22.2 | **Rollback impact analysis** | MEDIUM   | Show what happened between the original action and the rollback: "Endpoint was isolated for 47 minutes. During that time, 3 user sessions were terminated and 2 service alerts were generated." |

### Backend Completeness

| #    | Improvement                     | Priority | Detail                                                                                                                                                                                                   |
| ---- | ------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 22.3 | **Automatic rollback triggers** | HIGH     | Configure automatic rollback conditions: "If endpoint isolation causes more than 5 service alerts within 10 minutes, auto-rollback." Prevents response actions from causing more damage than the threat. |
| 22.4 | **Rollback audit trail**        | MEDIUM   | Comprehensive audit trail for every rollback: who requested, who approved, what changed, verification result. Required for compliance.                                                                   |

---

## 23. Playbook Library

**Source:** `client/src/pages/playbook-templates.tsx` (291 lines) | `server/routes/playbook-templates.ts`
**Current state:** Playbook template library with 6 queries. Pre-built playbook templates that can be imported and customized.

### UI/UX Polish

| #    | Improvement                              | Priority | Detail                                                                                                                                                                      |
| ---- | ---------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 23.1 | **Template categorization and search**   | HIGH     | Templates should be categorized (Incident Response, Threat Hunting, Compliance, Remediation) with tag-based filtering and full-text search. Currently may show a flat list. |
| 23.2 | **Template preview without importing**   | HIGH     | Show a read-only preview of the template's workflow, steps, and configuration before importing. Help users evaluate if the template fits their needs.                       |
| 23.3 | **Template rating and usage statistics** | LOW      | Show community ratings and usage counts for each template. "This template has been imported 47 times and rated 4.5/5."                                                      |

### Backend Completeness

| #    | Improvement                         | Priority | Detail                                                                                                                                                                                                                                |
| ---- | ----------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 23.4 | **Expand template library**         | HIGH     | Add more pre-built templates for common scenarios: phishing response, ransomware containment, data breach notification, insider threat investigation, compliance audit, vulnerability patching. Currently the library may be limited. |
| 23.5 | **Template versioning and updates** | MEDIUM   | When a template is updated, notify users who have imported previous versions. Allow updating imported playbooks to the latest template version while preserving customizations.                                                       |

---

## 24. Runbook Library

**Source:** `client/src/pages/runbook-templates.tsx` (505 lines) | `server/routes/playbook-templates.ts`
**Current state:** Runbook template library with 6 queries. Procedural step-by-step guides for manual operations.

### UI/UX Polish

| #    | Improvement                    | Priority | Detail                                                                                                                                                                        |
| ---- | ------------------------------ | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 24.1 | **Runbook execution tracking** | HIGH     | When an analyst follows a runbook, track progress through the steps: which steps are completed, which are pending, time spent per step. Allow pausing and resuming.           |
| 24.2 | **Runbook step checklists**    | HIGH     | Each runbook step should be a checklist item that the analyst marks as done. Show overall progress percentage. Add notes field per step for the analyst to document findings. |
| 24.3 | **Runbook print/PDF export**   | MEDIUM   | Export runbooks as printable PDFs for use during incidents when screen access may be limited (physical security incidents, network outages).                                  |

### Backend Completeness

| #    | Improvement                       | Priority | Detail                                                                                                                                                          |
| ---- | --------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 24.4 | **Runbook analytics**             | MEDIUM   | Track: average completion time per runbook, completion rates, steps most commonly skipped, steps with longest duration. Use data to improve runbooks over time. |
| 24.5 | **Runbook → Playbook conversion** | MEDIUM   | Allow converting manual runbook steps into automated playbook steps where possible. Suggest which steps can be automated based on available integrations.       |

---

## 25. CSPM

**Source:** `client/src/pages/cspm.tsx` (2,062 lines) | `server/routes/compliance.ts`, `server/cspm-scanner.ts`
**Current state:** Cloud Security Posture Management with 24 queries/mutations, 17 tabs. AWS/Azure/GCP scanning, drift detection, DSPM, attack paths, auto-remediation, misconfig findings.

### UI/UX Polish

| #    | Improvement                                           | Priority | Detail                                                                                                                                                                                   |
| ---- | ----------------------------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 25.1 | **Cloud resource inventory tree view**                | HIGH     | Show cloud resources in a hierarchical tree: Account → Region → Service → Resource. Currently resources may be shown in a flat table. Tree view helps analysts understand scope.         |
| 25.2 | **Compliance posture by framework per cloud account** | HIGH     | Show compliance scores broken down by framework (CIS Benchmarks, SOC 2, PCI DSS) per cloud account. Allow drilling into specific failing controls.                                       |
| 25.3 | **Drift detection visualization**                     | HIGH     | When a configuration drift is detected, show a visual diff: expected vs. actual configuration. Highlight the specific field that changed. Show drift timeline (when did it first drift). |
| 25.4 | **Multi-cloud unified view**                          | MEDIUM   | Single dashboard showing posture across all connected cloud accounts (AWS, Azure, GCP) with a unified scoring methodology. Currently each cloud may be shown separately.                 |

### Backend Completeness

| #    | Improvement                          | Priority | Detail                                                                                                                                                                                                        |
| ---- | ------------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 25.5 | **Scheduled scanning**               | HIGH     | Cloud scans should run on a configurable schedule (hourly, daily). Currently scans may be on-demand only. Show last scan time and next scheduled scan.                                                        |
| 25.6 | **Auto-remediation safety controls** | CRITICAL | Auto-remediation actions should have safety rails: dry-run first, require approval for destructive changes, rollback capability if remediation causes issues. Verify these controls exist and work correctly. |
| 25.7 | **Resource change tracking**         | MEDIUM   | Track cloud resource changes over time: what changed, when, by whom. Compare current state vs. previous scan. Alert on unexpected changes (outside change windows).                                           |

### Integration Gaps

| #     | Improvement                          | Priority | Detail                                                                                                                                                                                           |
| ----- | ------------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 25.8  | **CSPM → Attack Path analysis**      | HIGH     | CSPM findings (exposed resources, overly permissive IAM) should feed into Attack Path analysis. A publicly accessible S3 bucket with access to an RDS database creates a critical attack path.   |
| 25.9  | **CSPM → Compliance Center mapping** | HIGH     | Map CSPM findings to compliance framework controls. Show how cloud misconfigurations affect compliance posture. Auto-generate compliance evidence from CSPM scan results.                        |
| 25.10 | **CSPM → Incident correlation**      | MEDIUM   | When a security incident involves cloud resources, automatically pull CSPM findings for those resources to provide context: "This EC2 instance had 3 CSPM findings at the time of the incident." |

---

## 26. Endpoint Telemetry

**Source:** `client/src/pages/endpoint-telemetry.tsx` (775 lines) | `server/routes/endpoints.ts`
**Current state:** Endpoint telemetry management with 6 queries, 5 tabs. Shows endpoint status, OS distribution, last check-in times.

### UI/UX Polish

| #    | Improvement                     | Priority | Detail                                                                                                                                                                                                              |
| ---- | ------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 26.1 | **Endpoint detail page**        | HIGH     | Each endpoint should have a rich detail page: installed software, running processes, open ports, network connections, user sessions, security agent status, compliance state. Currently may show only summary info. |
| 26.2 | **Endpoint status at-a-glance** | HIGH     | Dashboard showing: total endpoints, online/offline counts, endpoints with outdated agents, endpoints with critical vulnerabilities, endpoints failing compliance checks.                                            |
| 26.3 | **Endpoint group management**   | MEDIUM   | Group endpoints by: department, location, OS type, criticality. Apply policies and view metrics per group.                                                                                                          |

### Backend Completeness

| #    | Improvement                                 | Priority | Detail                                                                                                                                                           |
| ---- | ------------------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 26.4 | **Real-time endpoint status via heartbeat** | HIGH     | Endpoints should send periodic heartbeats. Show real-time online/offline status. Alert when critical endpoints go offline. Currently check-in may be infrequent. |
| 26.5 | **Endpoint software inventory sync**        | MEDIUM   | Maintain a current software inventory per endpoint. Cross-reference with CVE database for vulnerability detection.                                               |

### Integration Gaps

| #    | Improvement                                    | Priority | Detail                                                                                                                                       |
| ---- | ---------------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| 26.6 | **Endpoint → Vuln Scanner correlation**        | HIGH     | Link endpoint telemetry with vulnerability scan results. Show vulnerabilities per endpoint. Priority patching based on endpoint criticality. |
| 26.7 | **Endpoint → Native Sensor deployment status** | HIGH     | Show which endpoints have SecureNexus native sensors deployed and their status. Identify endpoints with no coverage.                         |

---

## 27. Vulnerability Management

**Source:** `client/src/pages/security-posture.tsx` (607 lines) | `server/routes/standalone-platform.ts`, `server/posture-engine-v2.ts`
**Current state:** Security posture / vulnerability management with 7 queries, 5 tabs. Shows vulnerability overview, remediation tracking.

### UI/UX Polish

| #    | Improvement                             | Priority | Detail                                                                                                                                                                                            |
| ---- | --------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 27.1 | **Vulnerability prioritization matrix** | CRITICAL | Prioritize vulnerabilities using: CVSS score + EPSS probability + asset criticality + attack path exposure + compensating controls. Show a prioritized remediation queue, not just a sorted list. |
| 27.2 | **Vulnerability aging report**          | HIGH     | Show how long each vulnerability has been open. Track SLA compliance: "Critical vulns must be remediated within 7 days." Show aging distribution histogram.                                       |
| 27.3 | **Remediation tracking workflow**       | HIGH     | For each vulnerability, track: identified → assigned → in progress → verified → closed. Show assignee, due date, and SLA status. Send reminders for overdue items.                                |
| 27.4 | **Vulnerability trend charts**          | MEDIUM   | Show trends: new vulnerabilities per week, remediation rate, mean time to remediate by severity, vulnerability debt (open vulns over time).                                                       |

### Backend Completeness

| #    | Improvement                                    | Priority | Detail                                                                                                                                                        |
| ---- | ---------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 27.5 | **Scanner integration for automated scanning** | HIGH     | Integrate with vulnerability scanners (Nessus, Qualys, Rapid7) to import scan results automatically. Currently may rely on manual import or limited scanning. |
| 27.6 | **Patch verification**                         | MEDIUM   | After a patch is applied, automatically re-scan to verify the vulnerability is resolved. Mark as "verified fixed" vs. "reported fixed."                       |

### Integration Gaps

| #    | Improvement                              | Priority | Detail                                                                                                                           |
| ---- | ---------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------- |
| 27.7 | **Vuln management → Attack Path impact** | HIGH     | Show which attack paths each vulnerability enables. Prioritize vulns that appear in the most critical attack paths.              |
| 27.8 | **Vuln management → CSPM correlation**   | MEDIUM   | Cloud vulnerabilities from CSPM and infrastructure vulnerabilities from scanners should be unified in a single prioritized view. |

---

## 28. JIT Access

**Source:** `client/src/pages/jit-secret-access.tsx` (919 lines) | `server/routes/jit-secret-access.ts`
**Current state:** Just-In-Time privileged access management with 8 queries, 3 tabs. Access request workflow, time-limited access grants.

### UI/UX Polish

| #    | Improvement                                | Priority | Detail                                                                                                                                                  |
| ---- | ------------------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 28.1 | **Access request form with justification** | HIGH     | Request form should require: target system, required role/permissions, duration, business justification. Show approval workflow (who needs to approve). |
| 28.2 | **Active session monitoring**              | HIGH     | Show all currently active JIT sessions: who, what system, what permissions, time remaining. Allow emergency revocation.                                 |
| 28.3 | **Access request history with analytics**  | MEDIUM   | Show request patterns: frequency by user, most requested systems, average duration, approval rates. Identify unusual request patterns.                  |

### Backend Completeness

| #    | Improvement                             | Priority | Detail                                                                                                                                                                   |
| ---- | --------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 28.4 | **Automatic access revocation**         | CRITICAL | When a JIT access window expires, automatically revoke the access. Verify revocation succeeded. Currently may rely on manual revocation or time-based token expiry only. |
| 28.5 | **Session recording during JIT access** | HIGH     | Record all actions taken during a JIT access session for audit purposes. Link session recording to the access request.                                                   |
| 28.6 | **Multi-level approval workflow**       | MEDIUM   | Support multi-level approval: manager → security team → system owner. Configure approval chains per target system based on sensitivity.                                  |

---

## 29. Secret Rotation

**Source:** `client/src/pages/secret-rotation-overview.tsx` (382 lines) | `server/routes/jit-secret-access.ts`
**Current state:** Secret rotation overview with 2 queries. Shows rotation status and schedules.

### UI/UX Polish

| #    | Improvement                         | Priority | Detail                                                                                                                                                                                                    |
| ---- | ----------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 29.1 | **Secret inventory dashboard**      | CRITICAL | At 382 lines, this page is very thin. Show a comprehensive secret inventory: API keys, certificates, database passwords, service tokens. For each: age, last rotated, rotation schedule, expiration date. |
| 29.2 | **Rotation health indicators**      | HIGH     | Color-coded status per secret: green (recently rotated), yellow (approaching rotation deadline), red (overdue for rotation), critical (expired).                                                          |
| 29.3 | **Certificate expiration timeline** | HIGH     | Calendar view showing upcoming certificate expirations. Alert before expiration (30/14/7/1 days). Support auto-renewal for supported certificate authorities.                                             |

### Backend Completeness

| #    | Improvement                      | Priority | Detail                                                                                                                                                                                                   |
| ---- | -------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 29.4 | **Automated rotation execution** | CRITICAL | Actually rotate secrets automatically: generate new secret → update dependent services → verify services work → revoke old secret. Currently may only track rotation status without executing rotations. |
| 29.5 | **Rotation impact analysis**     | HIGH     | Before rotating a secret, show which services depend on it. Warn about potential downtime. Support staged rollout: update service A, verify, then update service B.                                      |

---

## 30. AI Engine

**Source:** `client/src/pages/ai-engine.tsx` (1,511 lines) | `server/routes/ai.ts`, `server/ai.ts`
**Current state:** AI investigation engine with 10 queries, 5 tabs, 4 charts. Multi-turn investigation chat, SSE streaming, attack graph generation, narrative analysis.

### UI/UX Polish

| #    | Improvement                                           | Priority | Detail                                                                                                                                                                                 |
| ---- | ----------------------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 30.1 | **Investigation chat — streaming response rendering** | HIGH     | SSE streaming responses should render progressively with proper markdown formatting: headers, bullet points, code blocks, tables. Currently may render as plain text during streaming. |
| 30.2 | **Investigation history search**                      | HIGH     | Search across all past AI investigations by keyword, date range, incident ID. Currently finding a previous investigation requires scrolling through history.                           |
| 30.3 | **AI confidence indicators**                          | HIGH     | Each AI finding should show a confidence score (low/medium/high) with explanation of why. Help analysts quickly identify which AI conclusions need manual verification.                |
| 30.4 | **AI investigation export**                           | MEDIUM   | Export a complete AI investigation (prompt, response, graphs, findings) as a PDF report. Include in incident documentation.                                                            |

### Backend Completeness

| #    | Improvement                     | Priority | Detail                                                                                                                                                                                                            |
| ---- | ------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 30.5 | **Context window optimization** | HIGH     | The RAG system should intelligently select the most relevant context documents. Monitor and report context window utilization. Warn when context is truncated due to token limits.                                |
| 30.6 | **AI hallucination detection**  | HIGH     | Cross-reference AI findings against actual data. Flag assertions that can't be verified from the provided context. Prevent the AI from stating facts not supported by evidence.                                   |
| 30.7 | **Multi-model support**         | MEDIUM   | Support switching between AI models (Claude, GPT-4, local LLMs) based on use case. Some queries need fast responses (Haiku), others need deep analysis (Opus). Make model selection configurable per prompt type. |

### Integration Gaps

| #    | Improvement                               | Priority | Detail                                                                                                                                                                                                        |
| ---- | ----------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 30.8 | **AI Engine → All data sources**          | CRITICAL | Ensure the AI can query: alerts, incidents, entities, threat intel, OSINT, UEBA scores, endpoint telemetry, network flows, cloud configurations. Currently may only have access to a subset of platform data. |
| 30.9 | **AI Engine → Response action execution** | HIGH     | Allow the AI to suggest and (with approval) execute response actions. "I recommend isolating endpoint 10.0.0.5 — shall I proceed?" → triggers the response action pipeline.                                   |

---

## 31. SOC Co-Pilot

**Source:** `client/src/pages/soc-copilot.tsx` (1,337 lines) | `server/routes/soc-copilot.ts`
**Current state:** SOC Co-Pilot chat interface with 13 queries, 2 charts. Contextual assistance for SOC analysts.

### UI/UX Polish

| #    | Improvement                           | Priority | Detail                                                                                                                                                                                                                                                                          |
| ---- | ------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 31.1 | **Context-aware suggestions**         | HIGH     | Co-Pilot should proactively suggest actions based on the current page context. On the Alerts page: "I see 5 critical alerts from the same source — would you like me to correlate them?" On Incidents: "This incident has been open for 48 hours — shall I suggest escalation?" |
| 31.2 | **Quick action buttons in responses** | HIGH     | Co-Pilot responses should include actionable buttons: "Block this IP", "Escalate to Incident", "Run Playbook X", "Create Detection Rule". One-click to execute AI recommendations.                                                                                              |
| 31.3 | **Persistent Co-Pilot sidebar**       | MEDIUM   | Allow keeping the Co-Pilot open as a sidebar panel while navigating the platform. Currently may be a full-page view that interrupts workflow.                                                                                                                                   |

### Backend Completeness

| #    | Improvement                             | Priority | Detail                                                                                                                                                                                                     |
| ---- | --------------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 31.4 | **Conversation memory across sessions** | HIGH     | Co-Pilot should remember previous conversations and analyst preferences. "Last time you asked about similar alerts, you resolved them by blocking the source IP."                                          |
| 31.5 | **Skill-based routing**                 | MEDIUM   | Route Co-Pilot queries to specialized prompts based on the question type: threat intel queries → threat intel prompt, compliance questions → compliance prompt, remediation guidance → remediation prompt. |

---

## 32. Prompt Builder

**Source:** `client/src/pages/prompt-to-artifact.tsx` (919 lines) | `server/routes/prompt-artifact.ts`
**Current state:** Prompt-to-artifact generator with 10 queries, 3 charts. Generate security artifacts (rules, reports, playbooks) from natural language prompts.

### UI/UX Polish

| #    | Improvement                                | Priority | Detail                                                                                                                                                                    |
| ---- | ------------------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 32.1 | **Artifact type selection with templates** | HIGH     | Offer artifact type selection upfront: Detection Rule, Playbook, Report Template, Hunt Query, Compliance Check. Each type should have example prompts and best practices. |
| 32.2 | **Generated artifact preview and editing** | HIGH     | Show the generated artifact in a preview mode with the ability to edit before saving. Syntax highlighting for rule languages (Sigma, YARA, KQL).                          |
| 32.3 | **Prompt history and favorites**           | MEDIUM   | Save prompt history. Allow marking prompts as favorites for reuse. Share prompts with team members.                                                                       |

### Backend Completeness

| #    | Improvement                      | Priority | Detail                                                                                                                                                                                                      |
| ---- | -------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 32.4 | **Artifact validation**          | HIGH     | Validate generated artifacts: Sigma rules should pass schema validation, playbooks should have valid step references, reports should reference existing data sources. Show validation errors before saving. |
| 32.5 | **Artifact deployment pipeline** | MEDIUM   | Generated artifacts should be deployable: detection rules → Detection Rules page, playbooks → Playbooks page, reports → Reports page. One-click deploy with rollback capability.                            |

---

## 33. Model Gateway

**Source:** `client/src/pages/model-gateway.tsx` (884 lines) | `server/routes/model-gateway.ts`
**Current state:** AI model gateway with 4 queries, 11 tabs, 2 charts. Model routing, rate limiting, cost tracking.

### UI/UX Polish

| #    | Improvement                       | Priority | Detail                                                                                                                                                                         |
| ---- | --------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 33.1 | **Model comparison dashboard**    | HIGH     | Side-by-side comparison of model performance: response time, accuracy, cost per query, error rate. Help admins choose the right model for each use case.                       |
| 33.2 | **Model routing rules UI**        | HIGH     | Visual editor for routing rules: "Use Claude Sonnet for triage, Claude Opus for deep investigation, Haiku for auto-responses." Currently rules may be configured as text/JSON. |
| 33.3 | **Cost tracking and forecasting** | HIGH     | Show AI cost breakdown by model, by use case, by user. Project future costs based on usage trends. Alert when approaching budget limits.                                       |

### Backend Completeness

| #    | Improvement                          | Priority | Detail                                                                                                                                                                                   |
| ---- | ------------------------------------ | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 33.4 | **Model health monitoring**          | HIGH     | Monitor model endpoint health: latency, error rate, throughput. Auto-failover to backup model if primary is degraded. Currently model health is shown but failover may not be automatic. |
| 33.5 | **Token usage tracking per request** | MEDIUM   | Track exact token usage (input + output) for every AI request. Use for accurate cost allocation and budget enforcement.                                                                  |
| 33.6 | **Model version management**         | MEDIUM   | Track which model versions are in use. Support A/B testing between model versions. Rollback to previous version if new version underperforms.                                            |

---

## 34. Prompt Registry

**Source:** `client/src/pages/ai-prompt-registry.tsx` (1,207 lines) | `server/ai/prompt-registry.ts`
**Current state:** Prompt template management with 6 queries, 6 tabs. Version control, diff viewer, test interface.

### UI/UX Polish

| #    | Improvement                       | Priority | Detail                                                                                                                                                                                                                      |
| ---- | --------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 34.1 | **Prompt A/B testing dashboard**  | HIGH     | Show A/B test results: compare quality scores, response times, and user satisfaction between prompt versions. Visualize performance differences with charts.                                                                |
| 34.2 | **Prompt variable documentation** | HIGH     | Each prompt template should clearly document its available variables ({{alert_title}}, {{severity}}, {{ioc_list}}), required vs. optional, and example values. Help admins understand what context the prompt will receive. |
| 34.3 | **Prompt template categories**    | MEDIUM   | Organize prompts by category: Triage, Investigation, Summarization, Rule Generation, Report Generation. Filter and search by category.                                                                                      |

### Backend Completeness

| #    | Improvement                            | Priority | Detail                                                                                                                                               |
| ---- | -------------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| 34.4 | **Prompt quality scoring**             | HIGH     | Automatically score prompt outputs using criteria: relevance, accuracy, actionability, format compliance. Track scores over time per prompt version. |
| 34.5 | **Prompt rollback with safety checks** | MEDIUM   | When rolling back a prompt version, verify the previous version is still compatible with current data schemas and available variables.               |

---

## 35. Feedback Loop

**Source:** `client/src/pages/ai-feedback-form.tsx` (537 lines) | `server/routes/active-learning.ts`
**Current state:** AI feedback collection with 5 queries. Analyst feedback on AI outputs, false positive tracking.

### UI/UX Polish

| #    | Improvement                                   | Priority | Detail                                                                                                                                                                                 |
| ---- | --------------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 35.1 | **Inline feedback on AI responses**           | CRITICAL | Feedback should be collected inline — thumbs up/down on each AI response, not on a separate page. The separate feedback form page adds friction and reduces feedback collection rates. |
| 35.2 | **Feedback analytics dashboard**              | HIGH     | Show feedback trends: accuracy improvement over time, false positive reduction rate, most common feedback categories (wrong severity, missed IOC, irrelevant context).                 |
| 35.3 | **Feedback → Prompt improvement suggestions** | MEDIUM   | When negative feedback patterns emerge (e.g., consistently wrong severity classification), suggest specific prompt modifications to address the issue.                                 |

### Backend Completeness

| #    | Improvement                                  | Priority | Detail                                                                                                                                                                                                                       |
| ---- | -------------------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 35.4 | **Few-shot example injection from feedback** | HIGH     | Positive feedback examples should be automatically added to the prompt's few-shot examples. "This was a great analysis" → store as an example of good output. Verify the active learning pipeline actually improves prompts. |
| 35.5 | **Source-level suppression**                 | HIGH     | When a data source consistently generates false positives (as tracked by feedback), automatically adjust alert scoring or add suppression rules. Verify this feedback loop is working end-to-end.                            |

---

## 36. Budget & Limits

**Source:** `client/src/pages/ai-budget-controls.tsx` (314 lines) | `server/routes/phase2-routes.ts`
**Current state:** AI budget configuration with 4 queries, 5 tabs, 3 charts. Monthly budget limits, usage tracking.

### UI/UX Polish

| #    | Improvement                                   | Priority | Detail                                                                                                                                                                                   |
| ---- | --------------------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 36.1 | **Budget visualization with burn-down chart** | HIGH     | Show a burn-down chart: budget consumed vs. remaining over the month. Forecast when budget will be exhausted at current usage rate. At 314 lines, this page needs significant expansion. |
| 36.2 | **Budget alerts and thresholds**              | HIGH     | Configure alert thresholds: "Alert at 50% consumed, 75% consumed, 90% consumed." Show notifications when thresholds are breached.                                                        |
| 36.3 | **Budget allocation by use case**             | MEDIUM   | Allocate budget portions: 40% for alert triage, 30% for investigations, 20% for report generation, 10% for other. Track actual vs. allocated usage.                                      |
| 36.4 | **Cost per investigation/action breakdown**   | MEDIUM   | Show the cost of each AI operation: average cost per alert triage, per incident investigation, per rule generation. Help admins understand where the budget goes.                        |

### Backend Completeness

| #    | Improvement                        | Priority | Detail                                                                                                                                                                         |
| ---- | ---------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 36.5 | **Hard budget enforcement**        | CRITICAL | When budget is exhausted, gracefully degrade AI features: disable non-critical AI features, switch to cheaper models, queue requests. Currently may not have hard enforcement. |
| 36.6 | **Budget rollover and adjustment** | LOW      | Support unused budget rollover to next month. Allow mid-month budget increases. Track budget changes in audit log.                                                             |

---

## 37. Connectors

**Source:** `client/src/pages/connectors.tsx` (1,832 lines) | `server/routes/connectors.ts`, `server/connector-engine.ts`
**Current state:** Connector management with 19 queries, 5 tabs, 3 charts. 20+ connector types (CrowdStrike, SentinelOne, Splunk, etc.), health monitoring, DLQ UI, sync history, test preview.

### UI/UX Polish

| #    | Improvement                         | Priority | Detail                                                                                                                                                                                                      |
| ---- | ----------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 37.1 | **Connector setup wizard**          | HIGH     | Step-by-step wizard for configuring each connector: select type → enter credentials → test connection → configure sync options → activate. Currently may require manual field entry without guidance.       |
| 37.2 | **Connector health dashboard**      | HIGH     | At-a-glance health for all connectors: last sync time, sync success rate, events ingested (24h), error count, DLQ depth. Show RED/YELLOW/GREEN status.                                                      |
| 37.3 | **DLQ management with retry**       | HIGH     | Dead Letter Queue UI should show: failed events with error details, retry individual or batch, purge old DLQ items, alert when DLQ depth exceeds threshold. Currently implemented — verify UX completeness. |
| 37.4 | **Sync history with detailed logs** | MEDIUM   | For each sync run, show: start/end time, events fetched, events processed, events failed, errors encountered, duration. Allow re-running a failed sync.                                                     |

### Backend Completeness

| #    | Improvement                              | Priority | Detail                                                                                                                                                                                  |
| ---- | ---------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 37.5 | **Connector credential rotation**        | HIGH     | Support rotating connector credentials (API keys, tokens) without downtime. Store credentials encrypted. Alert when credentials are approaching expiration.                             |
| 37.6 | **Connector rate limiting**              | MEDIUM   | Respect source system rate limits. Implement adaptive throttling: slow down when approaching rate limits, resume at full speed when limits reset. Show rate limit status per connector. |
| 37.7 | **Connector data mapping customization** | MEDIUM   | Allow customizing field mappings per connector: map source fields to SecureNexus schema fields. Handle custom fields and enrichment during ingestion.                                   |

### Integration Gaps

| #    | Improvement                               | Priority | Detail                                                                                                                                                                         |
| ---- | ----------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 37.8 | **Connector → Alert generation pipeline** | CRITICAL | Verify every connector type can successfully: connect → fetch events → normalize → create alerts. End-to-end pipeline verification for each of the 20+ connector types.        |
| 37.9 | **Connector → Response action execution** | HIGH     | For connector types that support it (EDR, firewall, identity), verify response actions work: isolate endpoint, block IP, disable account. Test each action type per connector. |

---

## 38. Integration Marketplace

**Source:** `client/src/pages/integration-marketplace.tsx` (970 lines) | `server/routes/integration-marketplace.ts`
**Current state:** Integration marketplace with 16 queries. Browse and install pre-built integrations.

### UI/UX Polish

| #    | Improvement                             | Priority | Detail                                                                                                                                                               |
| ---- | --------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 38.1 | **Category browsing and search**        | HIGH     | Organize integrations by category: SIEM, EDR, Cloud, Identity, Ticketing, Communication. Add search with filters for category, rating, install count.                |
| 38.2 | **Integration detail page**             | HIGH     | Each integration should have a detail page: description, screenshots, configuration guide, supported features, version history, reviews, pricing (if applicable).    |
| 38.3 | **One-click install with guided setup** | HIGH     | Installing an integration should launch a guided setup wizard specific to that integration type. Pre-fill known values, validate credentials, and test connectivity. |

### Backend Completeness

| #    | Improvement                       | Priority | Detail                                                                                                                                      |
| ---- | --------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| 38.4 | **Integration health monitoring** | HIGH     | After installation, monitor integration health: connection status, last successful data exchange, error rate. Alert when integrations fail. |
| 38.5 | **Integration update management** | MEDIUM   | Notify when integration updates are available. Support auto-update or manual update with changelog review.                                  |

---

## 39. Native Collectors

**Source:** `client/src/pages/native-collectors.tsx` (1,292 lines) | `server/routes/native-collectors.ts`, `server/native-collectors-engine.ts`
**Current state:** Log source configuration with 9 queries. Syslog, Windows Event Log, cloud log source deployment guides, config panels.

### UI/UX Polish

| #    | Improvement                      | Priority | Detail                                                                                                                                                                                              |
| ---- | -------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 39.1 | **Log source deployment wizard** | HIGH     | Step-by-step deployment guide for each log source type: select platform → download agent/configure forwarder → test data flow → verify in ingestion dashboard. Interactive, not just documentation. |
| 39.2 | **Log source health monitoring** | HIGH     | Show real-time status per log source: events per second, last received event, parsing errors, data volume. Alert when a log source stops sending data.                                              |
| 39.3 | **Log source coverage map**      | MEDIUM   | Visual map showing which log sources are configured across the infrastructure. Highlight coverage gaps: "No log collection from DMZ network segment."                                               |

### Backend Completeness

| #    | Improvement                                | Priority | Detail                                                                                                                                                                            |
| ---- | ------------------------------------------ | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 39.4 | **Log parsing engine with custom parsers** | HIGH     | Support custom log parsers: regex-based field extraction, grok patterns, JSON path mapping. Allow testing parsers against sample logs. Currently may have limited parser options. |
| 39.5 | **Log source certificate management**      | MEDIUM   | For TLS-encrypted log sources, manage certificates: generate CSRs, import certificates, track expiration, auto-renew.                                                             |

---

## 40. Webhooks

**Source:** `client/src/pages/webhook-security-center.tsx` (637 lines) | `server/routes/webhooks.ts`
**Current state:** Webhook management with 4 queries, 1 tab. Webhook configuration and delivery monitoring.

### UI/UX Polish

| #    | Improvement                   | Priority | Detail                                                                                                                                                           |
| ---- | ----------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 40.1 | **Webhook delivery history**  | HIGH     | Show delivery history per webhook: timestamp, payload, response code, response time, retry count. Filter by success/failure. Currently may show limited history. |
| 40.2 | **Webhook testing**           | HIGH     | "Send Test Payload" button for each webhook. Show the test request and response side-by-side. Verify connectivity without waiting for a real event.              |
| 40.3 | **Webhook payload templates** | MEDIUM   | Allow customizing the webhook payload format per destination. Support Slack formatting, PagerDuty event format, generic JSON. Currently may send a fixed format. |

### Backend Completeness

| #    | Improvement                                | Priority | Detail                                                                                                                                                                    |
| ---- | ------------------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 40.4 | **Webhook retry with exponential backoff** | HIGH     | Failed deliveries should retry: 3 attempts with exponential backoff (1s, 5s, 30s). After max retries, move to DLQ and alert. Verify retry logic exists and works.         |
| 40.5 | **Webhook signature verification**         | HIGH     | Outgoing webhooks should include an HMAC signature so receivers can verify authenticity. Document the verification process for webhook consumers.                         |
| 40.6 | **Webhook event filtering**                | MEDIUM   | Allow configuring which event types trigger each webhook: only critical alerts, only incident status changes, only specific alert sources. Currently may send all events. |

---

## 41. Ingestion Status

**Source:** `client/src/pages/ingestion.tsx` (554 lines) | `server/routes/ingestion.ts`
**Current state:** Ingestion monitoring with 7 queries. Shows event ingestion rates, API key management, log source status.

### UI/UX Polish

| #    | Improvement                        | Priority | Detail                                                                                                                                                                                           |
| ---- | ---------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 41.1 | **Real-time ingestion rate graph** | HIGH     | Live-updating graph showing events per second across all sources. Zoom into specific time ranges. Overlay anomaly detection: alert when ingestion rate drops significantly (source may be down). |
| 41.2 | **Per-source ingestion breakdown** | HIGH     | Break down ingestion by source: which connectors, log sources, and APIs are contributing events. Show percentage of total volume. Identify dominant and silent sources.                          |
| 41.3 | **Ingestion pipeline health**      | HIGH     | Show the full pipeline status: received → parsed → normalized → enriched → stored. Identify bottlenecks at each stage. Show error counts per stage.                                              |

### Backend Completeness

| #    | Improvement                                  | Priority | Detail                                                                                                                                                                  |
| ---- | -------------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 41.4 | **Ingestion rate limiting and backpressure** | HIGH     | When ingestion volume exceeds processing capacity, implement backpressure: slow down acceptance, queue excess events, alert operators. Prevent data loss during spikes. |
| 41.5 | **Ingestion data quality metrics**           | MEDIUM   | Track parsing success rate, field extraction accuracy, normalization coverage. Alert when data quality degrades (unparsed events exceeding threshold).                  |

---

## 42. Job Queue

**Source:** `client/src/pages/job-queue-dashboard.tsx` (453 lines) | `server/routes/admin.ts`
**Current state:** Job queue monitoring with 4 queries, 6 tabs, 2 charts. Shows running/pending/failed jobs.

### UI/UX Polish

| #    | Improvement                      | Priority | Detail                                                                                                                                              |
| ---- | -------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| 42.1 | **Job priority management**      | HIGH     | Allow re-prioritizing jobs in the queue. Critical security scan jobs should jump ahead of routine maintenance tasks. Show priority levels visually. |
| 42.2 | **Job dependency visualization** | MEDIUM   | Show job dependencies as a DAG (directed acyclic graph). Highlight which pending jobs are blocked waiting for other jobs to complete.               |
| 42.3 | **Failed job details and retry** | HIGH     | For failed jobs, show: error message, stack trace, retry count, last attempt timestamp. One-click retry with option to modify parameters.           |

### Backend Completeness

| #    | Improvement                   | Priority | Detail                                                                                                                             |
| ---- | ----------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| 42.4 | **Job execution time limits** | HIGH     | Configure maximum execution time per job type. Kill jobs that exceed time limits. Alert on repeatedly timing out jobs.             |
| 42.5 | **Job queue metrics**         | MEDIUM   | Track: average wait time, average execution time, throughput, failure rate. Show trends over time. Feed into Operations dashboard. |

---

## 43. Outbox Monitor

**Source:** `client/src/pages/outbox-monitoring.tsx` (1,105 lines) | `server/routes/operations.ts`
**Current state:** Outbox event monitoring with 5 queries, 5 tabs. Transactional outbox pattern for reliable event delivery.

### UI/UX Polish

| #    | Improvement                | Priority | Detail                                                                                                                                              |
| ---- | -------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| 43.1 | **Outbox event replay UI** | HIGH     | Allow replaying specific failed events or batches of events. Show replay status and outcome. Useful for recovering from downstream service outages. |
| 43.2 | **Outbox lag monitoring**  | HIGH     | Show the delay between event creation and delivery. Alert when lag exceeds threshold (events accumulating faster than they're being processed).     |
| 43.3 | **Event flow diagram**     | MEDIUM   | Visual diagram showing event flow: source → outbox → delivery attempt → success/failure → DLQ. Animate events flowing through the pipeline.         |

### Backend Completeness

| #    | Improvement                    | Priority | Detail                                                                                                                                                 |
| ---- | ------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 43.4 | **Outbox cleanup policy**      | MEDIUM   | Configure retention for delivered events: keep for N days then purge. Prevent outbox table from growing indefinitely. Show table size and growth rate. |
| 43.5 | **Outbox delivery guarantees** | HIGH     | Verify exactly-once delivery semantics. Document which events have at-least-once vs. exactly-once guarantees. Track duplicate delivery rate.           |

---

## 44. Data Lake

**Source:** `client/src/pages/data-lake.tsx` (1,407 lines) | `server/routes/data-lake.ts`
**Current state:** Security data lake with 22 queries, 13 tabs. Cold storage tiering, query federation, retention policies, legal holds, eDiscovery.

### UI/UX Polish

| #    | Improvement                            | Priority | Detail                                                                                                                                                                        |
| ---- | -------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 44.1 | **Storage tier visualization**         | HIGH     | Visual breakdown of data across tiers: hot (SSD, immediate access) → warm (HDD, seconds) → cold (S3, minutes) → archive (Glacier, hours). Show data volume and cost per tier. |
| 44.2 | **Query builder with cost estimation** | HIGH     | Before executing a data lake query, show estimated: data scanned, execution time, cost (if using cloud storage). Prevent accidental expensive queries.                        |
| 44.3 | **Data catalog / schema browser**      | HIGH     | Browse available data: tables, fields, data types, sample values. Auto-complete in query builder based on schema. Show data freshness per table.                              |
| 44.4 | **Legal hold management**              | MEDIUM   | For legal holds: show all active holds, affected data, hold duration, issuing authority. Prevent deletion of data under legal hold even if retention policy would expire it.  |

### Backend Completeness

| #    | Improvement                          | Priority | Detail                                                                                                                                                                        |
| ---- | ------------------------------------ | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 44.5 | **Automated data tiering**           | HIGH     | Data should automatically move between tiers based on age and access patterns. Configure per data type: "Alert data moves to cold after 90 days, to archive after 365 days."  |
| 44.6 | **Data compaction and optimization** | MEDIUM   | Periodically compact and optimize stored data: merge small files, update statistics, rebuild indexes. Show last optimization run and next scheduled.                          |
| 44.7 | **Cross-tier query federation**      | HIGH     | Queries that span multiple tiers should be seamless: the query engine handles fetching from appropriate tiers transparently. Show which tiers were queried and time per tier. |

---

## 45. Asset Inventory

**Source:** `client/src/pages/asset-inventory.tsx` (621 lines) | `server/routes/standalone-platform.ts`
**Current state:** Asset inventory with 5 queries, 1 tab, 2 charts. Basic asset listing with creation.

### UI/UX Polish

| #    | Improvement                              | Priority | Detail                                                                                                                                                                                                                                                |
| ---- | ---------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 45.1 | **Asset detail page with full context**  | CRITICAL | Each asset needs a rich detail page: OS/software inventory, open ports, network connections, associated users, vulnerability count, compliance status, risk score, alert history, last seen date. At 621 lines, this page is thin for a core feature. |
| 45.2 | **Asset classification and criticality** | HIGH     | Classify assets by criticality: crown jewels (databases, domain controllers), high (servers), medium (workstations), low (printers). Criticality should drive vulnerability prioritization and response urgency.                                      |
| 45.3 | **Asset topology map**                   | HIGH     | Visual network topology showing asset relationships: which assets connect to which, network segments, trust boundaries. Highlight internet-facing assets and critical paths.                                                                          |
| 45.4 | **Asset import from multiple sources**   | HIGH     | Import assets from: Active Directory, cloud providers (AWS EC2, Azure VMs, GCP instances), vulnerability scanners, EDR agents, CMDB exports. Currently may only support manual creation.                                                              |

### Backend Completeness

| #    | Improvement                      | Priority | Detail                                                                                                                                                                                              |
| ---- | -------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 45.5 | **Asset auto-discovery**         | CRITICAL | Continuously discover new assets from: network scans, connector data (EDR seeing new endpoints), cloud API enumeration, DNS records. Alert on newly discovered assets that aren't in the inventory. |
| 45.6 | **Asset lifecycle management**   | HIGH     | Track asset lifecycle: provisioned → active → decommissioning → decommissioned. Alert on zombie assets (no recent activity but still in inventory).                                                 |
| 45.7 | **Software inventory per asset** | HIGH     | Maintain current software inventory per asset. Cross-reference with CVE database. Show which assets have vulnerable software versions.                                                              |

### Integration Gaps

| #     | Improvement                            | Priority | Detail                                                                                                                                  |
| ----- | -------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| 45.8  | **Asset → CVE matching**               | CRITICAL | Every asset should show its vulnerability exposure: which CVEs affect its software. This is the #1 integration gap for asset inventory. |
| 45.9  | **Asset → CSPM correlation**           | HIGH     | Cloud assets should link to CSPM findings. Show cloud configuration issues per asset.                                                   |
| 45.10 | **Asset → Alert/Incident association** | HIGH     | Show all alerts and incidents involving each asset. This provides a security history per asset.                                         |

---

## 46. Risk Register

**Source:** `client/src/pages/risk-register.tsx` (560 lines) | `server/routes/standalone-platform.ts`
**Current state:** Risk register with 4 queries, 2 charts. Risk items with severity, likelihood, impact tracking.

### UI/UX Polish

| #    | Improvement                            | Priority | Detail                                                                                                                                                                  |
| ---- | -------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 46.1 | **Risk heatmap (likelihood × impact)** | HIGH     | Visual heatmap matrix showing risks plotted by likelihood (x-axis) and impact (y-axis). Color intensity shows concentration. Click cells to see risks in that quadrant. |
| 46.2 | **Risk trend tracking**                | HIGH     | Show how each risk's score has changed over time. Are risks being mitigated (scores decreasing) or growing (scores increasing)? Track residual risk after mitigations.  |
| 46.3 | **Risk ownership and accountability**  | HIGH     | Each risk should have an assigned owner and a due date for mitigation. Show overdue risks prominently. Send reminder notifications.                                     |
| 46.4 | **Risk treatment plans**               | MEDIUM   | For each risk: document the treatment plan (accept, mitigate, transfer, avoid), planned mitigations with timeline, and progress tracking.                               |

### Backend Completeness

| #    | Improvement                                 | Priority | Detail                                                                                                                                                        |
| ---- | ------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 46.5 | **Risk auto-population from security data** | HIGH     | Auto-create risk entries from: critical vulnerability findings, CSPM misconfigurations, UEBA anomalies, threat intel alerts. Reduce manual risk entry burden. |
| 46.6 | **Risk quantification (FAIR model)**        | MEDIUM   | Support quantitative risk analysis using the FAIR (Factor Analysis of Information Risk) model. Calculate risk in financial terms (expected annual loss).      |

---

## 47. Native Sensors

**Source:** `client/src/pages/native-sensors.tsx` (1,430 lines) | `server/routes/native-sensors.ts`
**Current state:** Native sensor management with 15 queries, 11 tabs. Sensor registration, deployment, health monitoring, telemetry collection across 7 platforms (Windows, macOS, Linux, Android, iOS, Docker, Kubernetes).

### UI/UX Polish

| #    | Improvement                   | Priority | Detail                                                                                                                                                                                       |
| ---- | ----------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 47.1 | **Sensor deployment wizard**  | HIGH     | Step-by-step deployment wizard per platform: generate installer → download → install → verify connectivity → configure policies. Currently may require manual steps.                         |
| 47.2 | **Sensor fleet dashboard**    | HIGH     | Overview of all deployed sensors: total count by platform, online/offline ratio, version distribution, policy compliance. Show sensors needing attention (offline, outdated, misconfigured). |
| 47.3 | **Sensor policy management**  | HIGH     | Configure collection policies per sensor group: what telemetry to collect, how often, what detection rules to enforce locally. Push policy updates to sensors.                               |
| 47.4 | **Sensor version management** | MEDIUM   | Track sensor versions across the fleet. Show upgrade availability. Support staged rollout: upgrade 10% → verify → upgrade remaining.                                                         |

### Backend Completeness

| #    | Improvement                                | Priority | Detail                                                                                                                                                     |
| ---- | ------------------------------------------ | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 47.5 | **Sensor heartbeat and health monitoring** | HIGH     | Sensors should send periodic heartbeats. Detect and alert on: sensor offline, sensor degraded (high CPU/memory), sensor tampered with, sensor uninstalled. |
| 47.6 | **Sensor auto-update**                     | MEDIUM   | Support automatic sensor updates with configurable update windows (maintenance windows only) and rollback capability if the new version causes issues.     |

---

## 48. Detection Rules

**Source:** `client/src/pages/detection-rules.tsx` (1,159 lines) | `server/routes/phase2-routes.ts`, `server/sigma-compiler.ts`
**Current state:** Detection rule management with 7 queries, 6 tabs. Sigma/YARA rules, MITRE ATT&CK heatmap, JSON rule builder, rule lifecycle management.

### UI/UX Polish

| #    | Improvement                              | Priority | Detail                                                                                                                                                                                                              |
| ---- | ---------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 48.1 | **Rule editor with syntax highlighting** | HIGH     | Full-featured code editor for Sigma and YARA rules: syntax highlighting, auto-indentation, bracket matching, error underlining, auto-complete for field names. Use Monaco or CodeMirror.                            |
| 48.2 | **Rule testing sandbox**                 | CRITICAL | Test a rule against historical data before deploying: show which alerts would have been generated, false positive rate, performance impact. This is essential — deploying untested rules can generate alert storms. |
| 48.3 | **Rule effectiveness scoring**           | HIGH     | For each active rule, show: alerts generated, true positive rate, false positive rate, mean time to triage alerts from this rule. Low-effectiveness rules should be flagged for review.                             |
| 48.4 | **Rule dependency management**           | MEDIUM   | Some rules depend on specific data sources or field mappings. Show dependencies per rule and alert when a dependency is broken (data source removed, field renamed).                                                |

### Backend Completeness

| #    | Improvement                           | Priority | Detail                                                                                                                                                                                                     |
| ---- | ------------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 48.5 | **Rule versioning with rollback**     | HIGH     | Track all changes to detection rules. Allow reverting to previous versions. Show diff between versions. Required for change management and compliance.                                                     |
| 48.6 | **Rule performance monitoring**       | HIGH     | Monitor rule execution performance: which rules take the longest to evaluate, which consume the most resources. Optimize or flag rules that impact system performance.                                     |
| 48.7 | **Sigma → backend query compilation** | HIGH     | Verify the Sigma compiler correctly translates rules to the backend query format. Test with complex rules including: OR conditions, NOT conditions, wildcards, regular expressions, time-based conditions. |

### Integration Gaps

| #    | Improvement                        | Priority | Detail                                                                                                                                                       |
| ---- | ---------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 48.8 | **Rule → MITRE ATT&CK coverage**   | HIGH     | Every rule should be tagged with the MITRE ATT&CK techniques it detects. Show rule coverage on the ATT&CK heatmap. Identify gaps (techniques with no rules). |
| 48.9 | **Rule → Threat Intel enrichment** | MEDIUM   | Automatically update rules when new IOCs are ingested from threat intel feeds. Rules referencing IOC lists should be dynamically updated.                    |

---

## 49. Vuln Scanner

**Source:** `client/src/pages/vuln-scanner.tsx` (576 lines) | `server/routes/vuln-scanner.ts`
**Current state:** Native vulnerability scanner with 5 queries, 5 tabs. Scan management, finding results, remediation tracking.

### UI/UX Polish

| #    | Improvement                             | Priority | Detail                                                                                                                                                                                        |
| ---- | --------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 49.1 | **Scan target configuration**           | HIGH     | Configure scan targets: IP ranges, hostnames, cloud resources, containers. Support scan exclusions (maintenance windows, non-production hosts). Currently may have limited targeting options. |
| 49.2 | **Scan result detail with remediation** | HIGH     | Each finding should show: CVE details, CVSS score, affected software version, fixed version, remediation steps, exploit availability. Link to CVE Database entry.                             |
| 49.3 | **Scan comparison (before/after)**      | HIGH     | Compare two scan results: show new vulnerabilities, fixed vulnerabilities, unchanged vulnerabilities. Track remediation progress between scans.                                               |
| 49.4 | **Scan scheduling**                     | HIGH     | Schedule recurring scans: daily quick scans, weekly comprehensive scans, monthly compliance scans. Show scan calendar.                                                                        |

### Backend Completeness

| #    | Improvement                      | Priority | Detail                                                                                                                                                                                    |
| ---- | -------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 49.5 | **Authenticated scanning**       | HIGH     | Support authenticated scans with credentials for deeper inspection: check installed software versions, configuration settings, patch levels. Currently may do unauthenticated scans only. |
| 49.6 | **Container and image scanning** | MEDIUM   | Scan Docker images and running containers for vulnerabilities. Integrate with CI/CD to scan images before deployment.                                                                     |

### Integration Gaps

| #    | Improvement                             | Priority | Detail                                                                                                                                                   |
| ---- | --------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 49.7 | **Vuln Scanner → Asset Inventory sync** | HIGH     | Discovered hosts from scans should automatically populate the Asset Inventory. New hosts should be flagged as "discovered by scanner, not in inventory." |
| 49.8 | **Vuln Scanner → Patch management**     | MEDIUM   | For each vulnerability, track patch status per host. Integrate with patch management tools to initiate patching directly from scan results.              |

---

## 50. Agent Response

**Source:** `client/src/pages/agent-response.tsx` (984 lines) | `server/routes/agent-response.ts`
**Current state:** Remote agent response actions with 11 queries, 5 tabs. Send commands to native sensors for remote response.

### UI/UX Polish

| #    | Improvement                            | Priority | Detail                                                                                                                                                                                           |
| ---- | -------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 50.1 | **Command execution with live output** | HIGH     | When sending a command to an agent, show live command output (streaming). Currently may only show final results. Analysts need to see command progress.                                          |
| 50.2 | **Command templates library**          | HIGH     | Pre-built command templates for common response actions: collect process list, dump memory, collect network connections, isolate endpoint, collect logs. One-click execution with customization. |
| 50.3 | **Command approval workflow**          | HIGH     | For destructive commands (kill process, delete file, isolate endpoint), require approval from a senior analyst. Show approval chain and current status.                                          |
| 50.4 | **Multi-agent batch commands**         | MEDIUM   | Execute the same command on multiple agents simultaneously. Show results in a consolidated view. Useful for fleet-wide response actions.                                                         |

### Backend Completeness

| #    | Improvement                   | Priority | Detail                                                                                                                                                            |
| ---- | ----------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 50.5 | **Command execution timeout** | HIGH     | Commands should have configurable timeouts. Alert when commands don't complete within the expected timeframe. Support command cancellation.                       |
| 50.6 | **Command audit trail**       | CRITICAL | Log every command sent to every agent: who sent, what command, when, result, approver. Required for forensic accountability. Verify comprehensive logging exists. |

---

## 51. UEBA Analytics

**Source:** `client/src/pages/ueba.tsx` (633 lines) | `server/routes/ueba.ts`
**Current state:** User and Entity Behavior Analytics with 7 queries, 5 tabs, 1 chart. Baseline behavior modeling, anomaly detection, risk scoring.

### UI/UX Polish

| #    | Improvement                                | Priority | Detail                                                                                                                                                                                           |
| ---- | ------------------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 51.1 | **User risk score dashboard**              | HIGH     | Show all users ranked by risk score with trend indicators (rising/falling/stable). Filter by department, role, location. Highlight users with sudden score increases.                            |
| 51.2 | **Anomaly detail with behavioral context** | HIGH     | Each anomaly should show: what the normal behavior looks like (baseline), what the anomalous behavior is, how far it deviates, possible explanations (travel, role change, compromised account). |
| 51.3 | **Peer group comparison**                  | HIGH     | Compare a user's behavior to their peer group (same role, department). Show where they deviate from peers. "This admin accesses 5x more systems than other admins."                              |
| 51.4 | **Activity timeline per entity**           | HIGH     | Visual timeline showing an entity's activity: login times, systems accessed, data volumes, privilege usage. Overlay anomaly markers on the timeline.                                             |

### Backend Completeness

| #    | Improvement                             | Priority | Detail                                                                                                                                                                                  |
| ---- | --------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 51.5 | **Baseline learning period**            | HIGH     | Track baseline learning status: "User baseline: 75% complete (needs 7 more days of data)." Don't generate anomaly alerts during the learning period. Show learning progress per entity. |
| 51.6 | **Contextual anomaly adjustment**       | MEDIUM   | Adjust anomaly scoring based on context: travel (different geo-IP), role change (new access patterns expected), holidays (reduced activity expected). Reduce false positives.           |
| 51.7 | **Machine learning model transparency** | MEDIUM   | Explain which features contributed to each anomaly score. Show feature importance: "60% of this score is from unusual login time, 30% from new system access, 10% from data volume."    |

### Integration Gaps

| #    | Improvement                                | Priority | Detail                                                                                                                                                                   |
| ---- | ------------------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 51.8 | **UEBA → Autonomous SOC triage**           | HIGH     | UEBA anomalies above a threshold should automatically trigger the Autonomous SOC for AI-powered investigation. Currently may generate alerts that require manual triage. |
| 51.9 | **UEBA → Identity Governance correlation** | HIGH     | Link UEBA anomalies with identity governance data: "This user has excessive permissions AND anomalous behavior." Combine risk signals for stronger detection.            |

---

## 52. Supply Chain Security

**Source:** `client/src/pages/supply-chain.tsx` (1,327 lines) | `server/routes/supply-chain.ts`
**Current state:** Supply chain security with 10 queries, 9 tabs, 2 charts. SBOM ingestion, dependency graph, typosquatting detection, IaC scanning.

### UI/UX Polish

| #    | Improvement                        | Priority | Detail                                                                                                                                                                                                  |
| ---- | ---------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 52.1 | **Dependency graph visualization** | HIGH     | Interactive dependency graph showing: direct dependencies, transitive dependencies, vulnerable dependencies (highlighted in red), license issues (highlighted in yellow). Zoom and filter capabilities. |
| 52.2 | **SBOM dashboard**                 | HIGH     | Show SBOM coverage: how many applications have SBOMs, how current they are, total unique dependencies, vulnerability exposure per application.                                                          |
| 52.3 | **Typosquatting alert review**     | HIGH     | Typosquatting detection results should show: suspicious package name, likely legitimate package it mimics, similarity score, download count, author reputation. Allow whitelisting legitimate packages. |

### Backend Completeness

| #    | Improvement                          | Priority | Detail                                                                                                                                                             |
| ---- | ------------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 52.4 | **SBOM auto-generation from CI/CD**  | HIGH     | Auto-generate SBOMs from build pipelines (npm, pip, Maven, Go modules). Update SBOMs on every build. Currently may require manual SBOM upload.                     |
| 52.5 | **Continuous dependency monitoring** | HIGH     | Monitor dependencies for new vulnerabilities. When a new CVE is published affecting a dependency, alert immediately. Currently may only check at SBOM upload time. |
| 52.6 | **License compliance checking**      | MEDIUM   | Check dependency licenses against allowed/prohibited license lists. Flag GPL dependencies in commercial software, etc.                                             |

---

## 53. Identity Governance

**Source:** `client/src/pages/identity-governance.tsx` (1,432 lines) | `server/routes/identity-governance.ts`
**Current state:** Identity governance with 20 queries, 13 tabs. Access reviews, privileged access management, SCIM sync, blast radius analysis, lateral movement detection.

### UI/UX Polish

| #    | Improvement                    | Priority | Detail                                                                                                                                                                       |
| ---- | ------------------------------ | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 53.1 | **Access review campaigns**    | HIGH     | Structured access review campaigns: select scope (department, application, role) → assign reviewers → set deadline → track completion → enforce decisions (revoke access).   |
| 53.2 | **Blast radius visualization** | HIGH     | Visual graph showing: if this user account is compromised, what can the attacker access? Show first-hop access, second-hop (lateral movement), and crown jewel reachability. |
| 53.3 | **Privilege creep detection**  | HIGH     | Detect and alert on privilege accumulation: users gaining permissions over time without losing old ones. Show historical permission timeline.                                |
| 53.4 | **Orphaned account detection** | HIGH     | Identify accounts with no corresponding employee (employee left, contractor ended). Cross-reference with HR data or identity provider.                                       |

### Backend Completeness

| #    | Improvement                              | Priority | Detail                                                                                                                                                                      |
| ---- | ---------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 53.5 | **SCIM provisioning and deprovisioning** | HIGH     | Full SCIM lifecycle: auto-create accounts on hire, update on role change, disable on termination. Verify deprovisioning actually removes access from all connected systems. |
| 53.6 | **Role mining and optimization**         | MEDIUM   | Analyze existing access patterns to suggest optimized role definitions. "Users with these 5 permissions always have these 3 others too — create a combined role."           |

### Integration Gaps

| #    | Improvement                           | Priority | Detail                                                                                                                                  |
| ---- | ------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| 53.7 | **Identity → JIT Access integration** | HIGH     | Identity governance should feed JIT access decisions: "This user already has standing access to this system — JIT request unnecessary." |
| 53.8 | **Identity → UEBA correlation**       | HIGH     | Combine identity governance data (permissions, access reviews) with UEBA behavioral data for comprehensive identity threat detection.   |

---

## 54. Deception Technology

**Source:** `client/src/pages/deception.tsx` (1,233 lines) | `server/routes/deception.ts`
**Current state:** Deception technology with 20 queries, 8 tabs. Canary tokens, honeypots, network decoys, deployment wizard.

### UI/UX Polish

| #    | Improvement                                 | Priority | Detail                                                                                                                                             |
| ---- | ------------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| 54.1 | **Deception coverage map**                  | HIGH     | Visual map showing where deception assets are deployed across the network. Identify coverage gaps: network segments with no canaries or honeypots. |
| 54.2 | **Alert drill-down for deception triggers** | HIGH     | When a canary is triggered, show: who/what triggered it, from where, what action was taken, timeline of activity, and recommended response.        |
| 54.3 | **Decoy authenticity scoring**              | MEDIUM   | Rate how convincing each decoy is. Track interaction rates: low interaction suggests the decoy isn't attractive or discoverable enough.            |

### Backend Completeness

| #    | Improvement                      | Priority | Detail                                                                                                                                                                                                                                  |
| ---- | -------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 54.4 | **Canary token types expansion** | HIGH     | Support canary types beyond the current set: AWS access keys, DNS canaries, web bugs, document canaries, USB canaries, email canaries. Each type should have a unique generation and monitoring mechanism.                              |
| 54.5 | **Honeypot emulation depth**     | MEDIUM   | Honeypots should offer configurable emulation depth: low interaction (simple protocol response) → medium (OS-level simulation) → high (full virtual machine). Deeper emulation captures more attacker TTPs but requires more resources. |

---

## 55. OT/ICS Security

**Source:** `client/src/pages/ot-security.tsx` (1,373 lines) | `server/routes/ot-security.ts`
**Current state:** OT/ICS security with 12 queries, 8 tabs, 2 charts. Passive asset discovery, protocol parsers (Modbus, DNP3, BACnet, OPC-UA, S7Comm, EtherNet/IP, PROFINET), Purdue Model visualization, IT/OT boundary monitoring.

### UI/UX Polish

| #    | Improvement                            | Priority | Detail                                                                                                                                                                               |
| ---- | -------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 55.1 | **Purdue Model interactive diagram**   | HIGH     | Interactive Purdue Model visualization: click each level (0-5) to see assets, traffic flows, and alerts at that level. Show cross-level communications that violate security policy. |
| 55.2 | **OT asset detail with protocol info** | HIGH     | Each OT asset should show: vendor, model, firmware version, supported protocols, network connections, last seen, known vulnerabilities, compliance status.                           |
| 55.3 | **Protocol anomaly visualization**     | HIGH     | Show protocol-level anomalies: unexpected commands, unauthorized register reads/writes, abnormal communication patterns. Color-code by severity.                                     |

### Backend Completeness

| #    | Improvement                    | Priority | Detail                                                                                                                                                                                |
| ---- | ------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 55.4 | **Passive network monitoring** | CRITICAL | OT environments cannot tolerate active scanning. Verify that all asset discovery and monitoring is strictly passive (network tap/SPAN port based). No active probing of OT devices.   |
| 55.5 | **OT vulnerability tracking**  | HIGH     | Cross-reference OT assets with ICS-CERT advisories. Track vulnerabilities specific to OT equipment (PLCs, HMIs, SCADA software). Show patch availability and risk mitigation options. |

---

## 56. Mobile Security

**Source:** `client/src/pages/mobile-security.tsx` (1,090 lines) | `server/routes/mobile-security.ts`
**Current state:** Mobile security with 17 queries, 7 tabs. MDM integration, device posture checks, ZTNA policies, mobile threat detection, remote worker risk scoring.

### UI/UX Polish

| #    | Improvement                  | Priority | Detail                                                                                                                                                                                         |
| ---- | ---------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 56.1 | **Device posture dashboard** | HIGH     | At-a-glance view of all mobile devices: compliant vs. non-compliant, jailbroken/rooted detection, outdated OS versions, missing encryption, disabled screen lock. Show counts and percentages. |
| 56.2 | **ZTNA policy builder**      | HIGH     | Visual policy builder for Zero Trust Network Access: IF device_posture=compliant AND user_risk < medium AND location IN approved_countries THEN allow_access. Drag-and-drop condition builder. |
| 56.3 | **Remote worker risk map**   | MEDIUM   | Geographic map showing remote worker locations with risk scores. Highlight workers in high-risk locations or with poor device posture.                                                         |

### Backend Completeness

| #    | Improvement                    | Priority | Detail                                                                                                                                                                     |
| ---- | ------------------------------ | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 56.4 | **MDM integration validation** | HIGH     | Verify MDM integration (Microsoft Intune, Jamf, VMware Workspace ONE) actually syncs device data. Check that device posture checks are using real MDM data, not simulated. |
| 56.5 | **App risk analysis**          | MEDIUM   | Analyze installed apps on managed devices. Flag known malicious apps, apps with dangerous permissions, apps from unknown sources.                                          |

---

## 57. API Security

**Source:** `client/src/pages/api-security.tsx` (1,341 lines) | `server/routes/api-security.ts`
**Current state:** API security with 12 queries, 5 tabs, 1 chart. API inventory discovery, schema validation, abuse detection, sensitive data scanning, DAST testing, shadow API detection.

### UI/UX Polish

| #    | Improvement                             | Priority | Detail                                                                                                                                                                                           |
| ---- | --------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 57.1 | **API inventory with traffic analysis** | HIGH     | Show all discovered APIs with: endpoint paths, methods, traffic volume, error rates, authentication status, schema drift. Filter by: shadow (undocumented), deprecated, sensitive data exposure. |
| 57.2 | **API abuse detection timeline**        | HIGH     | Show API abuse events on a timeline: brute force attempts, credential stuffing, rate limit violations, data scraping patterns. Correlate with source IPs and user accounts.                      |
| 57.3 | **Schema validation detail**            | MEDIUM   | For each API, compare observed request/response schemas against documented schemas. Highlight mismatches: extra fields (data leak risk), missing required fields, type mismatches.               |

### Backend Completeness

| #    | Improvement                | Priority | Detail                                                                                                                                                                                            |
| ---- | -------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 57.4 | **API traffic monitoring** | HIGH     | Monitor API traffic in real-time: request/response sizes, latency, error codes, authentication success/failure. Require integration with API gateway or reverse proxy.                            |
| 57.5 | **DAST scanning engine**   | HIGH     | Dynamic Application Security Testing for APIs: automatically test endpoints for: SQL injection, XSS, SSRF, authentication bypass, authorization flaws. Report findings with remediation guidance. |

---

## 58. Ransomware Defense

**Source:** `client/src/pages/ransomware-defense.tsx` (2,091 lines) | `server/routes/ransomware-defense.ts`
**Current state:** Ransomware defense suite with 24 queries, 8 tabs. Kill switch, canary files, ransomware intelligence, AI recovery runbooks, tabletop exercises, backup verification.

### UI/UX Polish

| #    | Improvement                      | Priority | Detail                                                                                                                                                                                                                                                 |
| ---- | -------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 58.1 | **Kill switch dashboard**        | HIGH     | Prominent, always-accessible kill switch panel: big red button to trigger emergency isolation. Show current kill switch status, affected systems, recovery procedures. This should be one of the most polished UIs since it's used during emergencies. |
| 58.2 | **Canary file monitoring map**   | HIGH     | Visual map showing canary file locations across the infrastructure. Show triggered vs. active canaries. Alert latency: how quickly was the trigger detected?                                                                                           |
| 58.3 | **Tabletop exercise scheduling** | MEDIUM   | Schedule and manage tabletop exercises: scenarios, participants, objectives, results, lessons learned. Track exercise frequency against compliance requirements.                                                                                       |
| 58.4 | **Recovery readiness score**     | HIGH     | Calculate and display recovery readiness: backup coverage, backup testing frequency, recovery time estimates per system, recovery procedure documentation status.                                                                                      |

### Backend Completeness

| #    | Improvement                             | Priority | Detail                                                                                                                                                                                        |
| ---- | --------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 58.5 | **Backup verification automation**      | CRITICAL | Automated backup verification: periodically restore backups to test environment, verify data integrity, measure recovery time. Report pass/fail per backup set. Currently may be manual only. |
| 58.6 | **Ransomware intelligence integration** | HIGH     | Integrate with ransomware intelligence feeds: known ransomware variants, IOCs, decryptors, ransom demand tracking. Alert when new ransomware variants target the org's industry.              |

---

## 59. Community Threat Intel

**Source:** `client/src/pages/community-intel.tsx` (1,251 lines) | `server/routes/community-intel.ts`
**Current state:** Community threat intel network with 15 queries, 13 tabs. Anonymous IOC sharing, industry feeds, campaign correlation.

### UI/UX Polish

| #    | Improvement                            | Priority | Detail                                                                                                                                                                         |
| ---- | -------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 59.1 | **Sharing dashboard**                  | HIGH     | Show sharing statistics: IOCs shared by your org, IOCs received, quality score of your contributions, industry participation rate. Gamification elements to encourage sharing. |
| 59.2 | **Industry feed curation**             | HIGH     | Configure which industry feeds to subscribe to (financial, healthcare, government, energy). Filter incoming intel by relevance to your sector.                                 |
| 59.3 | **Campaign correlation visualization** | MEDIUM   | When multiple community members report related IOCs, visualize the emerging campaign: shared infrastructure, common targets, timeline progression.                             |

### Backend Completeness

| #    | Improvement                    | Priority | Detail                                                                                                                                                                                    |
| ---- | ------------------------------ | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 59.4 | **Anonymization verification** | CRITICAL | Before sharing any IOC, verify that it has been properly anonymized: no org-identifying data, no internal IP addresses, no employee names. Show anonymization preview before submission.  |
| 59.5 | **IOC quality scoring**        | HIGH     | Score incoming community IOCs by quality: source reputation, corroboration count (how many orgs reported it), freshness, false positive rate from feedback. Prioritize high-quality IOCs. |

---

## 60. Security Posture Score

**Source:** `client/src/pages/posture-trust-center.tsx` (1,437 lines) | `server/routes/posture-trust.ts`
**Current state:** Security posture scoring and public trust center with 17 queries, 7 tabs, 3 charts. Real-time scoring, peer benchmarking, public trust pages, questionnaire automation.

### UI/UX Polish

| #    | Improvement                     | Priority | Detail                                                                                                                                                                                                                                                                               |
| ---- | ------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 60.1 | **Posture score breakdown**     | HIGH     | Show the overall posture score (e.g., 78/100) with a detailed breakdown by category: endpoint security (85%), cloud security (72%), identity security (80%), data protection (68%), vulnerability management (75%). Each category should be expandable to show contributing factors. |
| 60.2 | **Improvement recommendations** | HIGH     | For each low-scoring category, show specific, actionable recommendations ranked by impact: "Enable MFA for all admin accounts (+8 points)", "Patch 5 critical vulnerabilities (+5 points)."                                                                                          |
| 60.3 | **Trust center customization**  | HIGH     | Allow customizing the public trust center page: select which controls to display, add custom attestations, upload compliance certificates, write custom security descriptions.                                                                                                       |
| 60.4 | **Peer benchmarking detail**    | MEDIUM   | Show how the org compares to peers: percentile ranking, areas of strength (above average), areas of weakness (below average). Anonymous comparison by industry and size.                                                                                                             |

### Backend Completeness

| #    | Improvement                           | Priority | Detail                                                                                                                                                                                           |
| ---- | ------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 60.5 | **Continuous posture recalculation**  | HIGH     | Posture score should recalculate in real-time as conditions change: new vulnerability discovered → score drops, endpoint patched → score increases. Currently may recalculate on a schedule.     |
| 60.6 | **Questionnaire response automation** | HIGH     | For incoming security questionnaires (from customers, partners), auto-populate responses from platform data. "Do you have endpoint detection? → Yes (CrowdStrike deployed on 98% of endpoints)." |

---

## 61. Security Chaos Engineering

**Source:** `client/src/pages/security-chaos-engineering.tsx` (1,568 lines) | `server/routes/chaos-engineering.ts`
**Current state:** Security chaos engineering with 24 queries, 7 tabs, 2 charts. MITRE ATT&CK coverage heatmap, purple team automation, BAS dashboard.

### UI/UX Polish

| #    | Improvement                                        | Priority | Detail                                                                                                                                                                                                       |
| ---- | -------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 61.1 | **Simulation scenario builder**                    | HIGH     | Visual builder for attack simulation scenarios: select techniques → configure targets → set detection expectations → define success criteria. Drag-and-drop interface for building multi-step attack chains. |
| 61.2 | **Simulation results with detection gap analysis** | CRITICAL | After running a simulation, show: which attacks were detected, which were missed, time to detect, response actions triggered. Highlight detection gaps that need immediate attention.                        |
| 61.3 | **Purple team exercise management**                | HIGH     | Manage purple team exercises: assign red team (attackers) and blue team (defenders), define objectives, track findings, document improvements. Schedule recurring exercises.                                 |

### Backend Completeness

| #    | Improvement                                  | Priority | Detail                                                                                                                                                                                          |
| ---- | -------------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 61.4 | **Safe simulation execution**                | CRITICAL | Attack simulations must be safe: no actual damage, no data exfiltration, no persistence. Implement strict guardrails and sandboxing. Verify every simulation technique has a safety assessment. |
| 61.5 | **Simulation → Detection coverage tracking** | HIGH     | Track detection coverage improvement over time: before/after each simulation cycle. Show which gaps were closed and which remain open.                                                          |

---

## 62. AI Detection Rules

**Source:** `client/src/pages/ai-detection-rules.tsx` (1,055 lines) | `server/routes/ai-detection-rules.ts`
**Current state:** AI-native detection rule generation with 16 queries, 11 tabs, 2 charts. LLM-powered Sigma/YARA generation, quality scoring, A/B testing, lifecycle management, community marketplace.

### UI/UX Polish

| #    | Improvement                               | Priority | Detail                                                                                                                                                                                                                  |
| ---- | ----------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 62.1 | **Rule generation from natural language** | HIGH     | Analyst describes what to detect in plain English → AI generates a Sigma/YARA rule → shows the rule with explanation → analyst reviews and deploys. The natural language input should support examples and constraints. |
| 62.2 | **Rule quality report card**              | HIGH     | For each generated rule, show a quality report: estimated false positive rate, detection coverage, performance impact, MITRE technique mapping, comparison with existing similar rules.                                 |
| 62.3 | **A/B testing results visualization**     | HIGH     | When A/B testing two rule variants, show side-by-side comparison: alert volumes, true positive rates, processing times, analyst feedback. Recommend the winner.                                                         |

### Backend Completeness

| #    | Improvement                          | Priority | Detail                                                                                                                                                                                      |
| ---- | ------------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 62.4 | **Rule quality validation pipeline** | HIGH     | Before deploying AI-generated rules, run automated validation: syntax check, performance test against historical data, false positive estimation, coverage analysis. Flag potential issues. |
| 62.5 | **Community marketplace moderation** | MEDIUM   | Rules submitted to the marketplace should be reviewed for: quality, malicious intent, duplicate detection, accurate technique tagging. Implement a review workflow.                         |

---

## 63. Autonomous SOC

**Source:** `client/src/pages/autonomous-soc.tsx` (1,194 lines) | `server/routes/autonomous-soc.ts`
**Current state:** Autonomous SOC with 10 queries, 11 tabs, 3 charts. Three-tier AI analyst (Tier 1: autonomous, Tier 2: semi-autonomous, Tier 3: assisted).

### UI/UX Polish

| #    | Improvement                            | Priority | Detail                                                                                                                                                                                                                    |
| ---- | -------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 63.1 | **Autonomous decision audit trail**    | CRITICAL | Every autonomous decision must have a clear audit trail: what data was analyzed, what conclusion was reached, what confidence level, what action was taken. Analysts must be able to review and override.                 |
| 63.2 | **Confidence threshold tuning**        | HIGH     | Allow tuning confidence thresholds per action type: "Auto-resolve benign alerts at >90% confidence, escalate suspicious at >70%, always require human review below 70%." Show how threshold changes affect alert volumes. |
| 63.3 | **Autonomous SOC performance metrics** | HIGH     | Dashboard showing: alerts handled per hour, false negative rate, escalation rate, human override rate, time saved vs. manual triage. Demonstrate ROI.                                                                     |

### Backend Completeness

| #    | Improvement                                     | Priority | Detail                                                                                                                                                                                   |
| ---- | ----------------------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 63.4 | **Graceful degradation when AI is unavailable** | HIGH     | If the AI model is down or budget is exhausted, the Autonomous SOC should fall back gracefully: queue alerts for human triage, escalate based on rule-based thresholds, notify analysts. |
| 63.5 | **Learning from human overrides**               | HIGH     | When an analyst overrides an autonomous decision, feed that correction back into the system. Track override patterns and adjust confidence scoring accordingly.                          |

---

## 64. Developer Security

**Source:** `client/src/pages/developer-security.tsx` (1,133 lines) | `server/routes/developer-security.ts`, `server/sast-engine.ts`
**Current state:** Developer security (Shift-Left) with 13 queries, 8 tabs, 1 chart. SAST engine, secret scanning, CI gates, GitHub/GitLab integrations, code review assistant, security debt tracker.

### UI/UX Polish

| #    | Improvement                           | Priority | Detail                                                                                                                                                                                   |
| ---- | ------------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 64.1 | **Security debt dashboard**           | HIGH     | Show accumulating security debt: unresolved findings by age, findings by severity, trend over time. Calculate technical security debt in estimated remediation hours.                    |
| 64.2 | **Finding detail with code context**  | HIGH     | Each SAST finding should show: affected code snippet with highlighted vulnerable line, explanation of the vulnerability, remediation guidance with fix example, references (CWE, OWASP). |
| 64.3 | **CI/CD pipeline integration status** | HIGH     | Show which repositories have security gates configured, which don't. For configured repos: pass/fail rates, most common findings, blocking vs. non-blocking gate status.                 |
| 64.4 | **Developer leaderboard**             | LOW      | Gamification: show developers ranked by security posture (fewest findings, fastest remediation). Encourage secure coding practices. Optional and privacy-respecting.                     |

### Backend Completeness

| #    | Improvement               | Priority | Detail                                                                                                                                                                                         |
| ---- | ------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 64.5 | **SAST engine accuracy**  | HIGH     | Evaluate and improve SAST engine accuracy: track false positive rate per rule, allow rule tuning, support language-specific analysis. Currently the engine may have high false positive rates. |
| 64.6 | **Secret scanning depth** | HIGH     | Scan for secrets in: source code, configuration files, CI/CD variables, container images, documentation. Support custom secret patterns beyond the built-in regex set.                         |

---

## 65. TPRM

**Source:** `client/src/pages/tprm.tsx` (1,314 lines) | `server/routes/tprm.ts`
**Current state:** Third-Party Risk Management with 12 queries, 7 tabs, 1 chart. Vendor inventory, questionnaire automation, continuous monitoring, breach alerting, contract risk mapping, fourth-party risk.

### UI/UX Polish

| #    | Improvement                         | Priority | Detail                                                                                                                                                                                               |
| ---- | ----------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 65.1 | **Vendor risk dashboard**           | HIGH     | At-a-glance view of all vendors: risk score distribution, recently assessed, overdue for reassessment, vendors with active breaches. Show aggregate third-party risk posture.                        |
| 65.2 | **Questionnaire template builder**  | HIGH     | Visual questionnaire builder: drag-and-drop question types (yes/no, text, file upload, multi-choice), conditional logic (if answer is X, show follow-up), scoring weights, auto-scoring rules.       |
| 65.3 | **Vendor comparison**               | MEDIUM   | Compare two vendors side-by-side: risk scores, questionnaire responses, monitoring findings, contract terms. Help with vendor selection and renewal decisions.                                       |
| 65.4 | **Fourth-party risk visualization** | HIGH     | Graph showing fourth-party relationships: your vendor uses these sub-processors → those sub-processors use these services. Highlight concentration risk (too many vendors depending on one service). |

### Backend Completeness

| #    | Improvement                            | Priority | Detail                                                                                                                                                                                                                                    |
| ---- | -------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 65.5 | **Continuous monitoring data sources** | HIGH     | Monitor vendors continuously via: security ratings (BitSight, SecurityScorecard), breach notification services, certificate transparency logs, DNS changes, dark web mentions. Verify data sources are actually connected and refreshing. |
| 65.6 | **Contract risk extraction**           | MEDIUM   | Auto-extract risk-relevant clauses from vendor contracts: liability limits, data processing terms, breach notification SLAs, termination clauses. Currently may require manual entry.                                                     |

---

## 66. Dark Web Monitoring

**Source:** `client/src/pages/dark-web-monitoring.tsx` (1,213 lines) | `server/routes/dark-web.ts`
**Current state:** Dark web monitoring with 12 queries, 5 tabs, 1 chart. Credential exposure detection, breach integration, brand monitoring, threat actor tracking.

### UI/UX Polish

| #    | Improvement                               | Priority | Detail                                                                                                                                                                                                                                             |
| ---- | ----------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 66.1 | **Exposed credential detail with action** | HIGH     | Each exposed credential should show: where found (paste site, dark web forum, breach database), when, credential type (email+password, API key, certificate), affected user. Provide action buttons: reset password, notify user, disable account. |
| 66.2 | **Brand mention monitoring**              | HIGH     | Show all dark web mentions of the organization: forum posts, marketplace listings, malware targeting the org. Classify mentions by threat level.                                                                                                   |
| 66.3 | **Threat actor profiles**                 | MEDIUM   | Build profiles of threat actors mentioning or targeting the organization. Track their activity over time, known aliases, and capabilities.                                                                                                         |

### Backend Completeness

| #    | Improvement                           | Priority | Detail                                                                                                                                                                                   |
| ---- | ------------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 66.4 | **Dark web data source verification** | CRITICAL | Verify that dark web monitoring data sources are real and actively refreshing. Some dark web monitoring services provide stale or recycled data. Show data freshness per source.         |
| 66.5 | **Credential validation**             | HIGH     | For exposed credentials, check if they are still valid (without logging in): check password hash against known breaches, verify email is still active. Prioritize still-valid exposures. |

---

## 67. Physical Security

**Source:** `client/src/pages/physical-security.tsx` (1,212 lines) | `server/routes/physical-security.ts`
**Current state:** Physical security convergence with 14 queries, 7 tabs. Badge access monitoring, visitor management, camera integration, convergence alerts.

### UI/UX Polish

| #    | Improvement                            | Priority | Detail                                                                                                                                                                                                           |
| ---- | -------------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 67.1 | **Facility map with real-time status** | HIGH     | Interactive facility floor plan showing: door status (open/closed/locked), camera feeds, badge reader locations, motion sensor zones. Overlay alerts on the map.                                                 |
| 67.2 | **Access anomaly detection**           | HIGH     | Detect physical access anomalies: badge used at two locations simultaneously (cloned badge), after-hours access by non-authorized personnel, tailgating detection, access to restricted areas without clearance. |
| 67.3 | **Visitor check-in/check-out flow**    | MEDIUM   | Self-service visitor check-in: pre-register visitors, generate temporary badges, track visitor location, auto-expire badges, visitor history log.                                                                |

### Backend Completeness

| #    | Improvement                    | Priority | Detail                                                                                                                                                                                                                       |
| ---- | ------------------------------ | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 67.4 | **Physical-cyber convergence** | CRITICAL | Correlate physical access events with cyber events: "User badged into building A at 3am AND logged into domain controller at 3:05am" = high-priority alert. This is the key differentiator of physical security integration. |
| 67.5 | **Camera feed integration**    | LOW      | If camera integration is claimed, verify it works: live feed viewing, recorded footage retrieval, motion detection event correlation. This is complex and may require specific vendor integrations.                          |

---

## 68. Phishing & Awareness

**Source:** `client/src/pages/security-awareness.tsx` (1,291 lines) | `server/routes/security-awareness.ts`
**Current state:** Phishing simulation and security awareness with 13 queries, 7 tabs, 1 chart. Campaign management, email templates, tracking, training assignments.

### UI/UX Polish

| #    | Improvement                          | Priority | Detail                                                                                                                                                                               |
| ---- | ------------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 68.1 | **Campaign creation wizard**         | HIGH     | Step-by-step wizard: select template → customize email → select target group → schedule → review → launch. Preview the phishing email as recipients will see it.                     |
| 68.2 | **Campaign results dashboard**       | HIGH     | Rich results: email open rate, link click rate, credential submission rate, report rate, by department, by role, over time. Compare with industry benchmarks and previous campaigns. |
| 68.3 | **Training assignment and tracking** | HIGH     | Assign training modules based on phishing results: users who clicked links get assigned phishing awareness training. Track completion, quiz scores, certification status.            |
| 68.4 | **Phishing template library**        | MEDIUM   | Library of phishing email templates: categorized by type (credential harvest, malware delivery, BEC), difficulty level, industry vertical. Allow customization.                      |

### Backend Completeness

| #    | Improvement                            | Priority | Detail                                                                                                                                                                                            |
| ---- | -------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 68.5 | **Email delivery infrastructure**      | HIGH     | Phishing simulation emails must actually be delivered to recipient inboxes. Verify email infrastructure: SPF/DKIM/DMARC configuration, email sending service integration, delivery rate tracking. |
| 68.6 | **Click/submission tracking accuracy** | HIGH     | Verify tracking pixel and link tracking work reliably across email clients (Outlook, Gmail, mobile). Track and report on tracking pixel blocking rates.                                           |

---

## 69. Quantum Readiness

**Source:** `client/src/pages/quantum-readiness.tsx` (1,395 lines) | `server/routes/quantum-readiness.ts`
**Current state:** Quantum readiness assessment with 14 queries, 7 tabs, 2 charts. Cryptographic inventory, vulnerability scoring, PQC migration planning, NIST compliance.

### UI/UX Polish

| #    | Improvement                           | Priority | Detail                                                                                                                                                                                                                        |
| ---- | ------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 69.1 | **Cryptographic inventory dashboard** | HIGH     | Show all cryptographic implementations discovered: algorithm, key size, usage context (TLS, data encryption, signing), quantum vulnerability level (vulnerable, uncertain, safe). Priority: identify all RSA/ECC usage first. |
| 69.2 | **Migration roadmap**                 | HIGH     | Visual migration roadmap: which systems need to migrate to PQC algorithms, in what order (prioritize by risk), estimated effort, timeline. Track progress against NIST PQC migration guidelines.                              |
| 69.3 | **Risk assessment scoring**           | HIGH     | Quantum risk score per asset: combines vulnerability of crypto used, sensitivity of data protected, expected timeline to quantum threat. Show org-level aggregate risk.                                                       |

### Backend Completeness

| #    | Improvement                           | Priority | Detail                                                                                                                                                                                     |
| ---- | ------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 69.4 | **Automated cryptographic discovery** | HIGH     | Scan infrastructure for cryptographic usage: TLS certificates, SSH keys, code signing certificates, database encryption, application-level crypto. Currently may require manual inventory. |
| 69.5 | **PQC algorithm recommendations**     | MEDIUM   | For each vulnerable crypto usage, recommend the appropriate PQC replacement: CRYSTALS-Kyber for key exchange, CRYSTALS-Dilithium for signatures, etc. Include migration guidance.          |

---

## 70. Privacy Engineering

**Source:** `client/src/pages/privacy-engineering.tsx` (1,824 lines) | `server/routes/privacy-engineering.ts`
**Current state:** Privacy engineering (DSPM++) with 26 queries, 8 tabs. Data discovery, classification, PIAs, consent management, cross-border risk, DSAR automation.

### UI/UX Polish

| #    | Improvement                             | Priority | Detail                                                                                                                                                                                                               |
| ---- | --------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 70.1 | **Data map visualization**              | HIGH     | Visual map showing where personal data resides: databases, file shares, cloud storage, SaaS applications. Show data flows between systems. Highlight cross-border transfers.                                         |
| 70.2 | **DSAR automation workflow**            | HIGH     | Automated Data Subject Access Request handling: receive request → identify all data for that subject → compile report → redact third-party data → deliver to requester. Track SLA compliance (30-day GDPR deadline). |
| 70.3 | **Consent management dashboard**        | HIGH     | Show consent status per user per purpose: marketing consent (granted), analytics consent (denied), third-party sharing (not requested). Track consent changes over time.                                             |
| 70.4 | **Privacy Impact Assessment templates** | MEDIUM   | PIA templates for common processing activities: new SaaS vendor, employee monitoring, customer analytics, IoT data collection. Guided workflow with risk assessment matrix.                                          |

### Backend Completeness

| #    | Improvement                    | Priority | Detail                                                                                                                                                                                                                       |
| ---- | ------------------------------ | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 70.5 | **Automated data discovery**   | HIGH     | Automatically scan databases, file systems, and APIs for personal data: names, emails, SSNs, credit card numbers, IP addresses. Use pattern matching and ML classification. Currently may require manual data catalog entry. |
| 70.6 | **Data retention enforcement** | HIGH     | Enforce data retention policies automatically: delete personal data after retention period expires, except when under legal hold. Track enforcement execution and exceptions.                                                |

---

## 71. DNS Security

**Source:** `client/src/pages/dns-security.tsx` (803 lines) | `server/routes/dns-security.ts`
**Current state:** DNS security with 15 queries, 6 tabs. DNS query monitoring, DGA detection, tunneling detection, sinkholing, threat feeds.

### UI/UX Polish

| #    | Improvement                     | Priority | Detail                                                                                                                                                                                                  |
| ---- | ------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 71.1 | **DNS query dashboard**         | HIGH     | Real-time DNS query volume, top queried domains, top NXDomain responses, geographic distribution of external DNS targets. Time-range filtering.                                                         |
| 71.2 | **DGA detection visualization** | HIGH     | Show suspected DGA domains with confidence scores, character entropy analysis, lexical feature breakdown. Allow whitelisting false positives.                                                           |
| 71.3 | **DNS tunneling detection**     | HIGH     | Detect and visualize DNS tunneling: show suspiciously long subdomain queries, high query volume to single domains, base64-encoded subdomains. Show bandwidth estimation of potential data exfiltration. |
| 71.4 | **Sinkhole management**         | MEDIUM   | Manage DNS sinkholes: add malicious domains to sinkhole, monitor sinkhole hits (indicates infected hosts trying to reach C2), alert on new sinkhole contacts.                                           |

### Backend Completeness

| #    | Improvement                | Priority | Detail                                                                                                                                                                        |
| ---- | -------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 71.5 | **DNS log ingestion**      | CRITICAL | Verify DNS log ingestion from: recursive resolvers, DNS firewalls, cloud DNS services (Route53, Azure DNS). Without real DNS data, all detection features are non-functional. |
| 71.6 | **DNS policy enforcement** | HIGH     | Block DNS queries to known malicious domains. Implement response policy zones (RPZ). Track and report on blocked query volume.                                                |

---

## 72. Email Security

**Source:** `client/src/pages/email-security.tsx` (1,231 lines) | `server/routes/email-security.ts`
**Current state:** Email security with 17 queries, 13 tabs. BEC detection, thread injection detection, retroactive IOC scanning, M365/Gmail integration.

### UI/UX Polish

| #    | Improvement                      | Priority | Detail                                                                                                                                                                                            |
| ---- | -------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 72.1 | **Email threat dashboard**       | HIGH     | Overview: emails scanned, threats detected, phishing attempts blocked, BEC attempts detected, malicious attachments quarantined. Time-range filtering. Trend charts.                              |
| 72.2 | **Suspicious email detail view** | HIGH     | For each detected threat: full email headers, body preview (safe rendering), attachment analysis results, URL analysis results, sender reputation, DMARC/SPF/DKIM status, AI analysis of content. |
| 72.3 | **Email quarantine management**  | HIGH     | Quarantine queue: review quarantined emails, release false positives, permanently delete confirmed threats, bulk actions. Notify recipients when their email was quarantined.                     |
| 72.4 | **BEC detection patterns**       | HIGH     | Show BEC detection details: which executive was impersonated, what was requested (wire transfer, gift cards, data), lookalike domain used, urgency indicators found.                              |

### Backend Completeness

| #    | Improvement                           | Priority | Detail                                                                                                                                                                                     |
| ---- | ------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 72.5 | **Email gateway integration**         | CRITICAL | Verify integration with email platforms: Microsoft 365 (via Graph API), Gmail (via Workspace API), on-prem Exchange. Without real email access, all detection features are non-functional. |
| 72.6 | **Retroactive IOC scanning**          | HIGH     | When new IOCs are ingested, scan historical email messages for matches. Alert on emails that were delivered before the IOC was known. Show which users may be affected.                    |
| 72.7 | **Email authentication verification** | HIGH     | Check and report on email authentication: SPF, DKIM, DMARC, ARC compliance. Alert on emails that fail authentication checks. Show authentication pass/fail rates over time.                |

---

## 73. MSSP Dashboard

**Source:** `client/src/pages/mssp-dashboard.tsx` (639 lines) | `server/routes/mssp.ts`
**Current state:** MSSP dashboard with 8 queries, 2 charts. Multi-tenant overview for managed security service providers.

### UI/UX Polish

| #    | Improvement                   | Priority | Detail                                                                                                                                                                                                   |
| ---- | ----------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 73.1 | **Multi-tenant overview**     | CRITICAL | At 639 lines, this needs expansion. Show all managed tenants at a glance: alert volumes, incident counts, SLA compliance, health score per tenant. Red/yellow/green status. Allow sorting and filtering. |
| 73.2 | **Tenant drill-down**         | HIGH     | Click a tenant to see detailed security posture: open incidents, critical alerts, compliance status, recent activity. Navigate to tenant-specific views.                                                 |
| 73.3 | **SLA monitoring**            | HIGH     | Track SLA compliance per tenant per metric: response time, resolution time, uptime, report delivery. Show SLA breaches with notifications.                                                               |
| 73.4 | **White-label customization** | HIGH     | Each tenant can have their own branding: logo, color scheme, custom domain. Verify white-label settings actually apply across all tenant-facing pages.                                                   |

### Backend Completeness

| #    | Improvement                            | Priority | Detail                                                                                                                                                                         |
| ---- | -------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 73.5 | **Cross-tenant analytics**             | HIGH     | Aggregated analytics across all tenants: total alert volume, common threat patterns, trending attack types. Anonymized for privacy. Help MSSPs identify widespread threats.    |
| 73.6 | **Tenant data isolation verification** | CRITICAL | Verify absolute data isolation between tenants: no data leakage, no cross-tenant query possibility, separate encryption keys. This is a legal and trust requirement for MSSPs. |

---

## 74. Partner Portal

**Source:** `client/src/pages/mssp-partner-portal.tsx` (1,619 lines) | `server/routes/mssp.ts`
**Current state:** MSSP partner portal with 22 queries, 4 charts. Partner onboarding, SLA management, usage billing, aggregated reporting.

### UI/UX Polish

| #    | Improvement                       | Priority | Detail                                                                                                                                                                         |
| ---- | --------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 74.1 | **Partner onboarding wizard**     | HIGH     | Step-by-step onboarding for new MSSP partners: company info → billing setup → branding configuration → initial user creation → first tenant setup. Currently may be manual.    |
| 74.2 | **Usage and billing dashboard**   | HIGH     | Show MSSP partners their usage across all tenants: billable events, seat counts, storage usage, AI query costs. Compare actual vs. contracted usage. Show billing projections. |
| 74.3 | **Report generation for clients** | HIGH     | MSSPs need to generate branded reports for their clients: monthly security summaries, incident reports, compliance status. Verify report templates support white-labeling.     |

### Backend Completeness

| #    | Improvement                 | Priority | Detail                                                                                                                                                                 |
| ---- | --------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 74.4 | **Usage metering accuracy** | HIGH     | Verify usage metering is accurate across all tenants. Billing discrepancies can damage partner relationships. Implement usage reconciliation checks.                   |
| 74.5 | **Partner API**             | MEDIUM   | API for MSSP partners to: create tenants, manage users, pull reports, query alerts programmatically. Enables automation and integration with partner's existing tools. |

---

## 75. Assessments

**Source:** `client/src/pages/security-assessments.tsx` (611 lines) | `server/routes/security-assessments.ts`
**Current state:** Security assessments with 8 queries, 1 chart. Assessment templates, findings, remediation tracking.

### UI/UX Polish

| #    | Improvement              | Priority | Detail                                                                                                                                                                                       |
| ---- | ------------------------ | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 75.1 | **Assessment workflow**  | HIGH     | Structured assessment workflow: create assessment → assign assessors → conduct assessment (checklist) → document findings → assign remediation → track closure. Currently may be basic CRUD. |
| 75.2 | **Assessment templates** | HIGH     | Pre-built assessment templates: penetration test, vulnerability assessment, risk assessment, compliance audit, security architecture review. Each with appropriate checklists.               |
| 75.3 | **Findings management**  | HIGH     | Track findings from assessments with severity, affected systems, recommended remediation, assigned owner, due date, and current status. Link findings to the Risk Register.                  |

### Backend Completeness

| #    | Improvement                             | Priority | Detail                                                                                                                                               |
| ---- | --------------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| 75.4 | **Assessment scheduling**               | MEDIUM   | Schedule recurring assessments: annual penetration test, quarterly vulnerability assessment, monthly compliance check. Calendar view with reminders. |
| 75.5 | **Finding → Risk Register integration** | HIGH     | Assessment findings should automatically create or update Risk Register entries. Prevent findings from being lost or forgotten.                      |

---

## 76. Threat Reports

**Source:** `client/src/pages/threat-reports.tsx` (609 lines) | `server/routes/threat-reports.ts`
**Current state:** Threat report management with 5 queries, 4 charts. Create and share threat intelligence reports.

### UI/UX Polish

| #    | Improvement             | Priority | Detail                                                                                                                                                                          |
| ---- | ----------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 76.1 | **Report editor**       | HIGH     | Rich text editor for creating threat reports: markdown support, inline images, tables, code blocks, IOC tables, MITRE ATT&CK technique references, TLP classification markings. |
| 76.2 | **Report templates**    | HIGH     | Templates for common report types: threat advisory, incident summary, vulnerability disclosure, campaign analysis, industry threat landscape. Each with appropriate structure.  |
| 76.3 | **Report distribution** | HIGH     | Distribute reports to: internal teams, selected external partners, ISAC communities. Track who has accessed the report. Enforce TLP classifications.                            |

### Backend Completeness

| #    | Improvement                              | Priority | Detail                                                                                                                                                    |
| ---- | ---------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 76.4 | **Report generation from platform data** | HIGH     | Auto-populate reports with platform data: latest threat intel, recent incidents, IOC statistics, compliance posture. Reduce manual report writing effort. |
| 76.5 | **STIX report format**                   | MEDIUM   | Export threat reports in STIX format for interoperability with other threat intelligence platforms and ISACs.                                             |

---

## 77. Advanced Reports

**Source:** `client/src/pages/advanced-reporting.tsx` (732 lines) | `server/routes/advanced-reporting.ts`
**Current state:** Advanced reporting with 8 queries, 13 tabs, 7 charts. PDF generation, compliance templates, white-label support, financial impact analysis.

### UI/UX Polish

| #    | Improvement                           | Priority | Detail                                                                                                                                                                                          |
| ---- | ------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 77.1 | **Report builder with drag-and-drop** | HIGH     | Visual report builder: drag-and-drop widgets (charts, tables, text blocks, KPI cards) onto a canvas. Configure each widget's data source and appearance. Preview before generating.             |
| 77.2 | **Scheduled report delivery**         | HIGH     | Schedule reports for automatic generation and delivery: weekly security summary every Monday at 9am, monthly compliance report on the 1st, quarterly board report. Email and/or Slack delivery. |
| 77.3 | **Report versioning and history**     | MEDIUM   | Track all generated reports: when, by whom, what version of the template, what data snapshot. Allow re-generating previous reports with updated data.                                           |

### Backend Completeness

| #    | Improvement                   | Priority | Detail                                                                                                                                                                                                                   |
| ---- | ----------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 77.4 | **PDF generation quality**    | HIGH     | PDF reports should be high-quality: proper typography, correctly rendered charts (SVG-based), professional headers/footers with page numbers, table of contents for long reports. Verify charts render correctly in PDF. |
| 77.5 | **Data snapshot for reports** | MEDIUM   | When a report is generated, snapshot the underlying data. Ensure the report reflects data at generation time, even if data changes later. Important for compliance reports.                                              |

---

## 78. Compliance Center

**Source:** `client/src/pages/compliance.tsx` (3,202 lines) | `server/routes/compliance.ts`
**Current state:** Comprehensive compliance center with 35 queries/mutations, 23 tabs, 5 charts. 15+ compliance frameworks (SOC 2, ISO 27001, PCI DSS, HIPAA, GDPR, NIS2, DORA, etc.), control mapping, evidence collection, gap analysis.

### UI/UX Polish

| #    | Improvement                                   | Priority | Detail                                                                                                                                                                                         |
| ---- | --------------------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 78.1 | **Framework selector with progress overview** | HIGH     | Landing view should show all available frameworks with a donut chart showing compliance percentage for each. Click a framework to see detailed control-by-control status.                      |
| 78.2 | **Control detail with evidence**              | HIGH     | Each compliance control should show: description, current status (compliant/non-compliant/partially compliant), evidence attached, responsible person, last reviewed date, gap analysis notes. |
| 78.3 | **Evidence collection workflow**              | HIGH     | For each control, guided evidence collection: what evidence is needed, where to find it (auto-link to platform features that provide evidence), upload external evidence, mark as reviewed.    |
| 78.4 | **Audit readiness dashboard**                 | HIGH     | Show overall audit readiness: controls with evidence (85%), controls without evidence (10%), controls not assessed (5%). Time to next audit. Controls needing attention before audit.          |
| 78.5 | **Cross-framework control mapping**           | MEDIUM   | Show how controls map across frameworks: SOC 2 CC6.1 = ISO 27001 A.9.1.1 = NIST 800-53 AC-2. Implement one control, satisfy multiple frameworks.                                               |

### Backend Completeness

| #    | Improvement                          | Priority | Detail                                                                                                                                                                                                                               |
| ---- | ------------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 78.6 | **Automated evidence collection**    | CRITICAL | Automatically collect compliance evidence from platform features: MFA enabled (from Settings), vulnerability scan results (from Vuln Scanner), access review completed (from Identity Governance). Reduce manual evidence gathering. |
| 78.7 | **Continuous compliance monitoring** | HIGH     | Continuously monitor compliance status. Alert when a previously compliant control becomes non-compliant (e.g., MFA disabled for an admin account).                                                                                   |
| 78.8 | **Framework version updates**        | MEDIUM   | When compliance frameworks are updated (e.g., SOC 2 2022 → SOC 2 2024), map changes: new controls, removed controls, modified requirements. Help orgs update their compliance programs.                                              |

---

## 79. Trust Center

**Source:** `client/src/pages/trust-center.tsx` (924 lines) | `server/routes/posture-trust.ts`
**Current state:** Trust center with 12 queries. Public-facing trust page showing security posture, compliance certifications, and policies.

### UI/UX Polish

| #    | Improvement                            | Priority | Detail                                                                                                                                                                                               |
| ---- | -------------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 79.1 | **Public trust page design**           | HIGH     | Professional, brandable public page: security overview, compliance badges (SOC 2 Type II, ISO 27001), data handling practices, subprocessor list, incident response process, security contacts.      |
| 79.2 | **Self-service NDA and security pack** | HIGH     | Allow visitors to request security documentation behind an NDA: request form → auto-generate NDA → e-sign → grant access to security pack (pen test results, compliance reports, architecture docs). |
| 79.3 | **Compliance document management**     | MEDIUM   | Upload and manage compliance documents: certificates, audit reports, pen test summaries. Set access levels (public, NDA-required, internal-only). Track document expiration.                         |

### Backend Completeness

| #    | Improvement                        | Priority | Detail                                                                                                                                                                                     |
| ---- | ---------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 79.4 | **Auto-update from platform data** | HIGH     | Trust center should auto-update: compliance badge status from Compliance Center, posture score from Security Posture Score, last pen test date from Assessments. No manual updates needed. |
| 79.5 | **Access analytics**               | LOW      | Track who visits the trust center: page views, document downloads, NDA requests. Understand customer security review patterns.                                                             |

---

## 80. Gap Analysis

**Source:** `client/src/pages/gap-analysis.tsx` (334 lines), `client/src/pages/compliance-gap.tsx` (364 lines) | `server/routes/compliance.ts`
**Current state:** Gap analysis with 2-6 queries, 3 tabs, 1 chart. Basic gap identification between current state and compliance requirements.

### UI/UX Polish

| #    | Improvement                  | Priority | Detail                                                                                                                                                                                                                   |
| ---- | ---------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 80.1 | **Gap visualization**        | CRITICAL | At 334+364 lines, these pages are minimal. Show gaps visually: a matrix of controls vs. compliance status with color coding (green=compliant, yellow=partial, red=gap). Filter by framework, by severity, by department. |
| 80.2 | **Gap remediation tracking** | HIGH     | For each gap, create a remediation task: description, assigned owner, due date, effort estimate, status. Link to relevant platform features that can help close the gap.                                                 |
| 80.3 | **Gap trend over time**      | HIGH     | Track gap count over time: are gaps being closed faster than new ones appear? Show remediation velocity and forecast when all gaps will be closed at current pace.                                                       |

### Backend Completeness

| #    | Improvement                 | Priority | Detail                                                                                                                                                                  |
| ---- | --------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 80.4 | **Automated gap detection** | HIGH     | Automatically detect gaps by comparing platform state against compliance requirements: no MFA = gap against SOC 2 CC6.1, no encryption = gap against HIPAA §164.312(a). |
| 80.5 | **Gap prioritization**      | HIGH     | Prioritize gaps by: compliance criticality, audit proximity, remediation effort, risk impact. Show a prioritized remediation backlog.                                   |

---

## 81. Audit Log

**Source:** `client/src/pages/audit-log.tsx` (527 lines) | `server/routes/admin.ts`
**Current state:** Audit log viewer with 2 queries. Shows user actions and system events with filtering.

### UI/UX Polish

| #    | Improvement              | Priority | Detail                                                                                                                                                            |
| ---- | ------------------------ | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 81.1 | **Advanced filtering**   | HIGH     | Filter audit logs by: user, action type, resource type, time range, result (success/failure), IP address. Combine filters with AND/OR logic. Save filter presets. |
| 81.2 | **Audit log search**     | HIGH     | Full-text search across audit log entries. Search by: specific resource IDs, user names, IP addresses, action descriptions.                                       |
| 81.3 | **Audit log export**     | HIGH     | Export audit logs as CSV, JSON, or PDF. Support scheduled exports for compliance requirements (daily/weekly audit log delivery).                                  |
| 81.4 | **User activity report** | MEDIUM   | Generate per-user activity reports: all actions taken, systems accessed, data modified. Useful for access reviews and investigations.                             |

### Backend Completeness

| #    | Improvement                      | Priority | Detail                                                                                                                                                                                                    |
| ---- | -------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 81.5 | **Comprehensive audit coverage** | CRITICAL | Verify EVERY user action and system event is logged: CRUD on all resources, authentication events, permission changes, configuration changes, data exports, report generation. Audit every route handler. |
| 81.6 | **Tamper-proof audit trail**     | HIGH     | Audit logs must be immutable: no editing, no deletion (except by retention policy). Consider append-only storage or blockchain-style chaining for high-integrity audit requirements.                      |
| 81.7 | **Audit log retention policy**   | HIGH     | Configure audit log retention (typically 1-7 years for compliance). Auto-archive old logs to cold storage. Ensure logs under legal hold are not purged.                                                   |

---

## 82. Policy Packs

**Source:** `client/src/pages/policy-packs.tsx` (877 lines) | `server/routes/compliance.ts`
**Current state:** Policy pack management with 16 queries. Pre-built security policy documents and templates.

### UI/UX Polish

| #    | Improvement                                   | Priority | Detail                                                                                                                                                          |
| ---- | --------------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 82.1 | **Policy library with search and categories** | HIGH     | Browse policies by category: acceptable use, data classification, incident response, access control, remote work, BYOD, password, encryption. Full-text search. |
| 82.2 | **Policy customization workflow**             | HIGH     | Start with a template → customize for your org → legal review → approval → publish → distribute → track acknowledgment. Guided workflow.                        |
| 82.3 | **Policy acknowledgment tracking**            | HIGH     | Track which employees have read and acknowledged each policy. Send reminders for unacknowledged policies. Report acknowledgment rates by department.            |
| 82.4 | **Policy version management**                 | MEDIUM   | Track policy versions: what changed between versions, when was each version active, who approved changes. Required for compliance audits.                       |

### Backend Completeness

| #    | Improvement                    | Priority | Detail                                                                                                                                                                     |
| ---- | ------------------------------ | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 82.5 | **Policy compliance checking** | HIGH     | Check whether platform configuration actually complies with published policies. "Password policy says 12-character minimum — is this enforced in authentication settings?" |
| 82.6 | **Policy distribution**        | MEDIUM   | Distribute policies via: email with acknowledgment tracking, integration with LMS (learning management system), embed in employee onboarding flow.                         |

---

## 83. Reports

**Source:** `client/src/pages/reports.tsx` (1,378 lines) | `server/routes/reporting.ts`
**Current state:** Report management with 16 queries, 11 tabs, 30 charts. Comprehensive reporting with templates, scheduling, and distribution.

### UI/UX Polish

| #    | Improvement                        | Priority | Detail                                                                                                                                                                      |
| ---- | ---------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 83.1 | **Report template gallery**        | HIGH     | Visual gallery of report templates with preview thumbnails: executive summary, detailed technical, compliance audit, incident summary, risk assessment, board presentation. |
| 83.2 | **Report scheduling calendar**     | HIGH     | Calendar view showing all scheduled reports: what generates when, who receives it. Drag to reschedule. Show last generation status (success/failure).                       |
| 83.3 | **Report sharing and permissions** | MEDIUM   | Share reports with: internal users (by role), external recipients (by email with access link), public URL (for trust center reports). Set per-report access permissions.    |

### Backend Completeness

| #    | Improvement                  | Priority | Detail                                                                                                                                                                                         |
| ---- | ---------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 83.4 | **Report data accuracy**     | HIGH     | Verify report data matches platform data exactly. No discrepancies between what the dashboard shows and what reports contain. Implement data snapshot at generation time.                      |
| 83.5 | **Report delivery channels** | HIGH     | Support report delivery via: email (PDF attachment), Slack (file upload), S3 (for automated processing), webhook (notification with download link). Currently may only support in-app viewing. |

---

## 84. Data Residency

**Source:** `client/src/pages/data-residency.tsx` (1,089 lines) | `server/routes/data-residency.ts`
**Current state:** Data residency and sovereignty with 19 queries, 11 tabs. Per-org region selection, BYOK key management, cross-border flow controls.

### UI/UX Polish

| #    | Improvement                       | Priority | Detail                                                                                                                                                                              |
| ---- | --------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 84.1 | **Data flow map**                 | HIGH     | Visual map showing where data resides and flows: origin regions, processing regions, storage regions, cross-border transfers. Highlight transfers that violate configured policies. |
| 84.2 | **BYOK key management dashboard** | HIGH     | Show all encryption keys: which data they protect, rotation status, last rotated, next rotation. One-click rotation with impact preview.                                            |
| 84.3 | **Compliance mapping**            | HIGH     | Show how data residency configuration maps to compliance requirements: GDPR (EU data stays in EU), PIPEDA (Canadian data stays in Canada), data localization laws.                  |

### Backend Completeness

| #    | Improvement                       | Priority | Detail                                                                                                                                                                                |
| ---- | --------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 84.4 | **Cross-border flow enforcement** | CRITICAL | Verify that cross-border flow controls actually prevent data movement. Test: create data in region A → attempt to access from region B → verify blocked. This is a legal requirement. |
| 84.5 | **BYOK integration**              | HIGH     | Verify BYOK key management actually encrypts data with customer-provided keys. Test: rotate key → verify data is re-encrypted → verify old key no longer works.                       |

---

## 85. Board Dashboard

**Source:** `client/src/pages/board-dashboard.tsx` (620 lines) | `server/routes/admin.ts`
**Current state:** Executive board dashboard with 10 queries, 8 tabs, 2 charts. High-level security metrics for board reporting.

### UI/UX Polish

| #    | Improvement                          | Priority | Detail                                                                                                                                                                                             |
| ---- | ------------------------------------ | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 85.1 | **Executive-friendly visualization** | HIGH     | Board members are non-technical. Use simple, clear visualizations: traffic light status (red/yellow/green), trend arrows (improving/declining), risk scores as percentages. Avoid security jargon. |
| 85.2 | **Financial risk quantification**    | HIGH     | Show security risk in financial terms: "Estimated annual loss exposure: $2.4M. Current mitigation reduces this to $450K. Remaining risk: $450K." Board members understand dollars, not CVE counts. |
| 85.3 | **Regulatory compliance status**     | HIGH     | Simple compliance status per framework: SOC 2 ✓, ISO 27001 ✓, HIPAA ⚠ (3 gaps), PCI DSS ✗ (not started). Click for detail.                                                                         |
| 85.4 | **Incident summary for executives**  | HIGH     | Show significant incidents in business terms: "A phishing attack compromised 3 accounts. Impact: 2 hours of downtime. Resolution: all accounts secured, no data loss confirmed."                   |
| 85.5 | **Board report generation**          | HIGH     | One-click generation of a board-ready PDF report: security posture summary, key metrics, incident highlights, compliance status, risk register top items, budget utilization.                      |

### Backend Completeness

| #    | Improvement                            | Priority | Detail                                                                                                                                                                                                      |
| ---- | -------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 85.6 | **Data aggregation for board metrics** | HIGH     | Aggregate security data into board-level KPIs: security posture trend, incident volume trend, mean time to detect/respond, compliance coverage, third-party risk posture. Verify aggregations are accurate. |
| 85.7 | **Historical trend data**              | MEDIUM   | Maintain historical data for board metrics: show quarter-over-quarter and year-over-year comparisons. Board members want to see improvement trajectory.                                                     |

---

## 86. Onboarding

**Source:** `client/src/pages/onboarding-wizard.tsx` (842 lines), `client/src/pages/onboarding.tsx` (249 lines) | `server/routes/onboarding.ts`
**Current state:** Onboarding wizard with 10 queries. Multi-step wizard for new org setup: company info, plan selection, team invites, first connector setup.

### UI/UX Polish

| #    | Improvement                                   | Priority | Detail                                                                                                                                                                                      |
| ---- | --------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 86.1 | **Progress persistence**                      | HIGH     | If the user leaves mid-wizard and returns later, resume from where they left off. Currently wizard state may reset on page reload. Save progress server-side per user.                      |
| 86.2 | **Step validation with helpful errors**       | HIGH     | Each step should validate inputs before allowing progression. Show clear, actionable error messages. Highlight required fields that are missing.                                            |
| 86.3 | **Skip and revisit**                          | MEDIUM   | Allow skipping optional steps (e.g., team invites) and coming back later. Show which steps were skipped with "Complete later" reminders on the dashboard.                                   |
| 86.4 | **Getting started checklist post-onboarding** | HIGH     | After wizard completion, show a "Getting Started" checklist on the dashboard: ☐ Set up first connector, ☐ Configure detection rules, ☐ Create a playbook, ☐ Run first scan. Track progress. |

### Backend Completeness

| #    | Improvement                      | Priority | Detail                                                                                                                                                                     |
| ---- | -------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 86.5 | **Onboarding analytics**         | MEDIUM   | Track: completion rate per step, drop-off points, time to complete, most common configurations chosen. Use data to optimize the onboarding flow.                           |
| 86.6 | **Onboarding for invited users** | HIGH     | Invited team members should have their own simplified onboarding: accept invitation → set password → configure profile → guided tour. Different from org admin onboarding. |

---

## 87. Team & Invites

**Source:** `client/src/pages/team-management.tsx` (1,813 lines) | `server/routes/admin.ts`
**Current state:** Team management with 28 queries, 9 tabs. User CRUD, role assignment, invitation management.

### UI/UX Polish

| #    | Improvement                 | Priority | Detail                                                                                                                                                                           |
| ---- | --------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 87.1 | **Role permission matrix**  | HIGH     | Visual matrix showing what each role can do: admin (everything), analyst (view + triage), viewer (read-only), etc. Let admins create custom roles with fine-grained permissions. |
| 87.2 | **Team member activity**    | HIGH     | Show team member activity: last login, alerts triaged, incidents handled, playbooks executed. Identify inactive members. Help with license optimization.                         |
| 87.3 | **Invitation management**   | HIGH     | Track pending invitations: who was invited, when, by whom, status (pending/accepted/expired). Allow resending expired invitations. Bulk invite via CSV upload.                   |
| 87.4 | **User profile management** | MEDIUM   | Each user should manage their profile: display name, avatar, notification preferences, timezone, keyboard shortcut preferences.                                                  |

### Backend Completeness

| #    | Improvement                | Priority | Detail                                                                                                                                              |
| ---- | -------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| 87.5 | **SCIM user provisioning** | HIGH     | Support SCIM for automated user provisioning from identity providers (Okta, Azure AD, OneLogin). Auto-create users on hire, disable on termination. |
| 87.6 | **Session management**     | HIGH     | Show active sessions per user. Allow revoking sessions (force logout). Track suspicious sessions (new device, new location).                        |
| 87.7 | **Custom role creation**   | HIGH     | Admin-definable custom roles with granular permissions per feature area. Currently may have only fixed roles (admin, analyst, viewer).              |

---

## 88. Org Settings

**Source:** `client/src/pages/org-settings.tsx` (1,449 lines) | `server/routes/admin.ts`
**Current state:** Organization settings with 21 queries. Org profile, branding, notification settings, security policies, API configuration.

### UI/UX Polish

| #    | Improvement               | Priority | Detail                                                                                                                                                                                                         |
| ---- | ------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 88.1 | **Settings organization** | HIGH     | Group settings logically: General (name, logo, timezone), Security (MFA policy, password policy, session timeout), Notifications (email, Slack, webhook), Integrations (API keys, SSO), Billing (plan, usage). |
| 88.2 | **Settings search**       | MEDIUM   | Search across all settings: type "MFA" → shows MFA configuration section. For complex settings pages, search is essential.                                                                                     |
| 88.3 | **Settings change audit** | HIGH     | Log all settings changes: who changed what, when, from what value to what value. Show recent changes. Require confirmation for security-sensitive changes.                                                     |

### Backend Completeness

| #    | Improvement                     | Priority | Detail                                                                                                                                                             |
| ---- | ------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 88.4 | **SSO configuration**           | HIGH     | Support SSO providers: SAML 2.0 (Okta, Azure AD, OneLogin), OIDC (Google, Auth0). Step-by-step configuration wizard with metadata upload and test login.           |
| 88.5 | **Security policy enforcement** | HIGH     | Enforced security policies: password complexity, session timeout, MFA requirements, IP allowlisting. Verify policies are actually enforced at authentication time. |

---

## 89. Developer Portal

**Source:** `client/src/pages/developer-portal.tsx` (1,097 lines), `client/src/pages/dev-portal.tsx` (1,277 lines) | `server/routes/developer-portal.ts`
**Current state:** Developer portal with API documentation, SDK downloads, code examples, API key management. Two overlapping pages (developer-portal.tsx and dev-portal.tsx).

### UI/UX Polish

| #    | Improvement                       | Priority | Detail                                                                                                                                                                                    |
| ---- | --------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 89.1 | **Consolidate duplicate pages**   | CRITICAL | Two developer portal pages exist (`developer-portal.tsx` at 1,097 lines and `dev-portal.tsx` at 1,277 lines). These should be consolidated into a single, comprehensive developer portal. |
| 89.2 | **Interactive API documentation** | HIGH     | Swagger/OpenAPI-style interactive API docs: try endpoints directly from the browser, see request/response examples, auto-generate code snippets in multiple languages.                    |
| 89.3 | **API key management**            | HIGH     | Create, rotate, and revoke API keys. Per-key permissions (read-only, read-write, admin). Usage statistics per key. Expiration and rotation reminders.                                     |
| 89.4 | **SDK and code examples**         | MEDIUM   | Provide SDKs for popular languages (Python, JavaScript, Go, Java) with code examples for common use cases: create alert, query incidents, trigger playbook, ingest events.                |

### Backend Completeness

| #    | Improvement                   | Priority | Detail                                                                                                                                                                     |
| ---- | ----------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 89.5 | **API rate limiting per key** | HIGH     | Enforce rate limits per API key based on plan tier. Show current usage vs. limits. Provide rate limit headers in API responses (X-RateLimit-Remaining, X-RateLimit-Reset). |
| 89.6 | **API versioning**            | HIGH     | Support API versioning (v1, v2) with deprecation notices and migration guides. Don't break existing integrations when the API evolves.                                     |

---

## 90. Billing

**Source:** `client/src/pages/billing.tsx` (1,144 lines) | `server/routes/billing.ts`
**Current state:** Billing management with 14 queries, 7 tabs. Stripe integration, plan management, invoices, usage-based billing.

### UI/UX Polish

| #    | Improvement                       | Priority | Detail                                                                                                                                                                               |
| ---- | --------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 90.1 | **Current plan overview**         | HIGH     | Clear display of current plan: name, price, included features, usage limits, renewal date. Show usage vs. limits for metered features. Upgrade/downgrade buttons prominently placed. |
| 90.2 | **Invoice history with download** | HIGH     | Show all past invoices with: date, amount, payment status, PDF download link. Support invoice search and date range filtering.                                                       |
| 90.3 | **Usage forecasting**             | HIGH     | Based on current usage trends, forecast next month's bill. Alert when projected usage will exceed plan limits or budget.                                                             |
| 90.4 | **Payment method management**     | HIGH     | Add/remove payment methods. Show which method is default. Support credit card, ACH, wire transfer. PCI-compliant credit card input.                                                  |

### Backend Completeness

| #    | Improvement                 | Priority | Detail                                                                                                                                                                         |
| ---- | --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 90.5 | **Stripe webhook handling** | HIGH     | Verify all Stripe webhook events are handled: payment succeeded, payment failed, subscription updated, subscription cancelled, invoice created. Test webhook retry scenarios.  |
| 90.6 | **Plan change proration**   | HIGH     | When changing plans mid-cycle, correctly calculate proration: credit for unused time on old plan, charge for remaining time on new plan. Verify with Stripe's proration logic. |

---

## 91. Usage & Metering

**Source:** `client/src/pages/usage-billing.tsx` (541 lines), `client/src/pages/usage-metering-analytics.tsx` (281 lines) | `server/routes/billing.ts`
**Current state:** Usage tracking with 5-7 queries, 7-11 tabs. Shows usage metrics across platform features.

### UI/UX Polish

| #    | Improvement                     | Priority | Detail                                                                                                                                                                                              |
| ---- | ------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 91.1 | **Usage dashboard with limits** | HIGH     | Show all metered resources with progress bars: events ingested (80% of limit), active users (12/25), AI queries used (450/1000), storage consumed (45GB/100GB). Color coding as approaching limits. |
| 91.2 | **Usage breakdown by category** | HIGH     | Break down usage by: feature area, user, data source. Identify who/what is consuming the most resources. Help optimize usage.                                                                       |
| 91.3 | **Usage alerts**                | HIGH     | Configure alerts at usage thresholds: 80%, 90%, 95%, 100%. Notify admins before limits are reached. Show projected date of limit exhaustion.                                                        |

### Backend Completeness

| #    | Improvement                 | Priority | Detail                                                                                                                                                                   |
| ---- | --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 91.4 | **Accurate metering**       | CRITICAL | Verify metering is accurate for all billable resources. Discrepancies between actual usage and billed usage are a trust issue. Implement metering reconciliation checks. |
| 91.5 | **Consolidate usage pages** | HIGH     | Two usage pages exist (`usage-billing.tsx` and `usage-metering-analytics.tsx`). Consolidate into a single comprehensive usage analytics page.                            |

---

## 92. Plans & Packaging

**Source:** `client/src/pages/tiered-packaging.tsx` (964 lines) | `server/routes/billing.ts`
**Current state:** Plan comparison and packaging with 8 queries, 11 tabs, 3 charts. Shows plan tiers with feature matrices.

### UI/UX Polish

| #    | Improvement                        | Priority | Detail                                                                                                                                                                              |
| ---- | ---------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 92.1 | **Plan comparison table**          | HIGH     | Side-by-side comparison of all plan tiers: Free, Starter, Professional, Enterprise. Show features included in each tier. Highlight the recommended plan based on current usage.     |
| 92.2 | **Plan upgrade flow**              | HIGH     | Smooth upgrade flow: select new plan → review price change → preview feature unlocks → confirm → immediate access to new features. No page reload or re-authentication required.    |
| 92.3 | **Enterprise plan custom pricing** | MEDIUM   | For enterprise tier: show "Contact Sales" with a form. Collect: company size, expected usage, required features, security requirements. Auto-generate a quote or notify sales team. |

### Backend Completeness

| #    | Improvement                    | Priority | Detail                                                                                                                                                                                     |
| ---- | ------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 92.4 | **Feature gating enforcement** | HIGH     | Verify all plan-gated features are actually enforced: free tier users can't access enterprise features, API limits match plan tier, storage limits are enforced. Test every gated feature. |
| 92.5 | **Trial management**           | MEDIUM   | Support free trials: 14-day trial of higher tier → auto-downgrade at expiration → email reminder at 3/1 day before expiration → offer to convert.                                          |

---

## 93. Settings

**Source:** `client/src/pages/settings.tsx` (788 lines), `client/src/pages/mfa-setup.tsx` (244 lines) | `server/routes/admin.ts`
**Current state:** User settings with 11 queries. Profile management, MFA setup, notification preferences.

### UI/UX Polish

| #    | Improvement                              | Priority | Detail                                                                                                                                                                                                   |
| ---- | ---------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 93.1 | **Settings categories with navigation**  | HIGH     | Organize settings into clear categories with a side navigation: Profile, Security (MFA, sessions), Notifications (email, in-app, Slack), Appearance (theme, density, language), Integrations (API keys). |
| 93.2 | **MFA setup improvements**               | HIGH     | MFA setup should support: authenticator app (TOTP), SMS, hardware security key (WebAuthn/FIDO2). Show backup codes with download option. Currently may only support one MFA method.                      |
| 93.3 | **Active session management**            | HIGH     | Show all active sessions: device, browser, IP address, last activity, location (geo-IP). Allow revoking individual sessions. "Log out all other sessions" button.                                        |
| 93.4 | **Notification preferences granularity** | MEDIUM   | Per-notification-type preferences: critical alerts (email + push), medium alerts (in-app only), status updates (digest). Don't send everything everywhere — let users control notification volume.       |

### Backend Completeness

| #    | Improvement                | Priority | Detail                                                                                                                                           |
| ---- | -------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| 93.5 | **WebAuthn/FIDO2 support** | HIGH     | Support hardware security keys for MFA. This is the most phishing-resistant MFA method and increasingly required for compliance (FedRAMP, CJIS). |
| 93.6 | **Profile picture upload** | LOW      | Allow users to upload a profile picture. Show in team member lists, war room chat, audit logs. Support gravatar fallback.                        |

---

## 94. Landing Page

**Source:** `client/src/pages/landing.tsx` (1,222 lines) | No backend route (static page)
**Current state:** Marketing landing page with 3 charts. Product overview, feature highlights, pricing, CTA for sign-up.

### UI/UX Polish

| #    | Improvement                  | Priority | Detail                                                                                                                                                         |
| ---- | ---------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 94.1 | **Performance optimization** | HIGH     | Landing page must load in <2 seconds. Optimize: lazy-load images, minimize JavaScript bundle, use CDN for static assets. First contentful paint should be <1s. |
| 94.2 | **SEO optimization**         | HIGH     | Add proper meta tags: title, description, Open Graph, Twitter cards. Structured data (JSON-LD). Semantic HTML. Alt text on all images.                         |
| 94.3 | **Mobile responsiveness**    | HIGH     | Landing page must look great on all devices. Test on: iPhone SE (small), iPhone Pro Max, iPad, Android phones, desktop 1920px, ultrawide 2560px.               |
| 94.4 | **Accessibility**            | HIGH     | WCAG 2.1 AA compliance: keyboard navigation, screen reader support, color contrast ratios, focus indicators, alt text.                                         |
| 94.5 | **Social proof**             | MEDIUM   | Add: customer logos, testimonials, case studies, industry awards, analyst reports. Build trust with potential customers.                                       |
| 94.6 | **CTA optimization**         | MEDIUM   | Clear, compelling CTAs: "Start Free Trial", "Book a Demo", "View Pricing". A/B test CTA text, color, and placement.                                            |

### Backend Completeness

| #    | Improvement                     | Priority | Detail                                                                                                                                                               |
| ---- | ------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 94.7 | **Contact form / demo request** | HIGH     | Functional contact form: name, email, company, message. Demo request form: name, email, company size, use case. Deliver to sales team via email and CRM integration. |
| 94.8 | **Analytics integration**       | MEDIUM   | Track landing page metrics: visitors, bounce rate, CTA click rate, conversion to sign-up. Integrate with Google Analytics, Mixpanel, or PostHog.                     |

---

## 95. Cross-Cutting Platform Concerns

These improvements affect the entire platform, not individual features.

### Error Handling

| #    | Improvement                             | Priority | Detail                                                                                                                                                                                                                              |
| ---- | --------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 95.1 | **Global error boundary with recovery** | HIGH     | Every page should be wrapped in an error boundary that: catches rendering errors, shows a user-friendly error message, offers a "Refresh" button, logs the error to the error tracker. Verify error boundaries exist on all routes. |
| 95.2 | **API error handling consistency**      | HIGH     | All API error responses should follow a consistent format: `{error: string, code: string, details?: object}`. All frontend API calls should handle errors gracefully with toast notifications. No unhandled promise rejections.     |
| 95.3 | **Offline handling**                    | MEDIUM   | When the user loses internet connectivity, show a persistent banner: "You are offline. Changes will be saved when connectivity is restored." Queue mutations and replay when online.                                                |

### Performance

| #    | Improvement                    | Priority | Detail                                                                                                                                                                         |
| ---- | ------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 95.4 | **Route-based code splitting** | HIGH     | Verify every page component is lazily loaded. The initial JavaScript bundle should only contain the landing page and authentication code. Feature pages should load on-demand. |
| 95.5 | **Query deduplication**        | HIGH     | Verify React Query deduplicates identical in-flight queries. Multiple components requesting the same data should result in a single API call. Check for duplicate query keys.  |
| 95.6 | **Image optimization**         | MEDIUM   | Optimize all images: use WebP format, lazy loading, proper sizing. Use `<picture>` element with responsive sizes.                                                              |
| 95.7 | **Bundle size analysis**       | MEDIUM   | Run bundle analyzer and identify large dependencies. Consider alternatives for oversized libraries. Set a budget: main bundle <500KB gzipped.                                  |

### Accessibility

| #     | Improvement                        | Priority | Detail                                                                                                                                                                                       |
| ----- | ---------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 95.8  | **Keyboard navigation throughout** | HIGH     | Every interactive element should be keyboard-accessible. Tab order should be logical. Focus management after dialog open/close. Skip links for screen reader users.                          |
| 95.9  | **Screen reader compatibility**    | HIGH     | All form inputs should have labels. All images should have alt text. All icons should have aria-labels. Dynamic content changes should be announced. Data tables should have proper headers. |
| 95.10 | **Color contrast**                 | MEDIUM   | Verify all text meets WCAG 2.1 AA contrast ratios (4.5:1 for normal text, 3:1 for large text). Audit dark theme and light theme.                                                             |

### Internationalization

| #     | Improvement                     | Priority | Detail                                                                                                                                                                                                                     |
| ----- | ------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 95.11 | **i18n framework setup**        | MEDIUM   | Set up i18n framework (react-i18next). Extract all user-facing strings. Support at minimum: English, Hindi, Japanese, German, French, Portuguese. Even if translations aren't immediate, the framework should be in place. |
| 95.12 | **Date/time/number formatting** | MEDIUM   | Use locale-aware formatting for: dates (MM/DD/YYYY vs. DD/MM/YYYY), times (12h vs. 24h), numbers (1,000 vs. 1.000), currencies. Currently may use hardcoded US formats.                                                    |

### Monitoring & Observability

| #     | Improvement                 | Priority | Detail                                                                                                                                                       |
| ----- | --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 95.13 | **Frontend error tracking** | HIGH     | Send frontend errors to an error tracking service (Sentry, Datadog). Include: stack trace, user context (ID, role, page), browser info, reproduction steps.  |
| 95.14 | **Performance monitoring**  | HIGH     | Track frontend performance metrics: page load time, time to interactive, largest contentful paint, cumulative layout shift. Alert when performance degrades. |
| 95.15 | **API latency monitoring**  | HIGH     | Track and alert on API endpoint latency. Show p50, p95, p99 latency per endpoint. Alert when latency exceeds SLA thresholds.                                 |

### Security

| #     | Improvement                               | Priority | Detail                                                                                                                                                                              |
| ----- | ----------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 95.16 | **Content Security Policy audit**         | HIGH     | Audit and tighten CSP headers. Remove any overly permissive directives. Ensure CSP covers: script-src, style-src, img-src, connect-src, frame-ancestors.                            |
| 95.17 | **Dependency vulnerability scanning**     | HIGH     | Continuous scanning of npm and Python dependencies for known vulnerabilities. Auto-PR for patch-level updates. Alert for critical vulnerabilities.                                  |
| 95.18 | **Penetration test findings remediation** | HIGH     | Track findings from external penetration tests. Ensure all critical and high findings are remediated. Retest to verify fixes.                                                       |
| 95.19 | **RBAC audit across all endpoints**       | CRITICAL | Verify every API endpoint enforces RBAC. No unauthorized access. Test with each role type (admin, analyst, viewer) against every endpoint. Document the complete permission matrix. |

### Documentation

| #     | Improvement             | Priority | Detail                                                                                                                                                                         |
| ----- | ----------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 95.20 | **User documentation**  | HIGH     | Comprehensive user docs: getting started guide, feature-by-feature guides, video tutorials, FAQs, troubleshooting. Keep docs updated with each release.                        |
| 95.21 | **API documentation**   | HIGH     | Complete API reference: every endpoint documented with request/response schemas, example payloads, error codes, authentication requirements. Auto-generated from OpenAPI spec. |
| 95.22 | **Admin documentation** | HIGH     | Administration guide: deployment, configuration, backup/restore, scaling, monitoring, troubleshooting, security hardening.                                                     |

### Testing

| #     | Improvement                   | Priority | Detail                                                                                                                                                                    |
| ----- | ----------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 95.23 | **Unit test coverage target** | HIGH     | Set and enforce minimum unit test coverage: 80% for server routes, 60% for frontend components. Track coverage trends. Block PRs that reduce coverage.                    |
| 95.24 | **E2E test suite**            | HIGH     | Comprehensive E2E test suite covering: user registration → onboarding → first connector → first alert → triage → incident → resolution. Run on every PR.                  |
| 95.25 | **Load testing**              | HIGH     | Regular load testing: verify the platform handles expected load (1000 concurrent users, 10K events/second ingestion, 100 simultaneous queries). Document capacity limits. |
| 95.26 | **Chaos testing**             | MEDIUM   | Test platform resilience: database failover, service restart, network partition, disk full, memory pressure. Verify graceful degradation.                                 |

---

## Summary Statistics

| Category                        | Total Items | Critical | High    | Medium  | Low    |
| ------------------------------- | ----------- | -------- | ------- | ------- | ------ |
| Dashboard                       | 16          | 0        | 8       | 6       | 2      |
| Alerts                          | 19          | 1        | 12      | 5       | 1      |
| Incidents                       | 14          | 0        | 8       | 4       | 2      |
| Watch & Recon (4-10)            | 53          | 8        | 28      | 14      | 3      |
| Investigate (11-19)             | 47          | 3        | 29      | 11      | 4      |
| Respond (20-24)                 | 32          | 1        | 19      | 10      | 2      |
| Posture (25-29)                 | 34          | 5        | 19      | 7       | 3      |
| AI Analyst (30-36)              | 40          | 2        | 25      | 11      | 2      |
| Data & Integrations (37-44)     | 48          | 2        | 28      | 16      | 2      |
| Standalone Security (45-68)     | 157         | 11       | 98      | 40      | 8      |
| Governance (78-85)              | 48          | 2        | 31      | 12      | 3      |
| Admin & Settings (86-93)        | 41          | 1        | 24      | 12      | 4      |
| Landing & Cross-Cutting (94-95) | 34          | 1        | 18      | 11      | 4      |
| **TOTAL**                       | **583**     | **37**   | **347** | **159** | **40** |

---

## Priority Legend

- **CRITICAL** — Must fix before production. Functional gaps that make the feature unusable or insecure.
- **HIGH** — Should fix for production readiness. Missing polish that significantly impacts user experience or completeness.
- **MEDIUM** — Enhances quality. Improvements that make the feature more polished and professional.
- **LOW** — Nice to have. Refinements that add delight but don't block production use.

---

_This document serves as the definitive roadmap for horizontal development. Each item should be addressed in sidebar order, working through the platform feature-by-feature to achieve production-perfect quality across all domains._
