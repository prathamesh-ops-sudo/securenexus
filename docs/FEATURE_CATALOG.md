# SecureNexus — Comprehensive Feature Catalog

**Version:** 1.0  
**Last Updated:** March 2026  
**Source:** SecureNexus platform codebase (`client/src/pages/`, `server/routes/`)

This document catalogs every feature, capability, and component across all security domains implemented in the SecureNexus platform. Each feature is documented with its functional description, technical mechanism, applicable platforms/environments, integration points, configuration options, outputs, and related features.

---

## Table of Contents

1. [Security Operations Center (SOC) Dashboard](#1-security-operations-center-soc-dashboard)
2. [Alert Management](#2-alert-management)
3. [Incident Management](#3-incident-management)
4. [AI Engine & Analyst](#4-ai-engine--analyst)
5. [Autonomous SOC](#5-autonomous-soc)
6. [SOC Copilot](#6-soc-copilot)
7. [Threat Intelligence](#7-threat-intelligence)
8. [Threat Hunting Workbench](#8-threat-hunting-workbench)
9. [Detection Rules](#9-detection-rules)
10. [AI-Native Detection Rule Generation](#10-ai-native-detection-rule-generation)
11. [Native Sensors](#11-native-sensors)
12. [Native Vulnerability Scanner](#12-native-vulnerability-scanner)
13. [UEBA (User & Entity Behavior Analytics)](#13-ueba-user--entity-behavior-analytics)
14. [Playbooks & Automation](#14-playbooks--automation)
15. [War Room](#15-war-room)
16. [Cloud Security Posture Management (CSPM)](#16-cloud-security-posture-management-cspm)
17. [Mobile & Remote Worker Security](#17-mobile--remote-worker-security)
18. [Identity Threat Detection & PAM](#18-identity-threat-detection--pam)
19. [Ransomware Defense Suite](#19-ransomware-defense-suite)
20. [Supply Chain Security](#20-supply-chain-security)
21. [Deception Technology](#21-deception-technology)
22. [OT/ICS Security](#22-otics-security)
23. [Email Security](#23-email-security)
24. [DNS Security](#24-dns-security)
25. [Browser Defense](#25-browser-defense)
26. [API Security](#26-api-security)
27. [Developer Security (Shift-Left)](#27-developer-security-shift-left)
28. [Dark Web Monitoring](#28-dark-web-monitoring)
29. [Community Threat Intelligence Network](#29-community-threat-intelligence-network)
30. [Security Chaos Engineering](#30-security-chaos-engineering)
31. [Privacy Engineering (DSPM++)](#31-privacy-engineering-dspm)
32. [Data Residency & Sovereignty](#32-data-residency--sovereignty)
33. [Security Data Lake](#33-security-data-lake)
34. [Third-Party Risk Management (TPRM)](#34-third-party-risk-management-tprm)
35. [Physical Security Convergence](#35-physical-security-convergence)
36. [Phishing Simulation & Security Awareness](#36-phishing-simulation--security-awareness)
37. [Quantum Readiness Assessment](#37-quantum-readiness-assessment)
38. [Security Posture Score & Trust Center](#38-security-posture-score--trust-center)
39. [Compliance & Governance](#39-compliance--governance)
40. [Advanced Reporting Engine](#40-advanced-reporting-engine)
41. [Executive Risk Dashboard](#41-executive-risk-dashboard)
42. [Security Metrics Intelligence](#42-security-metrics-intelligence)
43. [MSSP White-Label & Partner Portal](#43-mssp-white-label--partner-portal)
44. [Connectors & Integrations](#44-connectors--integrations)
45. [Data Ingestion](#45-data-ingestion)
46. [Entity Graph & Correlation](#46-entity-graph--correlation)
47. [Autonomous Response](#47-autonomous-response)
48. [Agent Response Actions](#48-agent-response-actions)
49. [AI Prompt Registry](#49-ai-prompt-registry)
50. [AI Model Health & Inference](#50-ai-model-health--inference)
51. [AI Budget Controls](#51-ai-budget-controls)
52. [RAG Knowledge Layer](#52-rag-knowledge-layer)
53. [Active Learning Feedback Loop](#53-active-learning-feedback-loop)
54. [Onboarding & Wizard](#54-onboarding--wizard)
55. [Billing & Subscription](#55-billing--subscription)
56. [Team Management & RBAC](#56-team-management--rbac)
57. [SSO / SAML Integration](#57-sso--saml-integration)
58. [Multi-Tenant Isolation](#58-multi-tenant-isolation)
59. [Operations & Observability](#59-operations--observability)
60. [Cross-Cutting Capabilities](#60-cross-cutting-capabilities)
61. [Platform Hardening & Production Readiness](#61-platform-hardening--production-readiness)

---

## 1. Security Operations Center (SOC) Dashboard

**Source:** `client/src/pages/dashboard.tsx` (1585 lines), `server/routes/dashboard.ts`

### 1.1 Security Score Widget

- **Feature Name:** Security Score
- **What it does:** Calculates and displays a real-time composite security health score (0–100) based on weighted inputs from alert severity counts, connector health, and ingestion freshness.
- **How it works:** Aggregates open alert counts by severity (critical, high, medium, low), connector health ratios, and recent ingestion volume. Each factor is weighted and combined into a single numeric score. The score updates on every dashboard load via the `/api/dashboard/stats` endpoint.
- **Where it applies:** Main SOC dashboard, visible to all authenticated users.
- **Integration points:** Alert count data, connector health status, ingestion rate metrics.
- **Configuration options:** Dashboard preset selection (SOC Analyst, Enterprise, Cloud-first) changes which widgets are displayed.
- **Output or results:** Numeric score (0–100) rendered in a circular gauge with color coding (green > 80, yellow 50–80, red < 50). Tooltip shows breakdown by factor.
- **Related features:** Alert Management, Connector Health, Ingestion Rate.

### 1.2 Severity Distribution Chart

- **Feature Name:** Severity Distribution (Pie Chart)
- **What it does:** Visualizes the distribution of open alerts by severity level (Critical, High, Medium, Low, Informational) as an interactive pie chart.
- **How it works:** Queries `/api/dashboard/stats` which aggregates alert counts grouped by severity from the alerts table. Renders using Recharts PieChart component with custom color mapping per severity.
- **Where it applies:** SOC Dashboard widget grid.
- **Integration points:** Alerts database, dashboard stats API.
- **Configuration options:** Can be toggled on/off via widget customization panel. Position is drag-adjustable within the grid.
- **Output or results:** Interactive pie chart with percentage labels and click-to-filter functionality.
- **Related features:** Alert Management, Alert Trend.

### 1.3 Alerts by Source (Bar Chart)

- **Feature Name:** Alerts by Source
- **What it does:** Displays a horizontal bar chart showing alert volume grouped by data source/connector (e.g., CrowdStrike, Sentinel, Splunk).
- **How it works:** Fetches source-aggregated alert counts from the dashboard stats endpoint. Renders via Recharts BarChart with source names on the Y-axis and counts on X-axis.
- **Where it applies:** SOC Dashboard.
- **Integration points:** Connectors, alert ingestion pipeline.
- **Configuration options:** Widget visibility toggle; dashboard preset selection.
- **Output or results:** Horizontal bar chart with source labels, sortable by count.
- **Related features:** Connectors, Data Ingestion, Alert Management.

### 1.4 Alert Trend (7 Days)

- **Feature Name:** Alert Trend
- **What it does:** Shows a 7-day time-series line chart of alert creation volume, enabling SOC analysts to identify spikes or anomalies in alert flow.
- **How it works:** Queries daily alert counts for the past 7 days from the dashboard stats API. Renders as a Recharts AreaChart with date on X-axis and count on Y-axis.
- **Where it applies:** SOC Dashboard.
- **Integration points:** Alerts table (time-series aggregation).
- **Configuration options:** Widget toggle on/off.
- **Output or results:** Area chart showing daily alert volume with trend line.
- **Related features:** Security Score, Alert Management.

### 1.5 Top MITRE ATT&CK Tactics

- **Feature Name:** MITRE ATT&CK Tactics Distribution
- **What it does:** Displays alert counts mapped to MITRE ATT&CK tactic categories, helping analysts understand which attack phases are most prevalent.
- **How it works:** Aggregates alerts by their mapped MITRE tactic field. Uses pre-defined tactic color mapping (TACTIC_COLORS constant). Renders as a horizontal bar chart.
- **Where it applies:** SOC Dashboard.
- **Integration points:** Alert enrichment pipeline (MITRE mapping), detection rules.
- **Configuration options:** Widget visibility toggle.
- **Output or results:** Color-coded bar chart with tactic names (Initial Access, Execution, Persistence, etc.) and alert counts.
- **Related features:** Detection Rules, Threat Hunting, Alert Management.

### 1.6 Threat Categories Widget

- **Feature Name:** Threat Categories
- **What it does:** Shows a breakdown of alerts by threat category (Malware, Phishing, Brute Force, Insider Threat, etc.).
- **How it works:** Groups alerts by their `category` field and renders as a bar chart or table depending on the active dashboard preset.
- **Where it applies:** SOC Dashboard.
- **Integration points:** Alert classification pipeline.
- **Configuration options:** Widget toggle; category filter.
- **Output or results:** Bar chart or table with category labels and counts.
- **Related features:** Alert Management, AI Triage.

### 1.7 Connector Health Widget

- **Feature Name:** Connector Health
- **What it does:** Displays the operational status of all configured data connectors with health indicators (Healthy, Degraded, Error, Disconnected).
- **How it works:** Polls connector health status from `/api/connectors` and displays each connector's sync status, last sync timestamp, and error count.
- **Where it applies:** SOC Dashboard.
- **Integration points:** Connector management system, dead letter queue.
- **Configuration options:** Widget toggle.
- **Output or results:** Table/grid of connectors with colored health badges and last sync times.
- **Related features:** Connectors, Data Ingestion, Dead Letter Queue.

### 1.8 Ingestion Rate Widget

- **Feature Name:** Ingestion Rate
- **What it does:** Shows real-time and historical event ingestion rates (events per second/minute) to monitor pipeline throughput.
- **How it works:** Fetches ingestion statistics from `/api/ingestion/stats` including total ingested, alerts created, deduplicated, and failed counts. Renders as a time-series chart.
- **Where it applies:** SOC Dashboard.
- **Integration points:** Ingestion pipeline, API key management.
- **Configuration options:** Widget toggle; time window selection.
- **Output or results:** Line chart of ingestion rates plus numeric KPI cards (Total Ingested, Alerts Created, Deduplicated, Failed).
- **Related features:** Data Ingestion, Connectors.

### 1.9 What Changed (Last 24h)

- **Feature Name:** What Changed (Last 24h)
- **What it does:** Summarizes all significant security posture changes in the past 24 hours — new incidents, resolved alerts, configuration changes, new connectors.
- **How it works:** Queries audit log and alert/incident tables for entries created or updated in the last 24 hours. Groups changes by type and presents as a timeline.
- **Where it applies:** SOC Dashboard.
- **Integration points:** Audit log, incidents, alerts, connectors.
- **Configuration options:** Widget toggle.
- **Output or results:** Timeline list of recent changes with timestamps and severity indicators.
- **Related features:** Audit Log, Incident Management, Alert Management.

### 1.10 Dashboard Customization

- **Feature Name:** Widget Customization Panel
- **What it does:** Allows users to personalize their dashboard by selecting which widgets to display, reordering them, and choosing from preset layouts.
- **How it works:** Widget configuration is persisted to `localStorage` per user. Three built-in presets (SOC Analyst, Enterprise, Cloud-first) provide pre-configured widget sets. Users can toggle individual widgets on/off via a settings panel.
- **Where it applies:** SOC Dashboard.
- **Integration points:** All dashboard widgets.
- **Configuration options:** Widget visibility toggles, preset selection (SOC Analyst, Enterprise, Cloud-first), custom arrangement.
- **Output or results:** Personalized dashboard layout that persists across sessions.
- **Related features:** All dashboard widgets.

### 1.11 Dashboard Presets

- **Feature Name:** Dashboard Presets
- **What it does:** Provides pre-built dashboard configurations optimized for different user personas — SOC Analyst (alert-focused), Enterprise (compliance-focused), Cloud-first (cloud security-focused).
- **How it works:** Each preset defines a specific set of enabled widgets and their default arrangement. Selecting a preset instantly reconfigures the dashboard layout.
- **Where it applies:** SOC Dashboard.
- **Integration points:** Widget customization system.
- **Configuration options:** Three preset options; custom override per-widget.
- **Output or results:** Instant dashboard reconfiguration.
- **Related features:** Widget Customization Panel.

---

## 2. Alert Management

**Source:** `client/src/pages/alerts.tsx` (2068 lines), `client/src/pages/alert-detail.tsx`, `server/routes/alerts.ts`

### 2.1 Alert List & Queue

- **Feature Name:** Alert Queue
- **What it does:** Displays all security alerts in a paginated, filterable list with real-time counts by severity, source, status, and category.
- **How it works:** Queries `/api/alerts` with pagination, sorting, and filter parameters. Supports server-side filtering by severity, status (open, acknowledged, resolved, suppressed), source, category, and date range. Uses React Query for cache management and background refetching.
- **Where it applies:** Alert Management page, accessible to all SOC roles.
- **Integration points:** Connectors (alert ingestion), AI Engine (triage/enrichment), Incidents (escalation), Detection Rules (alert generation).
- **Configuration options:** Column visibility, sort order, filter presets, page size.
- **Output or results:** Sortable table with alert title, severity badge, source, timestamp, status, assigned analyst, and action buttons.
- **Related features:** Alert Detail, Incident Escalation, AI Triage.

### 2.2 Alert Detail View

- **Feature Name:** Alert Detail
- **What it does:** Provides a comprehensive single-alert view with raw payload, entity extraction, MITRE mapping, related alerts, AI analysis, timeline, and response actions.
- **How it works:** Fetches full alert data from `/api/alerts/:id` including raw JSON payload, extracted entities (IPs, domains, hashes, users), MITRE ATT&CK tactic/technique mapping, and related alerts (by shared entities). Supports inline status changes, severity adjustments, and analyst assignment.
- **Where it applies:** Alert detail page (navigated from alert queue).
- **Integration points:** Entity Graph, AI Engine (narrative generation), MITRE ATT&CK framework, Incident Management (escalation).
- **Configuration options:** None (full detail always shown).
- **Output or results:** Multi-section detail page with raw JSON viewer, entity cards, MITRE mapping, related alerts list, AI-generated narrative, and action toolbar.
- **Related features:** Entity Graph, AI Engine, Incident Escalation.

### 2.3 Alert Triage (Bulk Actions)

- **Feature Name:** Bulk Alert Triage
- **What it does:** Enables SOC analysts to select multiple alerts and perform bulk actions: acknowledge, resolve, suppress, assign, change severity, or escalate to incident.
- **How it works:** Multi-select checkboxes in the alert queue trigger bulk action endpoints (`/api/alerts/bulk-update`). All bulk operations are atomic and audit-logged.
- **Where it applies:** Alert queue page.
- **Integration points:** Audit Log, Incident Management.
- **Configuration options:** Bulk action permissions controlled by RBAC role.
- **Output or results:** Toast notification confirming bulk action success with count of affected alerts.
- **Related features:** Alert Queue, RBAC, Audit Log.

### 2.4 Alert Suppression Rules

- **Feature Name:** Alert Suppression Rules
- **What it does:** Allows creation of rules that automatically suppress future alerts matching specific criteria (source, category, severity, regex patterns) to reduce noise.
- **How it works:** Suppression rules are stored in the `suppression_rules` table. On alert ingestion, each incoming alert is evaluated against active suppression rules. Matching alerts are auto-set to suppressed status. Rules support expiration dates and match counters.
- **Where it applies:** Alert Management, Compliance (suppression rules management).
- **Integration points:** Alert ingestion pipeline, Compliance module.
- **Configuration options:** Rule name, match criteria (source, category, severity, title pattern), expiration date, enabled/disabled toggle.
- **Output or results:** CRUD interface for suppression rules with match count statistics.
- **Related features:** Alert Management, Data Ingestion, AI Active Learning.

### 2.5 Alert Tag Management

- **Feature Name:** Alert Tagging
- **What it does:** Allows analysts to add, remove, and filter alerts by custom tags for organizational classification.
- **How it works:** Tags are stored as many-to-many relationships via `/api/alerts/:id/tags`. Global tag management via `/api/tags`.
- **Where it applies:** Alert detail page, alert queue (filter by tag).
- **Integration points:** Incident tags (shared tag taxonomy).
- **Configuration options:** Custom tag creation, color assignment.
- **Output or results:** Tag badges on alert cards, tag-based filtering in queue.
- **Related features:** Incident Tags, Entity Graph.

### 2.6 Alert Entity Extraction

- **Feature Name:** Entity Extraction
- **What it does:** Automatically extracts security-relevant entities (IP addresses, domains, file hashes, email addresses, usernames, URLs) from alert payloads.
- **How it works:** Parses alert JSON payloads using regex patterns and heuristic extraction. Extracted entities are stored in the entity graph and linked to alerts via `/api/alerts/:id/entities`.
- **Where it applies:** Alert detail page, Entity Graph.
- **Integration points:** Entity Graph, Threat Intelligence (IOC matching), Related Alerts correlation.
- **Configuration options:** None (automatic extraction on ingestion).
- **Output or results:** Entity cards displayed in alert detail showing type, value, and linked occurrences.
- **Related features:** Entity Graph, Threat Intelligence, Related Alerts.

### 2.7 Related Alerts Correlation

- **Feature Name:** Related Alerts
- **What it does:** Identifies and displays alerts that share common entities (same IP, domain, hash, or user) with the current alert.
- **How it works:** Queries `/api/alerts/:id/related` which performs entity-based correlation, ranking by entity overlap count.
- **Where it applies:** Alert detail page.
- **Integration points:** Entity Graph, AI Correlation Engine.
- **Configuration options:** None.
- **Output or results:** List of related alerts with shared entity indicators and severity badges.
- **Related features:** Entity Graph, AI Correlation, Incident Creation.

### 2.8 Alert Confidence Scoring

- **Feature Name:** Confidence Score Adjustment
- **What it does:** Allows analysts to manually adjust the confidence score (0-100) of an alert, feeding back to AI triage accuracy.
- **How it works:** PATCH request to `/api/alerts/:id/confidence` updates the confidence field. Changes are audit-logged and fed to the AI active learning pipeline.
- **Where it applies:** Alert detail page.
- **Integration points:** AI Active Learning, AI Triage.
- **Configuration options:** Numeric slider (0-100).
- **Output or results:** Updated confidence badge on alert card.
- **Related features:** AI Active Learning, AI Triage.

### 2.9 Alert Archive

- **Feature Name:** Alert Archival
- **What it does:** Moves resolved/old alerts to an archive table for long-term retention without cluttering the active alert queue.
- **How it works:** Endpoints at `/api/alerts/archive` support archiving (POST), viewing (GET), restoring (POST /restore), and permanent deletion (DELETE).
- **Where it applies:** Alert Management.
- **Integration points:** Data Lake (cold storage tiering), Compliance (retention policies).
- **Configuration options:** Archive criteria (age threshold, status), retention period.
- **Output or results:** Separate archive view with restore capability.
- **Related features:** Data Lake, Retention Policies.

---

## 3. Incident Management

**Source:** `client/src/pages/incidents.tsx`, `client/src/pages/incident-detail.tsx` (3967 lines), `server/routes/incidents.ts` (1377 lines)

### 3.1 Incident Queue

- **Feature Name:** Incident Queue
- **What it does:** Displays all security incidents in a filterable queue with tabs for All, Unassigned, Escalated, and Aging incidents. Provides KPI cards for open/critical/MTTD/MTTR metrics.
- **How it works:** Queries `/api/incidents` and `/api/incidents/queues` with filters for status, severity, assignee, and age. Queue tabs use pre-defined filter sets.
- **Where it applies:** Incident Management page.
- **Integration points:** Alert Management (escalation source), Playbooks (automated response), War Room (collaboration).
- **Configuration options:** Queue tab filters, sort order, column visibility.
- **Output or results:** Tabbed incident queue with severity badges, assignee avatars, SLA timers, and bulk action toolbar.
- **Related features:** Alert Escalation, Playbooks, War Room.

### 3.2 Incident Detail Overview

- **Feature Name:** Incident Overview
- **What it does:** Shows comprehensive incident information including title, severity, status, assigned analyst, linked alerts, AI-generated summary, and root cause analysis.
- **How it works:** Fetches from `/api/incidents/:id` with related alerts via `/api/incidents/:id/alerts`. AI summary generated on-demand via `/api/incidents/:id/root-cause-summary` using Claude AI.
- **Where it applies:** Incident detail page, Overview tab.
- **Integration points:** AI Engine (summary generation), Alert Management (linked alerts), Entity Graph.
- **Configuration options:** None.
- **Output or results:** Multi-section overview with AI narrative, linked alerts table, entity map, and status timeline.
- **Related features:** AI Engine, Alert Management, Entity Graph.

### 3.3 Incident Evidence Management

- **Feature Name:** Evidence Collection
- **What it does:** Manages digital evidence attached to incidents: file uploads, screenshots, log excerpts, memory dumps, packet captures.
- **How it works:** CRUD operations via `/api/incidents/:incidentId/evidence`. Evidence items include metadata (type, description, hash, collector, timestamp). Supports chain-of-custody tracking.
- **Where it applies:** Incident detail, Evidence tab.
- **Integration points:** Evidence Chain of Custody, File Manager.
- **Configuration options:** Evidence type classification, custody chain requirements.
- **Output or results:** Evidence list with type icons, timestamps, collector info, and download links.
- **Related features:** Evidence Chain of Custody, Forensic Timeline.

### 3.4 Incident Hypotheses

- **Feature Name:** Investigation Hypotheses
- **What it does:** Allows investigators to create, track, and evaluate hypotheses about incident root cause.
- **How it works:** CRUD via `/api/incidents/:incidentId/hypotheses`. Each hypothesis has a status (proposed, investigating, confirmed, rejected), confidence level, and supporting evidence links.
- **Where it applies:** Incident detail, Hypotheses tab.
- **Integration points:** Evidence Management, AI Engine (hypothesis suggestion).
- **Output or results:** Hypothesis cards with status badges, confidence meters, and evidence links.
- **Related features:** Evidence Management, AI Investigation.

### 3.5 Incident Tasks

- **Feature Name:** Investigation Tasks
- **What it does:** Creates and tracks investigation tasks within an incident, assigned to team members with due dates and priorities.
- **How it works:** CRUD via `/api/incidents/:incidentId/tasks`. Tasks support assignment, priority levels, due dates, and status tracking.
- **Where it applies:** Incident detail, Tasks tab.
- **Integration points:** Team Management (assignees), Playbooks (auto-generated tasks).
- **Output or results:** Task list with progress tracking, assignee avatars, and due date indicators.
- **Related features:** Playbooks, Team Management.

### 3.6 Incident Runbooks

- **Feature Name:** Runbook Execution
- **What it does:** Attaches and executes response runbooks (playbooks) directly from the incident detail page, with step-by-step execution tracking.
- **How it works:** Links playbooks to incidents and tracks execution progress per step. Supports manual step completion, automated step execution, and approval gates.
- **Where it applies:** Incident detail, Runbooks tab.
- **Integration points:** Playbooks & Automation, Approval Workflows.
- **Output or results:** Step-by-step runbook tracker with status indicators and execution logs.
- **Related features:** Playbooks & Automation, Approval Workflows.

### 3.7 Incident Audit Chain

- **Feature Name:** Incident Audit Chain
- **What it does:** Provides a complete, tamper-evident audit trail of all actions taken on an incident.
- **How it works:** Every incident modification is logged to the activity table via `/api/incidents/:id/activity`. Each entry includes actor, action type, timestamp, and before/after values.
- **Where it applies:** Incident detail, Audit Chain tab.
- **Integration points:** Audit Log, Compliance.
- **Output or results:** Chronological timeline of all incident actions with actor identification.
- **Related features:** Audit Log, Compliance, Evidence Chain of Custody.

### 3.8 Incident Approvals

- **Feature Name:** Approval Workflows
- **What it does:** Implements multi-level approval gates for critical incident response actions requiring manager sign-off before execution.
- **How it works:** Approval requests are created when playbook steps require authorization. Approvers receive notifications and can approve/reject via the Approvals tab.
- **Where it applies:** Incident detail, Approvals tab.
- **Integration points:** Playbooks, RBAC (approver roles), Notification Channels.
- **Configuration options:** Approval thresholds, required approver roles, timeout periods.
- **Output or results:** Approval request cards with approve/reject buttons, status tracking, and audit trail.
- **Related features:** Playbooks, RBAC, Notifications.

### 3.9 Post-Incident Review (PIR)

- **Feature Name:** Post-Incident Review
- **What it does:** Structured post-mortem framework for completed incidents capturing lessons learned, timeline analysis, and improvement recommendations.
- **How it works:** PIR form on the PIR tab after incident resolution. Captures timeline, root cause, impact assessment, response effectiveness, and action items.
- **Where it applies:** Incident detail, PIR tab.
- **Integration points:** Compliance reporting, lessons learned database.
- **Output or results:** Structured PIR document with timeline visualization, findings, and action items.
- **Related features:** Advanced Reporting, Compliance.

### 3.10 Attack Graph Visualization

- **Feature Name:** Attack Graph
- **What it does:** Visualizes the attack chain and relationships between entities, alerts, and techniques involved in an incident as an interactive graph.
- **How it works:** AI-generated attack graphs are persisted to the database and rendered using a force-directed graph layout. Nodes represent entities (IPs, users, hosts) and edges represent observed relationships. Generated via deep investigation AI endpoint.
- **Where it applies:** Incident detail, Attack Graph tab; standalone attack graph page.
- **Integration points:** AI Engine (deep investigation), Entity Graph, MITRE ATT&CK mapping.
- **Output or results:** Interactive force-directed graph with clickable nodes, relationship labels, and MITRE technique annotations.
- **Related features:** AI Deep Investigation, Entity Graph, MITRE ATT&CK.

### 3.11 Incident Push & Ticket Sync

- **Feature Name:** Incident Push / Ticket Sync
- **What it does:** Pushes incident data to external ticketing systems (Jira, ServiceNow, PagerDuty) and maintains bidirectional sync.
- **How it works:** POST to `/api/incidents/:id/push` serializes incident data to configured integrations. Ticket sync via `/api/ticket-sync/:id` keeps status synchronized.
- **Where it applies:** Incident detail page, integrations.
- **Integration points:** Integrations (Jira, ServiceNow, PagerDuty, Slack, Teams), Notification Channels.
- **Output or results:** External ticket reference ID and link displayed on incident.
- **Related features:** Integrations, Notification Channels.

### 3.12 Incident Comments

- **Feature Name:** Incident Comments
- **What it does:** Threaded discussion system for incident collaboration.
- **How it works:** CRUD via `/api/incidents/:id/comments`. Deletion requires ownership or admin role.
- **Where it applies:** Incident detail page.
- **Integration points:** War Room (extended collaboration), Team Management.
- **Output or results:** Threaded comment stream with author avatars and timestamps.
- **Related features:** War Room, Team Management.

---

## 4. AI Engine & Analyst

**Source:** `client/src/pages/ai-engine.tsx`, `server/routes/ai.ts` (1832 lines)

### 4.1 AI Engine Health Monitor

- **Feature Name:** AI Engine Health
- **What it does:** Monitors the health and availability of configured AI models (Claude Sonnet 4, Opus 4) with real-time status, latency metrics, and circuit breaker state.
- **How it works:** Polls `/api/ai/health` which checks model API connectivity, response latency, and error rates. Displays circuit breaker status (closed/open/half-open) and auto-recovery indicators.
- **Where it applies:** AI Engine page, SOC Dashboard.
- **Integration points:** Anthropic API (Claude models), AI Budget Controls.
- **Configuration options:** Model selection (Sonnet 4, Opus 4), API key configuration, fallback model settings.
- **Output or results:** Health status cards with latency metrics, error rates, and circuit breaker state indicators.
- **Related features:** AI Budget Controls, AI Model Health.

### 4.2 AI Alert Correlation

- **Feature Name:** AI Alert Correlation Engine
- **What it does:** Uses Claude AI to analyze groups of alerts and identify patterns, clusters, and potential incidents by correlating entities, timing, and tactics.
- **How it works:** POST to `/api/ai/correlate` sends selected alerts to Claude for analysis. The AI identifies shared entities, temporal proximity, tactic chains, and suggests incident groupings. Results include correlation confidence scores and group names.
- **Where it applies:** AI Engine page, Alert Management.
- **Integration points:** Alert Management, Entity Graph, Incident Creation.
- **Configuration options:** Alert selection mode (all open alerts or selected subset), correlation threshold.
- **Output or results:** Correlation groups with AI-generated group names, member alerts, shared entities, confidence scores, and one-click incident creation.
- **Related features:** Alert Management, Incident Creation, Entity Graph.

### 4.3 AI Alert Triage

- **Feature Name:** AI-Powered Alert Triage
- **What it does:** Automatically triages incoming alerts using AI to assess severity accuracy, false positive probability, and recommended actions.
- **How it works:** Sends alert context to Claude for analysis. AI returns structured triage output: recommended severity, confidence score, false positive probability, suggested response actions, and explainability narrative.
- **Where it applies:** AI Engine page, Alert Detail.
- **Integration points:** Alert Management, Active Learning Feedback.
- **Configuration options:** Auto-triage toggle, confidence threshold for auto-actions.
- **Output or results:** Triage cards with AI recommendations, confidence scores, and explainability sections.
- **Related features:** Active Learning, Alert Management.

### 4.4 AI Explainability

- **Feature Name:** AI Explainability Panel
- **What it does:** Provides transparent explanations of AI decision-making for each triage or correlation action, showing the reasoning chain and evidence used.
- **How it works:** Each AI action includes a structured explainability block with: reasoning steps, evidence cited, confidence factors, alternative interpretations, and limitations acknowledged.
- **Where it applies:** AI Engine page (per-action explainability), Alert Detail.
- **Integration points:** AI Triage, AI Correlation.
- **Output or results:** Expandable explainability panels with step-by-step reasoning, cited evidence, and confidence breakdown.
- **Related features:** AI Triage, AI Correlation, Active Learning.

### 4.5 AI Setup Status & First-Run Health Checks

- **Feature Name:** AI Setup Status
- **What it does:** Detects whether the AI engine is properly configured (API keys set, models accessible) and guides first-time setup.
- **How it works:** GET `/api/ai/setup-status` checks for valid Anthropic API key, model accessibility, and returns setup completion state. Displays setup wizard if not configured.
- **Where it applies:** AI Engine page (first visit).
- **Integration points:** Settings (API key management).
- **Configuration options:** API key input, model selection, budget limits.
- **Output or results:** Setup wizard or health dashboard depending on configuration state.
- **Related features:** AI Budget Controls, Settings.

### 4.6 AI Circuit Breaker Alerts

- **Feature Name:** Circuit Breaker Alerts
- **What it does:** Monitors AI model error rates and automatically trips circuit breakers when error thresholds are exceeded, preventing cascade failures.
- **How it works:** GET `/api/ai/circuit-alerts` returns active circuit breaker alerts. Breakers trip on sustained high error rates or latency. PATCH endpoint allows manual reset.
- **Where it applies:** AI Engine page, Operations dashboard.
- **Integration points:** AI Health Monitor, Notification Channels.
- **Output or results:** Alert cards showing tripped breakers with error details and manual reset buttons.
- **Related features:** AI Health Monitor, Operations.

### 4.7 AI-Powered Root Cause Summary

- **Feature Name:** Root Cause Summary
- **What it does:** Generates AI-powered root cause analysis narratives for incidents, synthesizing all linked alerts, entities, and timeline data.
- **How it works:** GET `/api/incidents/:id/root-cause-summary` sends incident context (alerts, entities, timeline) to Claude, which generates a structured narrative covering attack vector, impact scope, affected systems, and recommended remediation.
- **Where it applies:** Incident Detail page.
- **Integration points:** Incident Management, Entity Graph, Alert Management.
- **Output or results:** AI-generated narrative document with sections for summary, attack vector, impact, timeline, and recommendations.
- **Related features:** Incident Management, AI Deep Investigation.

### 4.8 AI Deep Investigation (SSE Streaming)

- **Feature Name:** Deep Investigation with Streaming
- **What it does:** Conducts deep AI-powered investigation of incidents with real-time streaming output, generating comprehensive analysis including attack graphs.
- **How it works:** SSE endpoint streams AI analysis in real-time as Claude processes the investigation. Generates attack graph nodes and edges, MITRE technique mappings, and detailed narrative. Results are persisted to the database.
- **Where it applies:** Incident Detail page, AI Engine.
- **Integration points:** Attack Graph persistence, Entity Graph, MITRE ATT&CK.
- **Output or results:** Real-time streaming text output with progressive attack graph construction.
- **Related features:** Attack Graph, SSE Streaming, Incident Management.

### 4.9 AI Playbook Authoring

- **Feature Name:** AI Playbook Proposal
- **What it does:** Uses AI to propose new playbook steps and automation workflows based on incident patterns and response history.
- **How it works:** POST `/api/ai/playbook-authoring/propose` sends incident context to Claude, which generates proposed playbook steps with trigger conditions, actions, and approval requirements.
- **Where it applies:** Playbooks page, Incident Detail.
- **Integration points:** Playbooks & Automation, Incident Management.
- **Output or results:** Proposed playbook structure with steps, conditions, and action definitions ready for review and deployment.
- **Related features:** Playbooks, Incident Management.

### 4.10 Multi-Turn Investigation Chat

- **Feature Name:** Investigation Chat
- **What it does:** Provides a multi-turn conversational interface for SOC analysts to ask follow-up questions about incidents and receive AI-powered responses.
- **How it works:** Maintains conversation history per incident, sending full context with each turn to Claude. Supports follow-up questions, clarifications, and deeper analysis requests.
- **Where it applies:** Incident Detail page.
- **Integration points:** AI Engine, Incident Management.
- **Output or results:** Chat-style interface with analyst questions and AI responses, preserving investigation context.
- **Related features:** AI Deep Investigation, Incident Management.

### 4.11 AI Inference Metrics

- **Feature Name:** Inference Metrics Dashboard
- **What it does:** Tracks AI inference volume, latency, token usage, cost, and error rates across all AI features.
- **How it works:** GET `/api/ai/inference-metrics` aggregates inference logs with per-model and per-feature breakdowns. Tracks tokens consumed, response times, and costs.
- **Where it applies:** AI Model Health page, AI Engine page.
- **Integration points:** AI Budget Controls, Operations.
- **Output or results:** Metrics dashboard with time-series charts for inference volume, latency, cost, and error rates.
- **Related features:** AI Budget Controls, AI Model Health.

### 4.12 AI Feedback System

- **Feature Name:** AI Feedback Collection
- **What it does:** Collects analyst feedback (thumbs up/down, corrections, false positive flags) on AI outputs to improve model performance over time.
- **How it works:** POST `/api/ai/feedback` stores structured feedback linked to the AI action (triage, correlation, narrative). Feedback includes rating, correction text, and false positive indicators.
- **Where it applies:** AI Engine page, Alert Detail, Incident Detail (wherever AI outputs are displayed).
- **Integration points:** Active Learning pipeline, AI Triage accuracy improvement.
- **Output or results:** Feedback submission form with rating, correction field, and confirmation.
- **Related features:** Active Learning, AI Triage.

---

## 5. Autonomous SOC

**Source:** `client/src/pages/autonomous-soc.tsx` (1136 lines), `server/routes/autonomous-soc.ts`

### 5.1 Autonomous SOC Overview

- **Feature Name:** Autonomous SOC Dashboard
- **What it does:** Displays an overview of the AI-native 3-tier analyst system with tier distribution, decision outcomes, 30-day trends, and recent autonomous decisions.
- **How it works:** Queries autonomous SOC stats endpoints for decision metrics. Tier 1 (fully autonomous) handles low-risk alerts automatically. Tier 2 (semi-autonomous) provides recommendations requiring analyst approval. Tier 3 (assisted) augments senior analyst investigations.
- **Where it applies:** Autonomous SOC page, Overview tab.
- **Integration points:** AI Engine, Alert Management, Incident Management.
- **Output or results:** Dashboard with tier distribution pie chart, decision outcomes bar chart, 30-day trend line, and recent decisions table.
- **Related features:** AI Engine, Alert Triage.

### 5.2 Autonomous Decisions Log

- **Feature Name:** Decisions Log
- **What it does:** Records all autonomous decisions made by the AI system with full transparency: what action was taken, why, which tier handled it, and the outcome.
- **How it works:** Each AI decision is logged with decision type, tier level, confidence score, action taken, reasoning, and outcome status. Filterable by tier, decision type, and date range.
- **Where it applies:** Autonomous SOC page, Decisions tab.
- **Integration points:** AI Engine, Audit Log.
- **Output or results:** Filterable decision log with expandable reasoning sections.
- **Related features:** AI Explainability, Audit Log.

### 5.3 AI Triage Queue

- **Feature Name:** Triage Queue
- **What it does:** Displays alerts that the AI has triaged but requires human review, with AI recommendations and confidence scores.
- **How it works:** AI-triaged alerts with confidence below the auto-action threshold are queued for human review. Each entry shows AI recommendation, confidence, reasoning, and accept/reject buttons.
- **Where it applies:** Autonomous SOC page, Triage tab.
- **Integration points:** AI Triage, Alert Management.
- **Output or results:** Queue of pending triage decisions with AI recommendations and one-click accept/override.
- **Related features:** AI Triage, Alert Management.

### 5.4 Audit Log

- **Feature Name:** Autonomous SOC Audit Log
- **What it does:** Complete audit trail of all autonomous actions, human overrides, and system decisions for compliance and accountability.
- **How it works:** Every autonomous action is logged with actor (AI or human), action, timestamp, rationale, and outcome.
- **Where it applies:** Autonomous SOC page, Audit tab.
- **Output or results:** Searchable audit log with filters for action type, actor, and date range.
- **Related features:** Compliance, Audit Log.

### 5.5 Human Override Controls

- **Feature Name:** Override Controls
- **What it does:** Allows SOC managers to override autonomous decisions, adjust tier thresholds, and temporarily disable autonomous actions for specific alert categories.
- **How it works:** Override interface shows current tier thresholds and allows adjustment. Overrides are logged to the audit trail with justification requirements.
- **Where it applies:** Autonomous SOC page, Override tab.
- **Configuration options:** Tier confidence thresholds, category exclusions, global enable/disable.
- **Output or results:** Override configuration panel with threshold sliders and guidelines reference.
- **Related features:** AI Triage, RBAC.

---

## 6. SOC Copilot

**Source:** `client/src/pages/agentic-soc.tsx`, `client/src/pages/ai-soc-analyst.tsx`, `server/routes/soc-copilot.ts`

### 6.1 SOC Copilot Chat Interface

- **Feature Name:** SOC Copilot
- **What it does:** Provides a conversational AI assistant that SOC analysts can query in natural language about alerts, incidents, threat intelligence, and recommended actions.
- **How it works:** Natural language queries are processed by Claude AI with full context of the organization's security data. The copilot can look up alerts, correlate entities, suggest playbooks, and draft incident summaries on demand.
- **Where it applies:** SOC Copilot page, available from any page via sidebar shortcut.
- **Integration points:** AI Engine, Alert Management, Incident Management, Threat Intelligence, Playbooks.
- **Output or results:** Chat-style interface with AI responses, inline data cards, and action suggestions.
- **Related features:** AI Engine, Multi-Turn Investigation.

---

## 7. Threat Intelligence

**Source:** `client/src/pages/threat-intel.tsx` (2145 lines), `server/routes/threat-intel.ts` (1115+ lines)

### 7.1 IOC Management

- **Feature Name:** Indicators of Compromise (IOC) Management
- **What it does:** Manages a database of threat indicators (IP addresses, domains, file hashes, URLs, email addresses) with severity ratings, tags, expiration dates, and source attribution.
- **How it works:** CRUD via `/api/threat-intel/iocs` with support for bulk import/export. Each IOC has type, value, severity, confidence, tags, source, first/last seen dates, and expiration. IOCs are automatically matched against incoming alerts.
- **Where it applies:** Threat Intelligence page, Alert enrichment pipeline.
- **Integration points:** Alert Management (IOC matching), Community Intel (shared IOCs), Dark Web Monitoring.
- **Configuration options:** IOC types, severity levels, expiration policies, auto-enrichment toggles.
- **Output or results:** Searchable IOC database with severity badges, source attribution, and match count indicators.
- **Related features:** Community Intel, Alert Enrichment, Dark Web Monitoring.

### 7.2 IOC Matching Engine

- **Feature Name:** IOC Alert Matching
- **What it does:** Automatically matches incoming alerts against the IOC database and flags matches with threat intelligence context.
- **How it works:** On alert ingestion, extracted entities are compared against active IOCs. Matches create IOC match records linking alerts to threat intelligence. Match results are displayed on alert detail pages.
- **Where it applies:** Alert ingestion pipeline, Alert Detail.
- **Integration points:** Alert Management, Entity Extraction.
- **Output or results:** IOC match indicators on alert cards, linked threat intelligence context.
- **Related features:** Alert Management, Entity Extraction.

### 7.3 Threat Intelligence Feeds

- **Feature Name:** TI Feed Subscriptions
- **What it does:** Manages subscriptions to external threat intelligence feeds, automatically ingesting IOCs from commercial and open-source feeds.
- **How it works:** Feed configurations define source URL, format (STIX/TAXII, CSV, JSON), polling interval, and mapping rules. Feed ingestion runs on schedule, deduplicating and enriching incoming IOCs.
- **Where it applies:** Threat Intelligence page.
- **Integration points:** IOC Management, Community Intel feeds.
- **Configuration options:** Feed URL, format, polling interval, severity mapping, auto-expire settings.
- **Output or results:** Feed status cards with last sync time, IOC count, and error indicators.
- **Related features:** IOC Management, Community Intel.

### 7.4 Threat Actor Profiles

- **Feature Name:** Threat Actor Tracking
- **What it does:** Maintains profiles of known threat actors and APT groups with associated TTPs, IOCs, target sectors, and activity timelines.
- **How it works:** CRUD via threat actor endpoints. Each profile includes name, aliases, motivation, target sectors, associated MITRE techniques, known IOCs, and activity timeline.
- **Where it applies:** Threat Intelligence page.
- **Integration points:** MITRE ATT&CK mapping, IOC Management.
- **Output or results:** Threat actor profile cards with TTP mapping, IOC links, and activity timelines.
- **Related features:** MITRE ATT&CK, IOC Management.

### 7.5 Campaign Tracking

- **Feature Name:** Threat Campaign Tracking
- **What it does:** Tracks and visualizes active threat campaigns linking multiple IOCs, threat actors, and observed TTPs into campaign narratives.
- **How it works:** Campaigns are created manually or auto-detected by correlating IOC clusters and temporal patterns. Each campaign links threat actors, IOCs, targeted sectors, and observed techniques.
- **Where it applies:** Threat Intelligence page, Campaign Viewer.
- **Integration points:** IOC Management, Threat Actors, MITRE ATT&CK.
- **Output or results:** Campaign timeline visualization with linked IOCs, actors, and technique mapping.
- **Related features:** IOC Management, Threat Actors, Attack Graph.

### 7.6 MITRE ATT&CK Integration

- **Feature Name:** MITRE ATT&CK Framework Mapping
- **What it does:** Maps all threat intelligence, detection rules, and alerts to the MITRE ATT&CK framework for standardized threat classification.
- **How it works:** Maintains a local copy of MITRE ATT&CK tactics and techniques. IOCs, detection rules, and alerts are tagged with relevant technique IDs. Coverage heatmap shows which techniques are covered by detection rules.
- **Where it applies:** Threat Intelligence, Detection Rules, Threat Hunting, Dashboard.
- **Integration points:** Detection Rules, Threat Hunting, Alert Management.
- **Output or results:** MITRE ATT&CK navigator heatmap showing coverage, technique detail cards.
- **Related features:** Detection Rules, Threat Hunting.

### 7.7 Threat Intelligence Reports

- **Feature Name:** TI Report Generation
- **What it does:** Generates formatted threat intelligence reports summarizing IOC trends, campaign activity, and threat landscape changes.
- **How it works:** Aggregates IOC statistics, campaign data, and threat actor activity into structured reports with charts and tables.
- **Where it applies:** Threat Intelligence page.
- **Integration points:** Advanced Reporting, Compliance.
- **Output or results:** Downloadable PDF/HTML threat intelligence reports.
- **Related features:** Advanced Reporting.

---

## 8. Threat Hunting Workbench

**Source:** `client/src/pages/threat-hunting.tsx` (1963 lines), `server/routes/threat-hunting.ts`

### 8.1 Hunt Creation & Management

- **Feature Name:** Threat Hunt Management
- **What it does:** Creates, manages, and tracks proactive threat hunting investigations with hypotheses, queries, and findings.
- **How it works:** CRUD via `/api/threat-hunting/hunts`. Each hunt has a name, hypothesis, status (draft, active, completed), assigned hunter, MITRE technique tags, and linked query results. Hunts progress through defined lifecycle stages.
- **Where it applies:** Threat Hunting Workbench.
- **Integration points:** Detection Rules (hunt-to-rule conversion), Incident Management (finding escalation).
- **Configuration options:** Hunt templates, MITRE technique tagging, assignee selection.
- **Output or results:** Hunt cards with status tracking, result counts, and linked findings.
- **Related features:** Detection Rules, Incident Management.

### 8.2 Hunt Query Engine

- **Feature Name:** Query Engine
- **What it does:** Executes structured threat hunting queries against the security data lake, supporting SQL-like syntax with security-specific operators.
- **How it works:** POST to `/api/threat-hunting/hunts/:id/execute` compiles and executes the hunt query against stored event data. Query compiler validates syntax and prevents SQL injection. Results include matching events with entity extraction.
- **Where it applies:** Threat Hunting Workbench.
- **Integration points:** Data Lake, Detection Rules, Entity Graph.
- **Configuration options:** Query language (SQL-like), time range, data source selection.
- **Output or results:** Query results table with matching events, entity highlights, and export options.
- **Related features:** Data Lake, Query Federation.

### 8.3 Hunt Library

- **Feature Name:** Hunt Library
- **What it does:** Provides a curated library of pre-built hunt queries and hypotheses organized by MITRE technique, threat type, and data source.
- **How it works:** Library entries are stored and searchable via `/api/threat-hunting/library`. Each entry includes query template, hypothesis description, required data sources, and MITRE mapping. Users can clone library entries to start new hunts.
- **Where it applies:** Threat Hunting Workbench.
- **Integration points:** MITRE ATT&CK framework.
- **Output or results:** Searchable library with one-click hunt creation from templates.
- **Related features:** MITRE ATT&CK, Hunt Management.

### 8.4 IOC Pivot Interface

- **Feature Name:** IOC Pivot
- **What it does:** Allows hunters to pivot from discovered IOCs to find related activity across all data sources.
- **How it works:** POST to `/api/threat-hunting/pivot/:iocType/:iocValue` searches across all stored events for the given IOC type (IP, domain, hash) and returns all matching activity with timeline.
- **Where it applies:** Threat Hunting Workbench.
- **Integration points:** Entity Graph, Threat Intelligence, Alert Management.
- **Output or results:** Pivot results showing all activity related to the IOC across time and data sources.
- **Related features:** Entity Graph, Threat Intelligence.

### 8.5 Hunt Scheduling

- **Feature Name:** Scheduled Hunts
- **What it does:** Automates recurring hunt execution on defined schedules (hourly, daily, weekly) with alerting on new findings.
- **How it works:** CRUD via `/api/threat-hunting/schedules`. Schedules define hunt ID, cron expression, and notification settings. Toggle enable/disable per schedule.
- **Where it applies:** Threat Hunting Workbench.
- **Configuration options:** Cron schedule, notification recipients, auto-escalation thresholds.
- **Output or results:** Schedule management interface with next-run indicators and result history.
- **Related features:** Hunt Management, Notifications.

### 8.6 Hunt-to-Incident Escalation

- **Feature Name:** Hunt Finding Escalation
- **What it does:** Converts hunt findings directly into security incidents with all context preserved.
- **How it works:** POST `/api/threat-hunting/results/:id/create-incident` creates a new incident from hunt results, linking all discovered entities, evidence, and the original hypothesis. PATCH `/api/threat-hunting/results/:id/link-incident` links findings to existing incidents.
- **Where it applies:** Threat Hunting Workbench.
- **Integration points:** Incident Management, Alert Management.
- **Output or results:** New incident created with hunt context, or findings linked to existing incident.
- **Related features:** Incident Management, Alert Management.

### 8.7 MITRE ATT&CK Coverage Heatmap

- **Feature Name:** MITRE Coverage Heatmap
- **What it does:** Visualizes organization's threat hunting coverage mapped to the MITRE ATT&CK matrix, showing which techniques have active hunts and detection coverage.
- **How it works:** GET `/api/threat-hunting/mitre-coverage` aggregates hunt and detection rule coverage per MITRE technique. Renders as a color-coded matrix (green = covered, yellow = partial, red = no coverage).
- **Where it applies:** Threat Hunting Workbench.
- **Integration points:** Detection Rules, MITRE ATT&CK framework.
- **Output or results:** Interactive MITRE ATT&CK matrix heatmap with click-to-drill coverage details.
- **Related features:** Detection Rules, MITRE ATT&CK.

### 8.8 Hunt Statistics

- **Feature Name:** Hunt Statistics Dashboard
- **What it does:** Tracks key hunting metrics: total hunts, success rate, findings per hunt, average hunt duration, and MITRE technique coverage.
- **How it works:** GET `/api/threat-hunting/stats` aggregates hunt metadata and results into KPIs.
- **Where it applies:** Threat Hunting Workbench.
- **Output or results:** KPI cards and trend charts for hunting program effectiveness.
- **Related features:** Security Metrics, Executive Dashboard.

### 8.9 Threat Hunting Playbooks

- **Feature Name:** Hunt Playbooks
- **What it does:** Defines structured hunting playbooks with step-by-step procedures, required data sources, and expected outcomes for specific threat scenarios.
- **How it works:** CRUD via `/api/threat-hunting/playbooks`. Each playbook includes name, description, steps, required data sources, and MITRE technique mapping.
- **Where it applies:** Threat Hunting Workbench.
- **Output or results:** Playbook library with step-by-step execution guides.
- **Related features:** Playbooks & Automation, Hunt Library.

---

## 9. Detection Rules

**Source:** `client/src/pages/detection-rules.tsx`, `server/routes/native-sensors.ts`

### 9.1 Detection Rule Management

- **Feature Name:** Detection Rule CRUD
- **What it does:** Creates, manages, and deploys detection rules that generate alerts when matching conditions are met in incoming event data.
- **How it works:** CRUD via `/api/detection-rules`. Each rule has name, description, severity, MITRE technique mapping, detection logic (conditions), enabled/disabled status, and match count. Rules are evaluated against incoming sensor events in real-time.
- **Where it applies:** Detection Rules page, Native Sensor pipeline.
- **Integration points:** Native Sensors (event evaluation), Alert Management (alert generation), MITRE ATT&CK.
- **Configuration options:** Rule name, severity, MITRE mapping, detection logic (JSON conditions), enabled/disabled toggle.
- **Output or results:** Rule list with match counts, last triggered timestamps, and status badges.
- **Related features:** Native Sensors, Alert Management, MITRE ATT&CK.

### 9.2 Rule Type Filtering

- **Feature Name:** Rule Type Filter
- **What it does:** Filters detection rules by type (Sigma, YARA, Custom, AI-Generated) for focused management.
- **How it works:** Client-side filtering on rule type field. Supports multi-select filter with type badges.
- **Where it applies:** Detection Rules page.
- **Output or results:** Filtered rule list by selected types.
- **Related features:** AI Detection Rule Generation.

### 9.3 MITRE ATT&CK Heatmap (Detection)

- **Feature Name:** Detection Coverage Heatmap
- **What it does:** Visualizes which MITRE ATT&CK techniques are covered by active detection rules.
- **How it works:** Aggregates detection rules by MITRE technique ID and renders a color-coded matrix showing coverage density.
- **Where it applies:** Detection Rules page.
- **Output or results:** Interactive MITRE matrix with coverage indicators.
- **Related features:** MITRE ATT&CK, Threat Hunting Coverage.

### 9.4 JSON Rule Builder

- **Feature Name:** Visual Rule Builder
- **What it does:** Provides a visual interface for constructing detection rule logic as structured JSON conditions without writing raw code.
- **How it works:** Form-based builder for defining field conditions, logical operators (AND/OR), and threshold values. Generates the detection rule JSON structure.
- **Where it applies:** Detection Rules page (create/edit modal).
- **Output or results:** Structured JSON detection rule ready for deployment.
- **Related features:** Detection Rule Management.

### 9.5 Pre-Built Detection Rules (45 MITRE ATT&CK Rules)

- **Feature Name:** Seed Detection Rules
- **What it does:** Ships 45 pre-built detection rules covering major MITRE ATT&CK techniques, seeded via `/api/detection-rules/seed`.
- **How it works:** POST to seed endpoint creates default rules covering techniques like credential dumping, lateral movement, data exfiltration, privilege escalation, and persistence.
- **Where it applies:** Detection Rules page (first-time setup).
- **Output or results:** 45 ready-to-use detection rules across MITRE ATT&CK tactics.
- **Related features:** MITRE ATT&CK, Native Sensors.

---

## 10. AI-Native Detection Rule Generation

**Source:** `client/src/pages/ai-detection-rules.tsx`, `server/routes/ai-detection-rules.ts`

### 10.1 AI Rule Generation

- **Feature Name:** LLM-Powered Rule Generation
- **What it does:** Uses Claude AI to generate Sigma and YARA detection rules from natural language descriptions or threat intelligence context.
- **How it works:** POST to `/api/ai-detection-rules/generate` sends a prompt describing the threat scenario. Claude generates syntactically valid detection rules with logic, MITRE mapping, and quality scores.
- **Where it applies:** AI Detection Rules page, Generate tab.
- **Integration points:** AI Engine (Claude), Detection Rules, MITRE ATT&CK.
- **Configuration options:** Rule format (Sigma/YARA/Custom), threat description, target data sources.
- **Output or results:** Generated detection rules with quality scores, MITRE mappings, and deploy buttons.
- **Related features:** Detection Rules, AI Engine.

### 10.2 Rule A/B Testing

- **Feature Name:** Detection Rule A/B Testing
- **What it does:** Runs parallel evaluation of two detection rule variants to measure relative effectiveness (true positive rate, false positive rate).
- **How it works:** CRUD via `/api/ai-detection-rules/ab-tests`. Creates test pairs running both rule variants against the same event stream, tracking match rates and analyst feedback.
- **Where it applies:** AI Detection Rules page, A/B Testing tab.
- **Output or results:** Side-by-side comparison of rule variants with statistical significance indicators.
- **Related features:** Detection Rules, Active Learning.

### 10.3 Rule Lifecycle Management

- **Feature Name:** Rule Lifecycle
- **What it does:** Tracks detection rules through lifecycle stages: draft, testing, active, deprecated, archived.
- **How it works:** GET `/api/ai-detection-rules/lifecycle` provides lifecycle event history for rules. Rules automatically progress through stages based on testing outcomes and time thresholds.
- **Where it applies:** AI Detection Rules page, Lifecycle tab.
- **Output or results:** Lifecycle timeline per rule with stage transitions and triggering events.
- **Related features:** Detection Rules.

### 10.4 Community Rule Marketplace

- **Feature Name:** Rule Marketplace
- **What it does:** Browse, share, and download community-contributed detection rules with quality ratings and usage statistics.
- **How it works:** GET `/api/ai-detection-rules/marketplace` lists published rules. Rules can be published from the organization's rule set and downloaded by others.
- **Where it applies:** AI Detection Rules page, Marketplace tab.
- **Output or results:** Marketplace listing with rule cards, quality scores, download counts, and one-click import.
- **Related features:** Community Intel, Detection Rules.

---

## 11. Native Sensors

**Source:** `client/src/pages/native-sensors.tsx` (1431 lines), `server/routes/native-sensors.ts`

### 11.1 Sensor Registration

- **Feature Name:** Native Sensor Registration
- **What it does:** Registers lightweight security agents (native sensors) deployed on endpoints across 7 platforms: Linux, Windows, macOS, iOS, Android, Docker, and Kubernetes.
- **How it works:** POST to `/api/native-sensors/register` creates a sensor record with platform, hostname, OS version, and capabilities. Each sensor receives a unique ID and authentication token for subsequent communications.
- **Where it applies:** Native Sensors page; all supported platforms.
- **Integration points:** Detection Rules (event evaluation), Alert Management (alert generation), Onboarding wizard.
- **Configuration options:** Platform selection, sensor name, deployment mode (agent/agentless).
- **Output or results:** Registered sensor card with platform icon, hostname, status badge, and last heartbeat timestamp.
- **Related features:** Detection Rules, Alert Management, Onboarding.

### 11.2 Sensor Heartbeat Monitoring

- **Feature Name:** Sensor Heartbeat
- **What it does:** Monitors sensor health through periodic heartbeat signals, detecting offline or degraded sensors.
- **How it works:** POST to `/api/native-sensors/:id/heartbeat` updates the sensor's last-seen timestamp and health metrics. Sensors not reporting within the expected interval are flagged as offline.
- **Where it applies:** Native Sensors page.
- **Integration points:** Operations monitoring, Alert Management (sensor-down alerts).
- **Output or results:** Real-time sensor status indicators (online/offline/degraded) with last heartbeat timestamps.
- **Related features:** Operations, Alert Management.

### 11.3 Sensor Event Ingestion

- **Feature Name:** Sensor Event Collection
- **What it does:** Receives security event data from deployed sensors including process execution, network connections, file operations, and authentication events.
- **How it works:** POST to `/api/native-sensors/:id/events` accepts batched event payloads from sensors. Events are stored and evaluated against active detection rules in real-time. Matching events generate alerts.
- **Where it applies:** Native Sensors pipeline.
- **Integration points:** Detection Rules (real-time evaluation), Alert Management (alert generation).
- **Output or results:** Events stored in the sensor events table, accessible via `/api/sensor-events`.
- **Related features:** Detection Rules, Alert Management.

### 11.4 Platform-Specific Capabilities

- **Feature Name:** Platform Capability Mapping
- **What it does:** Defines and displays platform-specific monitoring capabilities for each of the 7 supported platforms.
- **How it works:** PLATFORM_CAPABILITIES constant maps each platform to its specific features, log sources, and requirements:
  - **Linux:** Process monitoring (auditd/eBPF), network socket tracking (netfilter), file integrity (inotify), SSH session logging, container escape detection, kernel module monitoring, cron job auditing. Requires Linux 4.15+ kernel.
  - **Windows:** Process creation (Sysmon/ETW), network connection monitoring (WFP), registry change tracking, PowerShell script block logging, WMI event subscription monitoring, service installation tracking, Windows Event Log forwarding. Requires Windows 10/Server 2016+.
  - **macOS:** Process monitoring (Endpoint Security framework), network filter (Network Extension), file system events (FSEvents), Keychain access logging, Gatekeeper bypass detection, TCC permission monitoring. Requires macOS 12+.
  - **iOS:** App activity monitoring (NSExtension), network traffic inspection (NEFilterDataProvider), device posture assessment (MDM compliance), jailbreak detection, certificate pinning validation, Bluetooth/AirDrop monitoring, push notification event forwarding. Requires iOS 15+, MDM enrollment.
  - **Android:** App usage monitoring (UsageStatsManager), network traffic inspection (VpnService), device posture assessment (Device Admin/Android Enterprise), root/bootloader unlock detection, SMS/call log monitoring, Wi-Fi/Bluetooth scanning, accessibility service event capture. Requires Android 10+ (API 29+).
  - **Docker:** Container lifecycle events (Docker API), image vulnerability scanning, network policy enforcement, volume mount auditing, privileged container detection, resource limit monitoring, secrets exposure scanning. Requires Docker 20.10+.
  - **Kubernetes:** Pod security policy enforcement (OPA/Gatekeeper), network policy monitoring (Cilium/Calico), RBAC audit logging, secrets access monitoring, admission controller events, node-level syscall auditing (Falco), service mesh telemetry (Istio/Linkerd). Requires K8s 1.24+.
- **Where it applies:** Native Sensors page (platform selection), Onboarding wizard.
- **Output or results:** Platform-specific capability cards with feature lists and deployment requirements.
- **Related features:** Sensor Registration, Detection Rules.

### 11.5 Sensor Deletion

- **Feature Name:** Sensor Deregistration
- **What it does:** Removes a sensor from the platform, stopping event collection and cleaning up associated resources.
- **How it works:** DELETE `/api/native-sensors/:id` removes the sensor record and invalidates its authentication token.
- **Where it applies:** Native Sensors page.
- **Output or results:** Sensor removed from the management interface.
- **Related features:** Sensor Registration.

---

## 12. Native Vulnerability Scanner

**Source:** `client/src/pages/vuln-scanner.tsx`, `server/routes/vuln-scanner.ts`

### 12.1 Package Vulnerability Scanning

- **Feature Name:** Package Vulnerability Scanner
- **What it does:** Scans software packages installed on monitored endpoints for known vulnerabilities by matching against a CVE database.
- **How it works:** POST to `/api/native/vuln/packages` accepts package manifests (name, version, type) from sensors. Each package is matched against the CVE database for known vulnerabilities. Findings are stored with severity, CVE ID, and remediation guidance.
- **Where it applies:** Vulnerability Scanner page.
- **Integration points:** Native Sensors (package inventory), Supply Chain Security (SBOM).
- **Configuration options:** Scan scope, severity threshold for alerting.
- **Output or results:** Vulnerability findings list with CVE IDs, severity scores (CVSS), affected packages, and fix versions.
- **Related features:** Native Sensors, Supply Chain Security.

### 12.2 Vulnerability Findings Management

- **Feature Name:** Vulnerability Findings
- **What it does:** Displays, filters, and manages discovered vulnerabilities with status tracking (open, in_progress, resolved, accepted_risk).
- **How it works:** GET `/api/native/vuln/findings` with filters for severity, status, package, and CVE. PATCH endpoint allows status updates and risk acceptance.
- **Where it applies:** Vulnerability Scanner page.
- **Configuration options:** Severity filter, status filter, date range.
- **Output or results:** Filterable findings table with severity badges, affected asset counts, and remediation actions.
- **Related features:** Risk Management, Compliance.

### 12.3 CVE Database Browser

- **Feature Name:** CVE Database
- **What it does:** Provides a searchable database of known CVEs with CVSS scores, affected products, and remediation information.
- **How it works:** GET `/api/native/vuln/cve-database` returns the local CVE database. Supports search by CVE ID, product name, and severity range.
- **Where it applies:** Vulnerability Scanner page, CVE Browser page.
- **Output or results:** Searchable CVE catalog with detail cards for each vulnerability.
- **Related features:** Vulnerability Findings, Package Scanning.

### 12.4 Package Inventory

- **Feature Name:** Package Inventory
- **What it does:** Maintains a complete inventory of software packages across all monitored endpoints.
- **How it works:** GET `/api/native/vuln/packages` returns all scanned packages with version info, source sensor, and vulnerability status.
- **Where it applies:** Vulnerability Scanner page.
- **Output or results:** Package inventory table with vulnerability status indicators.
- **Related features:** SBOM, Supply Chain Security.

---

## 13. UEBA (User & Entity Behavior Analytics)

**Source:** `client/src/pages/ueba.tsx`, `server/routes/ueba.ts`

### 13.1 Entity Risk Profiling

- **Feature Name:** Entity Risk Profiles
- **What it does:** Builds behavioral profiles for users and entities (hosts, services), calculating dynamic risk scores based on observed activity patterns.
- **How it works:** GET `/api/ueba/entities` returns entity profiles with risk scores, baseline deviations, anomaly counts, and activity summaries. Risk scores are computed from weighted factors: login anomalies, data access patterns, privilege usage, and behavioral deviations.
- **Where it applies:** UEBA page.
- **Integration points:** Identity Governance (user context), Alert Management (risk-based enrichment).
- **Output or results:** Entity cards with risk scores, trend indicators, and behavioral pattern summaries.
- **Related features:** Identity Governance, Alert Management.

### 13.2 Anomaly Detection

- **Feature Name:** Behavioral Anomaly Detection
- **What it does:** Detects anomalous user and entity behaviors by comparing current activity against established baselines.
- **How it works:** GET `/api/ueba/anomalies` returns detected anomalies. PATCH `/api/ueba/anomalies/:id` allows status updates (open, investigating, resolved, false_positive). Anomaly types include unusual login times, geographic impossibility, excessive data access, privilege escalation patterns, and lateral movement indicators.
- **Where it applies:** UEBA page.
- **Integration points:** Alert Management, Incident Management.
- **Configuration options:** Anomaly sensitivity thresholds, baseline learning period.
- **Output or results:** Anomaly cards with deviation scores, baseline comparison, and timeline visualization.
- **Related features:** Alert Management, Incident Management.

### 13.3 Baseline Management

- **Feature Name:** Behavioral Baselines
- **What it does:** Establishes and manages normal behavior baselines for users and entities, used as reference for anomaly detection.
- **How it works:** GET `/api/ueba/baselines` returns current baselines. POST endpoint triggers baseline recalculation. Baselines capture normal patterns for login times, data access volumes, application usage, and network behavior.
- **Where it applies:** UEBA page.
- **Configuration options:** Baseline learning period, recalculation frequency.
- **Output or results:** Baseline profiles with normal range indicators and confidence levels.
- **Related features:** Anomaly Detection.

### 13.4 Peer Group Analysis

- **Feature Name:** Peer Group Comparison
- **What it does:** Compares an entity's behavior against its peer group (same role, department, or function) to identify outliers.
- **How it works:** Entities are grouped by role/department. Individual behavior is compared against peer group averages to identify statistically significant deviations.
- **Where it applies:** UEBA page.
- **Output or results:** Peer comparison charts showing individual vs. group behavior patterns.
- **Related features:** Identity Governance, Entity Risk Profiling.

---

## 14. Playbooks & Automation

**Source:** `client/src/pages/playbooks.tsx` (2639 lines), `server/routes/playbooks.ts` (1353 lines)

### 14.1 Playbook Management

- **Feature Name:** Playbook CRUD
- **What it does:** Creates, manages, and deploys security response playbooks with multi-step workflows, trigger conditions, and automated/manual action steps.
- **How it works:** CRUD via `/api/playbooks`. Each playbook has a name, description, trigger type (manual, alert-based, scheduled), severity threshold, steps (ordered list of actions), and tags. Playbooks support conditional branching and parallel execution paths.
- **Where it applies:** Playbooks page.
- **Integration points:** Incident Management (runbook execution), Alert Management (auto-triggered), Integrations (action targets).
- **Configuration options:** Trigger conditions, step actions, approval gates, timeout values, rollback procedures.
- **Output or results:** Playbook cards with step counts, trigger types, execution history, and status badges.
- **Related features:** Incident Runbooks, Autonomous Response.

### 14.2 Playbook Execution

- **Feature Name:** Playbook Execution Engine
- **What it does:** Executes playbook workflows step-by-step, with support for automated actions, manual checkpoints, and approval gates.
- **How it works:** POST to `/api/playbooks/:id/execute` starts playbook execution. Each step is executed in sequence with status tracking. Automated steps execute immediately; manual steps wait for analyst action; approval steps wait for authorized approval.
- **Where it applies:** Playbooks page, Incident Detail (runbook execution).
- **Integration points:** Integrations (action dispatch), Approval Workflows, Notification Channels.
- **Output or results:** Step-by-step execution tracker with status indicators, timing, and output logs.
- **Related features:** Incident Runbooks, Approval Workflows.

### 14.3 Playbook Version Control

- **Feature Name:** Playbook Versioning
- **What it does:** Maintains version history for playbooks, enabling rollback to previous versions and change tracking.
- **How it works:** GET `/api/playbooks/:playbookId/versions` returns version history. Each edit creates a new version snapshot. Versions can be viewed, compared, and restored.
- **Where it applies:** Playbooks page.
- **Output or results:** Version timeline with diff capability and one-click restore.
- **Related features:** Playbook Management.

### 14.4 Playbook Approval Workflows

- **Feature Name:** Execution Approval Gates
- **What it does:** Requires manager approval before executing high-impact playbook steps (e.g., host isolation, account lockout).
- **How it works:** GET `/api/playbook-approvals` shows pending approvals. Approval steps pause execution until authorized. POST to `/api/playbook-executions/:id/resume` continues after approval.
- **Where it applies:** Playbooks page, Incident Detail.
- **Integration points:** RBAC (approver roles), Notification Channels.
- **Output or results:** Approval queue with pending requests and approve/reject controls.
- **Related features:** RBAC, Incident Approvals.

### 14.5 Playbook Rollback

- **Feature Name:** Execution Rollback
- **What it does:** Rolls back completed playbook actions when an execution is determined to be erroneous or harmful.
- **How it works:** POST to `/api/playbook-executions/:id/rollback` reverses executed steps in reverse order, undoing actions where possible (e.g., re-enabling a disabled account, removing firewall rules).
- **Where it applies:** Playbooks page.
- **Output or results:** Rollback progress tracker with per-step reversal status.
- **Related features:** Autonomous Response Rollback.

### 14.6 Blast Radius Preview

- **Feature Name:** Playbook Blast Radius
- **What it does:** Previews the potential impact of a playbook execution before running it, showing which assets, users, and services would be affected.
- **How it works:** Analyzes playbook steps and target scope to estimate affected resources. Displays impact summary before execution confirmation.
- **Where it applies:** Playbooks page (pre-execution).
- **Output or results:** Impact preview showing affected assets, users, and services with severity indicators.
- **Related features:** Playbook Execution.

---

## 15. War Room

**Source:** `client/src/pages/war-room.tsx`, `server/routes/war-room.ts`

### 15.1 War Room Creation

- **Feature Name:** War Room Management
- **What it does:** Creates persistent collaboration spaces for major incident response, bringing together analysts, evidence, timelines, and communication in a dedicated workspace.
- **How it works:** POST to create war rooms linked to specific incidents. War rooms include real-time chat, evidence sharing, timeline tracking, and participant management. Rooms persist beyond incident resolution for post-mortem reference.
- **Where it applies:** War Room page.
- **Integration points:** Incident Management, Team Management, Evidence Management.
- **Configuration options:** Room name, linked incident, participant list, access controls.
- **Output or results:** Dedicated workspace with chat, evidence panel, timeline, and participant list.
- **Related features:** Incident Management, Team Management.

### 15.2 Real-Time Chat

- **Feature Name:** War Room Chat
- **What it does:** Provides real-time messaging within the war room for incident response coordination.
- **How it works:** WebSocket-based real-time messaging via war room chat endpoints. Messages support text, formatted content, and evidence attachments.
- **Where it applies:** War Room page.
- **Integration points:** Notification Channels (Slack/Teams bridging).
- **Output or results:** Real-time chat stream with author identification and timestamps.
- **Related features:** Incident Comments.

### 15.3 War Room Timeline

- **Feature Name:** Investigation Timeline
- **What it does:** Maintains a shared chronological timeline of all investigation activities, findings, and decisions within the war room.
- **How it works:** Timeline entries are automatically created from war room activities and can be manually added. Each entry has a timestamp, type (finding, decision, action, note), author, and description.
- **Where it applies:** War Room page.
- **Output or results:** Chronological timeline with filterable entry types.
- **Related features:** Incident Audit Chain, Investigation Timeline.

### 15.4 War Room Participants

- **Feature Name:** Participant Management
- **What it does:** Manages war room membership, roles (lead, analyst, observer), and access permissions.
- **How it works:** Participant CRUD endpoints allow adding/removing team members and assigning roles within the war room.
- **Where it applies:** War Room page.
- **Integration points:** Team Management, RBAC.
- **Output or results:** Participant list with role badges and online status indicators.
- **Related features:** Team Management, RBAC.

### 15.5 War Room Evidence Sharing

- **Feature Name:** Evidence Board
- **What it does:** Shared evidence board within the war room for pinning, annotating, and discussing investigation artifacts.
- **How it works:** Evidence items from the incident can be pinned to the war room board. Analysts can annotate evidence and discuss findings in context.
- **Where it applies:** War Room page.
- **Integration points:** Evidence Management, Incident Management.
- **Output or results:** Visual evidence board with pinned items, annotations, and discussion threads.
- **Related features:** Evidence Management.

---

## 16. Cloud Security Posture Management (CSPM)

**Source:** `client/src/pages/cspm.tsx` (2063 lines), `server/routes/cspm.ts` (if exists), phase2 routes

### 16.1 Cloud Account Connectivity

- **Feature Name:** Cloud Account Management
- **What it does:** Connects and manages cloud provider accounts (AWS, Azure, GCP) for continuous security posture monitoring.
- **How it works:** CloudAccountsTab (lines 116-430) manages cloud account connections. Each account stores provider type, credentials (IAM role ARN for AWS, service principal for Azure, service account for GCP), region scope, and scan schedule. Accounts are validated on connection.
- **Where it applies:** CSPM page, Cloud Accounts tab.
- **Integration points:** AWS API, Azure API, GCP API.
- **Configuration options:** Provider selection, credential configuration (cross-account IAM roles), region scope, scan schedule.
- **Output or results:** Connected account cards with provider icons, scan status, finding counts, and last scan timestamps.
- **Related features:** Cloud Scanning, Drift Detection.

### 16.2 Cloud Security Scanning

- **Feature Name:** Cloud Posture Scanning
- **What it does:** Performs automated security posture scans across connected cloud accounts, evaluating configurations against security best practices and compliance frameworks.
- **How it works:** ScanHistoryTab (lines 432-545) shows scan history. Scans evaluate cloud resources (S3 buckets, security groups, IAM policies, encryption settings, logging configurations) against defined policy checks. Results are stored as findings with severity ratings.
- **Where it applies:** CSPM page, Scan History tab.
- **Integration points:** Cloud Accounts, Policy Checks, Compliance frameworks.
- **Output or results:** Scan history table with scan status, duration, finding counts by severity, and drill-down links.
- **Related features:** Policy Checks, Cloud Findings.

### 16.3 Cloud Security Findings

- **Feature Name:** Cloud Findings Management
- **What it does:** Displays, filters, and manages cloud security findings from posture scans with remediation guidance.
- **How it works:** FindingsTab (lines 547-771) provides a filterable list of cloud misconfigurations and security issues. Each finding includes resource identifier, cloud account, severity, description, remediation steps, and compliance mapping.
- **Where it applies:** CSPM page, Findings tab.
- **Configuration options:** Filters by severity, cloud provider, resource type, compliance framework.
- **Output or results:** Findings table with severity badges, resource details, and one-click remediation actions.
- **Related features:** Remediation Playbooks, Compliance.

### 16.4 Cloud Policy Checks

- **Feature Name:** Policy Check Engine
- **What it does:** Defines and manages security policy rules that cloud resources are evaluated against during scans.
- **How it works:** PolicyChecksTab (lines 773-1275) provides CRUD for security policies. Each policy defines a resource type, evaluation logic, severity, compliance framework mapping, and remediation guidance. Policies can be run individually or as part of full scans.
- **Where it applies:** CSPM page, Policy Checks tab.
- **Integration points:** Compliance frameworks (CIS, NIST, SOC 2, PCI DSS).
- **Configuration options:** Policy definition (resource type, evaluation criteria, severity), enabled/disabled toggle, compliance mapping.
- **Output or results:** Policy list with pass/fail statistics, last evaluation results, and compliance mapping indicators.
- **Related features:** Cloud Scanning, Compliance.

### 16.5 Infrastructure Drift Detection

- **Feature Name:** Drift Detection
- **What it does:** Detects unauthorized or unexpected changes to cloud infrastructure by comparing current state against a known-good baseline.
- **How it works:** DriftDetectionTab (lines 1278-1468) monitors cloud resource configurations for changes. Baselines are established from approved configurations. Any deviation triggers a drift alert with before/after comparison.
- **Where it applies:** CSPM page, Drift Detection tab.
- **Integration points:** Cloud Accounts, Alert Management.
- **Configuration options:** Baseline capture schedule, drift severity thresholds, exclusion patterns.
- **Output or results:** Drift alerts with resource identification, change details (before/after), and remediation options.
- **Related features:** Cloud Scanning, Alert Management.

### 16.6 Data Security Posture Management (DSPM)

- **Feature Name:** DSPM
- **What it does:** Discovers and classifies sensitive data across cloud storage (S3, Blob Storage, GCS), evaluating data protection posture including encryption, access controls, and exposure risk.
- **How it works:** DSPMTab (lines 1471-1659) scans cloud storage for sensitive data patterns (PII, PCI, PHI, credentials). Evaluates encryption status, access policy permissiveness, and public exposure risk.
- **Where it applies:** CSPM page, DSPM tab.
- **Integration points:** Privacy Engineering, Compliance.
- **Output or results:** Data inventory with classification labels, encryption status, access control evaluation, and exposure risk scores.
- **Related features:** Privacy Engineering, Compliance, Data Residency.

### 16.7 Attack Path Analysis

- **Feature Name:** Cloud Attack Paths
- **What it does:** Identifies potential attack paths through cloud infrastructure by analyzing resource relationships, permissions, and vulnerabilities.
- **How it works:** AttackPathsTab (lines 1662-1805) builds a graph of cloud resources, permissions, and network connectivity. Identifies chains of misconfigurations that could enable lateral movement, privilege escalation, or data exfiltration.
- **Where it applies:** CSPM page, Attack Paths tab.
- **Integration points:** Cloud Accounts, Vulnerability Scanner.
- **Output or results:** Attack path visualizations showing step-by-step exploitation chains with risk scores and remediation priorities.
- **Related features:** Attack Graph, Vulnerability Scanner.

### 16.8 Cloud Remediation Playbooks

- **Feature Name:** Auto-Remediation
- **What it does:** Provides automated and guided remediation for cloud security findings, including one-click fixes for common misconfigurations.
- **How it works:** RemediationTab (lines 1808-1975) links findings to remediation playbooks. Automated remediation executes cloud API calls to fix configurations (e.g., enable encryption, restrict security groups). Manual remediation provides step-by-step guides.
- **Where it applies:** CSPM page, Remediation tab.
- **Integration points:** Playbooks & Automation, Cloud provider APIs.
- **Configuration options:** Auto-remediation enable/disable per policy, approval requirements.
- **Output or results:** Remediation action cards with execution status, before/after comparison, and rollback capability.
- **Related features:** Playbooks, Cloud Scanning.

---

## 17. Mobile & Remote Worker Security

**Source:** `client/src/pages/mobile-security.tsx` (1091 lines), `server/routes/mobile-security.ts` (1379 lines)

### 17.1 Device Inventory

- **Feature Name:** Mobile Device Management
- **What it does:** Maintains a comprehensive inventory of registered mobile devices with platform, OS version, compliance status, and risk assessment.
- **How it works:** CRUD via `/api/mobile/devices`. Devices are registered with platform (iOS/Android), OS version, device name, user assignment, MDM enrollment status, and security posture indicators (encryption, jailbreak/root, screen lock).
- **Where it applies:** Mobile Security page, Devices tab.
- **Integration points:** MDM systems (Intune, Jamf, VMware WS1), Identity Governance.
- **Configuration options:** Platform filter, compliance criteria, risk thresholds.
- **Output or results:** Device inventory table with platform icons, compliance badges, risk scores, and posture indicators.
- **Related features:** MDM Integration, Device Posture.

### 17.2 Device Posture Assessment

- **Feature Name:** Device Posture Check
- **What it does:** Evaluates the security posture of registered devices against configurable compliance criteria (encryption, jailbreak/root status, OS version, MDM enrollment).
- **How it works:** POST to `/api/mobile/devices/:id/posture-check` runs a comprehensive posture evaluation. Checks include: storage encryption enabled, jailbreak/root detection, OS version currency, MDM enrollment, screen lock configuration, and installed security apps.
- **Where it applies:** Mobile Security page.
- **Integration points:** ZTNA Policies (posture-based access), Compliance.
- **Output or results:** Posture assessment results with pass/fail per criterion and overall compliance score.
- **Related features:** ZTNA Policies, Compliance.

### 17.3 Mobile Threat Detection

- **Feature Name:** Mobile Threat Detection
- **What it does:** Detects and manages mobile-specific threats including malicious apps, network attacks (MitM), phishing attempts, and OS-level exploits.
- **How it works:** CRUD via `/api/mobile/threats`. Threats are reported by mobile sensors or MDM integrations. Each threat includes type, severity, affected device, detection timestamp, and remediation status.
- **Where it applies:** Mobile Security page, Threats tab.
- **Integration points:** Alert Management, Native Sensors (mobile platforms).
- **Output or results:** Threat list with severity badges, affected device links, and remediation actions.
- **Related features:** Alert Management, Native Sensors.

### 17.4 ZTNA (Zero Trust Network Access) Policies

- **Feature Name:** ZTNA Policy Engine
- **What it does:** Defines and enforces Zero Trust access policies based on device posture, user risk, location, and application sensitivity.
- **How it works:** CRUD via `/api/mobile/ztna/policies`. Policies define conditions (minimum posture score, allowed locations, required encryption) and actions (allow, deny, step-up authentication). POST to `/api/mobile/ztna/evaluate` evaluates a device/user against all active policies.
- **Where it applies:** Mobile Security page, ZTNA tab.
- **Integration points:** Device Posture, Identity Governance, SSO.
- **Configuration options:** Policy conditions (posture score, location, device type), actions (allow/deny/MFA), priority ordering.
- **Output or results:** Policy list with evaluation statistics and enforcement actions.
- **Related features:** Device Posture, Identity Governance.

### 17.5 Remote Session Management

- **Feature Name:** Remote Worker Sessions
- **What it does:** Tracks and manages remote access sessions, monitoring session health, duration, and security compliance.
- **How it works:** CRUD via `/api/mobile/sessions`. Sessions track connection time, device, user, access type, and posture status at connection time. Supports session termination for compromised devices.
- **Where it applies:** Mobile Security page, Sessions tab.
- **Output or results:** Active session list with duration, device info, and terminate buttons.
- **Related features:** ZTNA Policies, Device Posture.

### 17.6 MDM Integration Status

- **Feature Name:** MDM Integration
- **What it does:** Integrates with enterprise MDM solutions (Microsoft Intune, Jamf Pro, VMware Workspace ONE) for device management synchronization.
- **How it works:** GET `/api/mobile/mdm/status` returns integration status. MDM sync via `/api/mobile/devices/sync` pulls device inventory from configured MDM platforms.
- **Where it applies:** Mobile Security page, MDM tab.
- **Integration points:** Microsoft Intune, Jamf Pro, VMware WS1.
- **Configuration options:** MDM platform selection, sync schedule, credential configuration.
- **Output or results:** MDM connection status with sync history and device count.
- **Related features:** Device Inventory, Device Posture.

### 17.7 Mobile Security Dashboard

- **Feature Name:** Mobile Dashboard
- **What it does:** Aggregated view of mobile security metrics including total devices, compliance rate, active threats, and posture distribution.
- **How it works:** GET `/api/mobile/dashboard` aggregates device counts, compliance metrics, threat statistics, and posture scores.
- **Where it applies:** Mobile Security page, Dashboard tab.
- **Output or results:** KPI cards and charts for mobile security posture overview.
- **Related features:** All mobile security features.

---

## 18. Identity Threat Detection & PAM

**Source:** `client/src/pages/identity-governance.tsx` (1432 lines), `server/routes/identity-governance.ts`

### 18.1 Access Reviews

- **Feature Name:** Access Review Campaigns
- **What it does:** Creates and manages periodic access review campaigns where managers certify or revoke user entitlements.
- **How it works:** CRUD via `/api/identity/access-reviews`. Campaigns define scope (all users, specific departments), review period, and reviewers. Entitlements are listed for certification with approve/revoke actions per entitlement.
- **Where it applies:** Identity Governance page, Access Reviews tab.
- **Integration points:** SCIM provisioning, Identity Providers.
- **Configuration options:** Campaign scope, review period, reviewer assignment, auto-revoke on non-response.
- **Output or results:** Review campaign dashboard with progress tracking, decision statistics, and entitlement detail tables.
- **Related features:** SCIM Provisioning, Stale Accounts.

### 18.2 Privileged Access Management (PAM)

- **Feature Name:** PAM Controls
- **What it does:** Manages privileged access with just-in-time (JIT) elevation, session recording, and checkout/checkin workflows for sensitive credentials.
- **How it works:** PAM tab (lines 586-865) provides privilege elevation requests, approval workflows, session monitoring, and credential vault integration. Supports time-limited access grants with automatic revocation.
- **Where it applies:** Identity Governance page, PAM tab.
- **Integration points:** Approval Workflows, Audit Log, Session Management.
- **Configuration options:** Elevation duration limits, approval requirements, session recording toggle.
- **Output or results:** PAM dashboard with active sessions, pending requests, and audit trail.
- **Related features:** Approval Workflows, Audit Log.

### 18.3 Stale Account Detection

- **Feature Name:** Stale Account Identification
- **What it does:** Identifies user accounts that have been inactive beyond configurable thresholds, flagging them for review or automated deactivation.
- **How it works:** GET `/api/identity/stale-accounts` queries user accounts by last activity date. Accounts exceeding the inactivity threshold are flagged with recommendations (disable, delete, review).
- **Where it applies:** Identity Governance page, Stale Accounts tab.
- **Configuration options:** Inactivity threshold (days), auto-disable settings.
- **Output or results:** Stale account list with last activity dates, account details, and bulk action controls.
- **Related features:** Access Reviews, SCIM Provisioning.

### 18.4 Blast Radius Analysis

- **Feature Name:** Identity Blast Radius
- **What it does:** Visualizes the potential impact of a compromised identity by mapping all accessible resources, permissions, and downstream dependencies.
- **How it works:** GET `/api/identity/blast-radius/:userId` traces all permissions, group memberships, role assignments, and resource access for a user. Builds a dependency graph showing affected systems.
- **Where it applies:** Identity Governance page, Blast Radius tab.
- **Integration points:** Access Graph, Risk Profiling.
- **Output or results:** Visual blast radius map showing affected resources, permission chains, and risk scores.
- **Related features:** Access Graph, Risk Profiling.

### 18.5 Lateral Movement Detection

- **Feature Name:** Lateral Movement Analysis
- **What it does:** Detects potential lateral movement paths through the identity infrastructure by analyzing permission chains, trust relationships, and access patterns.
- **How it works:** Access graph analysis identifies paths where a compromised account could escalate privileges or move laterally through connected systems.
- **Where it applies:** Identity Governance page, Lateral Movement tab.
- **Integration points:** UEBA, Alert Management.
- **Output or results:** Lateral movement path visualizations with risk scores and remediation recommendations.
- **Related features:** UEBA, Blast Radius, Attack Graph.

### 18.6 SCIM Provisioning

- **Feature Name:** SCIM Integration
- **What it does:** Automated user provisioning and deprovisioning via SCIM 2.0 protocol integration with identity providers.
- **How it works:** SCIM endpoints handle user creation, update, and deactivation events from IdPs. Provisioning logs track all SCIM operations. Supports manual provisioning via `/api/identity/scim/provision`.
- **Where it applies:** Identity Governance page, SCIM tab.
- **Integration points:** Identity Providers (Okta, Azure AD, OneLogin), SSO.
- **Output or results:** Provisioning event log with operation details and status indicators.
- **Related features:** SSO, Team Management.

### 18.7 Access Graph

- **Feature Name:** Identity Access Graph
- **What it does:** Visualizes the complete access graph showing relationships between users, groups, roles, and resources.
- **How it works:** GET `/api/identity/access-graph` builds a graph of identity-to-resource relationships. POST endpoint allows adding/modifying edges.
- **Where it applies:** Identity Governance page.
- **Output or results:** Interactive graph visualization of identity-resource relationships.
- **Related features:** Blast Radius, Lateral Movement.

### 18.8 Identity Risk Profiles

- **Feature Name:** Identity Risk Assessment
- **What it does:** Calculates risk profiles for identities based on privilege level, access patterns, compliance status, and behavioral indicators.
- **How it works:** GET `/api/identity/risk-profiles` returns risk assessments. POST `/api/identity/risk-profiles/assess` triggers reassessment.
- **Where it applies:** Identity Governance page.
- **Output or results:** Risk profile cards with score breakdowns and trend indicators.
- **Related features:** UEBA, Access Reviews.

---

## 19. Ransomware Defense Suite

**Source:** `client/src/pages/ransomware-defense.tsx` (2091 lines), `server/routes/ransomware-defense.ts` (1519 lines)

### 19.1 Ransomware Dashboard

- **Feature Name:** Ransomware Defense Dashboard
- **What it does:** Provides an overview of ransomware defense posture including kill switch status, canary file coverage, backup health, and active intelligence.
- **How it works:** GET `/api/ransomware-defense/summary` aggregates metrics from all ransomware defense components.
- **Where it applies:** Ransomware Defense page, Dashboard tab.
- **Output or results:** KPI cards for kill switch status, canary coverage, backup freshness, and threat intelligence indicators.
- **Related features:** All ransomware defense features.

### 19.2 Kill Switch

- **Feature Name:** Ransomware Kill Switch
- **What it does:** Provides an emergency kill switch that can immediately isolate affected systems, terminate suspicious processes, and block lateral movement during an active ransomware attack.
- **How it works:** GET/POST `/api/ransomware-defense/kill-switch` manages kill switch state. Activation triggers: network isolation of affected segments, process termination of known ransomware signatures, SMB/RDP blocking, and automated backup verification.
- **Where it applies:** Ransomware Defense page, Kill Switch tab.
- **Integration points:** Native Sensors (host isolation), Network Segmentation, Alert Management.
- **Configuration options:** Isolation scope (host, segment, organization), process kill list, network block rules.
- **Output or results:** Kill switch activation panel with scope selection and real-time execution status.
- **Related features:** Autonomous Response, Native Sensors.

### 19.3 Canary Files

- **Feature Name:** Canary File Monitoring
- **What it does:** Deploys decoy files (canary files) across file systems that trigger alerts when accessed, indicating potential ransomware file enumeration or encryption activity.
- **How it works:** Canary files with monitored extensions (.docx, .xlsx, .pdf) are deployed to strategic locations. File system monitoring detects any access or modification to these files, triggering immediate alerts.
- **Where it applies:** Ransomware Defense page, Canary Files tab.
- **Integration points:** Native Sensors (file monitoring), Alert Management, Deception Technology.
- **Output or results:** Canary file inventory with deployment status, access alerts, and coverage map.
- **Related features:** Deception Technology, Native Sensors.

### 19.4 Ransomware Intelligence

- **Feature Name:** Ransomware Group Tracking
- **What it does:** Tracks active ransomware groups with profiles including TTPs, targeted sectors, ransom demands, and known IOCs.
- **How it works:** GET `/api/ransomware-defense/groups` returns ransomware group profiles. GET `/api/ransomware-defense/groups/:id` provides detailed group intelligence.
- **Where it applies:** Ransomware Defense page, Intelligence tab.
- **Integration points:** Threat Intelligence, MITRE ATT&CK.
- **Output or results:** Ransomware group cards with TTP mapping, targeted sectors, and IOC lists.
- **Related features:** Threat Intelligence, MITRE ATT&CK.

### 19.5 AI Recovery Runbooks

- **Feature Name:** Recovery Runbooks
- **What it does:** AI-generated and curated recovery runbooks for ransomware incident response, with step-by-step procedures for containment, eradication, and recovery.
- **How it works:** GET `/api/ransomware-defense/runbooks` returns available recovery runbooks. Each runbook includes phases (containment, eradication, recovery), steps, checklists, and communication templates.
- **Where it applies:** Ransomware Defense page, Recovery tab.
- **Integration points:** Playbooks, Incident Management.
- **Output or results:** Runbook library with step-by-step recovery procedures and execution tracking.
- **Related features:** Playbooks, Incident Management.

### 19.6 Tabletop Exercises

- **Feature Name:** Tabletop Exercise Simulator
- **What it does:** Facilitates ransomware tabletop exercises with scenario-based simulations, team role assignments, and effectiveness scoring.
- **How it works:** GET `/api/ransomware-defense/exercises` manages exercise scenarios. Each exercise defines a ransomware scenario, participant roles, decision points, and evaluation criteria.
- **Where it applies:** Ransomware Defense page, Tabletop tab.
- **Output or results:** Exercise scenarios with role assignments, decision tracking, and post-exercise scoring.
- **Related features:** Security Awareness, Incident Management.

### 19.7 Backup Verification

- **Feature Name:** Backup Health Monitoring
- **What it does:** Monitors and verifies backup integrity and recoverability, ensuring ransomware recovery capabilities are maintained.
- **How it works:** GET `/api/ransomware-defense/backups` returns backup status across monitored systems. Verifies backup freshness, integrity hashes, and restore test results.
- **Where it applies:** Ransomware Defense page, Backups tab.
- **Output or results:** Backup inventory with freshness indicators, integrity status, and last restore test results.
- **Related features:** Disaster Recovery, Operations.

---

## 20. Supply Chain Security

**Source:** `client/src/pages/supply-chain.tsx` (1327 lines), `server/routes/supply-chain.ts`

### 20.1 SBOM Ingestion

- **Feature Name:** SBOM Management
- **What it does:** Ingests, stores, and analyzes Software Bill of Materials (SBOMs) from applications and systems, tracking all software components and their dependencies.
- **How it works:** POST to SBOM ingestion endpoint accepts SPDX and CycloneDX format SBOMs. Parses component lists, dependency trees, and license information. Components are matched against vulnerability databases.
- **Where it applies:** Supply Chain Security page, SBOMs tab.
- **Integration points:** Vulnerability Scanner (CVE matching), Developer Security (CI pipeline).
- **Configuration options:** SBOM format (SPDX, CycloneDX), auto-scan on upload.
- **Output or results:** SBOM inventory with component counts, vulnerability indicators, and dependency tree visualization.
- **Related features:** Vulnerability Scanner, Developer Security.

### 20.2 Dependency Graph Visualization

- **Feature Name:** Dependency Graph
- **What it does:** Visualizes software dependency trees showing all transitive dependencies and their vulnerability status.
- **How it works:** Parses SBOM dependency relationships and renders as an interactive tree/graph. Nodes are colored by vulnerability severity.
- **Where it applies:** Supply Chain Security page, Dependencies tab.
- **Output or results:** Interactive dependency tree with vulnerability highlights and click-to-drill detail.
- **Related features:** SBOM Management, Vulnerability Scanner.

### 20.3 Supply Chain Findings

- **Feature Name:** Supply Chain Vulnerability Findings
- **What it does:** Displays vulnerabilities found in software supply chain components with severity, CVE details, and remediation paths.
- **How it works:** GET findings endpoint returns vulnerabilities matched from SBOM components against CVE databases. Each finding includes component name, version, CVE ID, CVSS score, and fix version.
- **Where it applies:** Supply Chain Security page, Findings tab.
- **Output or results:** Findings table with severity badges, affected components, and remediation actions.
- **Related features:** Vulnerability Scanner, Compliance.

### 20.4 Typosquatting Detection

- **Feature Name:** Typosquatting Detection
- **What it does:** Detects potential typosquatting attacks in software dependencies by identifying packages with names similar to popular libraries.
- **How it works:** Analyzes SBOM package names against a database of known popular packages. Uses string similarity algorithms (Levenshtein distance) to flag suspicious package names that may be typosquatting attempts.
- **Where it applies:** Supply Chain Security page.
- **Integration points:** SBOM Management, Alert Management.
- **Output or results:** Typosquatting alerts with suspicious package names, similar legitimate packages, and risk assessment.
- **Related features:** SBOM Management, Alert Management.

### 20.5 IaC Security Scanning

- **Feature Name:** Infrastructure-as-Code Scanning
- **What it does:** Scans Infrastructure-as-Code templates (Terraform, CloudFormation, Kubernetes manifests) for security misconfigurations.
- **How it works:** POST scan endpoint accepts IaC templates and evaluates against security policies. Checks include: overly permissive IAM policies, unencrypted storage, public network exposure, missing logging.
- **Where it applies:** Supply Chain Security page, Developer Security.
- **Integration points:** CSPM (cloud policy alignment), Developer Security.
- **Output or results:** IaC scan results with finding severity, affected resources, and remediation code snippets.
- **Related features:** CSPM, Developer Security.

---

## 21. Deception Technology

**Source:** `client/src/pages/deception.tsx`, `server/routes/deception.ts`

### 21.1 Canary Token Management

- **Feature Name:** Canary Tokens
- **What it does:** Creates and manages decoy credentials, API keys, URLs, and documents that trigger alerts when accessed by unauthorized actors.
- **How it works:** CRUD via `/api/deception/canaries`. Canary types include: AWS credentials, API keys, URLs, DNS tokens, database connection strings, and document beacons. Each canary generates a unique trigger that reports access attempts with source information.
- **Where it applies:** Deception Technology page, Canary Tokens tab.
- **Integration points:** Alert Management (canary trigger alerts), Dark Web Monitoring (credential exposure).
- **Configuration options:** Canary type, name, location placement, alert severity, expiration.
- **Output or results:** Canary inventory with type icons, deployment status, trigger count, and access logs.
- **Related features:** Ransomware Defense (canary files), Dark Web Monitoring.

### 21.2 Honeypot Deployment

- **Feature Name:** Honeypot Management
- **What it does:** Deploys and manages decoy systems (honeypots) that mimic real production assets to detect and study attacker behavior.
- **How it works:** CRUD via `/api/deception/honeypots`. Honeypot types include: SSH honeypot, HTTP honeypot, database honeypot, file server honeypot, and IoT honeypot. Each honeypot captures interaction logs and attacker TTPs.
- **Where it applies:** Deception Technology page, Honeypots tab.
- **Integration points:** Alert Management, Threat Intelligence (attacker TTP capture).
- **Configuration options:** Honeypot type, emulated service, network placement, interaction capture settings.
- **Output or results:** Honeypot inventory with status indicators, interaction counts, and captured TTP summaries.
- **Related features:** Alert Management, Threat Intelligence.

### 21.3 Network Decoys

- **Feature Name:** Network Decoy Deployment
- **What it does:** Creates decoy network services and endpoints that appear as legitimate infrastructure to attract and detect lateral movement.
- **How it works:** CRUD via `/api/deception/decoys`. Decoys emulate network services (SMB shares, RDP endpoints, web servers) with realistic responses. Access to decoys triggers immediate alerts with source attribution.
- **Where it applies:** Deception Technology page, Decoys tab.
- **Integration points:** Alert Management, OT/ICS Security (industrial decoys).
- **Configuration options:** Decoy service type, network placement, response behavior, alert severity.
- **Output or results:** Decoy inventory with service types, network locations, and interaction logs.
- **Related features:** Alert Management, OT/ICS Security.

### 21.4 Deception Deployment Wizard

- **Feature Name:** Deployment Wizard
- **What it does:** Guided wizard for deploying a comprehensive deception strategy across the organization's network, recommending optimal placement of canaries, honeypots, and decoys.
- **How it works:** Step-by-step wizard analyzes the organization's network topology and recommends deception asset placement. Generates deployment configurations for selected deception types.
- **Where it applies:** Deception Technology page.
- **Output or results:** Guided deployment workflow with recommended placements and one-click deployment.
- **Related features:** All deception features.

### 21.5 Auto-Escalation

- **Feature Name:** Deception Alert Auto-Escalation
- **What it does:** Automatically escalates deception alerts to incidents based on confidence and interaction patterns, since any canary/honeypot trigger indicates genuine malicious activity.
- **How it works:** Deception alerts are automatically classified as high-confidence true positives. Based on configurable rules, triggers can auto-create incidents, run containment playbooks, and notify response teams.
- **Where it applies:** Deception Technology pipeline.
- **Integration points:** Incident Management, Playbooks, Autonomous Response.
- **Output or results:** Auto-created incidents from deception triggers with full context.
- **Related features:** Incident Management, Playbooks, Autonomous Response.

---

## 22. OT/ICS Security

**Source:** `client/src/pages/ot-ics-security.tsx`, `server/routes/ot-ics.ts`

### 22.1 OT Asset Inventory

- **Feature Name:** OT Asset Discovery & Inventory
- **What it does:** Discovers and maintains an inventory of OT/ICS assets including PLCs, HMIs, RTUs, SCADA servers, engineering workstations, and network devices.
- **How it works:** CRUD via `/api/ot-ics/assets`. Passive asset discovery identifies devices through network traffic analysis without sending active probes. Each asset record includes type, vendor, firmware version, network zone (Purdue Model level), and communication protocols.
- **Where it applies:** OT/ICS Security page, Asset Inventory tab.
- **Integration points:** Native Sensors (OT network monitoring), CSPM (IT/OT convergence).
- **Configuration options:** Asset type classification, Purdue Model level assignment, criticality rating.
- **Output or results:** Asset inventory table with type icons, vendor info, firmware versions, and network zone indicators.
- **Related features:** Purdue Model Visualization, Protocol Analysis.

### 22.2 Protocol Analysis

- **Feature Name:** Industrial Protocol Parsing
- **What it does:** Parses and analyzes OT-specific network protocols (Modbus, DNP3, OPC UA, BACnet, EtherNet/IP, S7comm) for security monitoring.
- **How it works:** Protocol parsers decode OT network traffic into structured events. Monitors for protocol anomalies, unauthorized commands, and parameter changes.
- **Where it applies:** OT/ICS Security page, Protocols tab.
- **Integration points:** Alert Management (protocol anomaly alerts), Detection Rules.
- **Output or results:** Protocol traffic analysis with command breakdowns, anomaly indicators, and baseline deviation alerts.
- **Related features:** Detection Rules, Alert Management.

### 22.3 Purdue Model Visualization

- **Feature Name:** Purdue Model Network Map
- **What it does:** Visualizes the organization's OT network architecture mapped to the Purdue Model reference architecture (Levels 0-5), showing asset placement and zone boundaries.
- **How it works:** Renders OT assets in a Purdue Model diagram with levels: Level 0 (Physical Process), Level 1 (Basic Control), Level 2 (Area Supervisory), Level 3 (Site Operations), Level 3.5 (DMZ), Level 4 (Enterprise IT), Level 5 (Enterprise Network).
- **Where it applies:** OT/ICS Security page, Network Map tab.
- **Output or results:** Interactive Purdue Model diagram with asset placement, zone boundaries, and communication flows.
- **Related features:** OT Asset Inventory, IT/OT Boundary Monitoring.

### 22.4 IT/OT Boundary Monitoring

- **Feature Name:** IT/OT Boundary Security
- **What it does:** Monitors and enforces security at the IT/OT network boundary (DMZ), detecting unauthorized cross-zone communications.
- **How it works:** Tracks communication flows between IT (Level 4-5) and OT (Level 0-3) zones. Alerts on unauthorized cross-zone traffic, policy violations, and new communication paths.
- **Where it applies:** OT/ICS Security page, Boundary tab.
- **Integration points:** Alert Management, Network Security.
- **Output or results:** Boundary monitoring dashboard with traffic flow analysis, policy violations, and alert indicators.
- **Related features:** Purdue Model, Alert Management.

### 22.5 OT Vulnerability Tracking

- **Feature Name:** OT Vulnerability Management
- **What it does:** Tracks vulnerabilities specific to OT/ICS assets including firmware vulnerabilities, protocol weaknesses, and configuration issues.
- **How it works:** GET `/api/ot-ics/vulnerabilities` returns OT-specific vulnerability findings. Matches asset firmware versions against ICS-CERT advisories and vendor bulletins.
- **Where it applies:** OT/ICS Security page, Vulnerabilities tab.
- **Output or results:** Vulnerability findings with ICS-CERT advisory links, affected assets, and OT-safe remediation guidance.
- **Related features:** Vulnerability Scanner, Compliance.

### 22.6 OT Alerts

- **Feature Name:** OT Security Alerts
- **What it does:** Dedicated alert management for OT/ICS security events with OT-specific context and response procedures.
- **How it works:** OT alerts are tagged with OT context (Purdue level, protocol, asset type) and routed to OT-specific response workflows.
- **Where it applies:** OT/ICS Security page, Alerts tab.
- **Integration points:** Alert Management, OT Playbooks.
- **Output or results:** OT-contextualized alert queue with protocol and zone information.
- **Related features:** Alert Management, OT Playbooks.

### 22.7 OT Settings

- **Feature Name:** OT/ICS Configuration
- **What it does:** Configures OT security monitoring parameters including protocol parsers, detection sensitivity, and zone definitions.
- **How it works:** Settings page for OT module configuration.
- **Where it applies:** OT/ICS Security page, Settings tab.
- **Output or results:** Configuration forms for OT monitoring parameters.
- **Related features:** All OT/ICS features.

---

## 23. Email Security

**Source:** `client/src/pages/email-security.tsx`, `server/routes/email-security.ts`

### 23.1 BEC (Business Email Compromise) Detection

- **Feature Name:** BEC Detection
- **What it does:** Detects Business Email Compromise attacks by analyzing email patterns, sender behavior, and content for indicators of impersonation, urgency manipulation, and financial fraud.
- **How it works:** Analyzes email metadata and content for BEC indicators: executive impersonation (display name spoofing, lookalike domains), urgency keywords, wire transfer requests, and deviation from normal communication patterns.
- **Where it applies:** Email Security page, BEC tab.
- **Integration points:** Alert Management, Threat Intelligence, Identity Governance.
- **Output or results:** BEC detection alerts with confidence scores, impersonation indicators, and recommended actions.
- **Related features:** Alert Management, Threat Intelligence.

### 23.2 Thread Injection Detection

- **Feature Name:** Thread Hijacking Detection
- **What it does:** Detects email thread injection attacks where attackers insert themselves into existing email conversations using stolen or compromised credentials.
- **How it works:** Monitors email threads for anomalous participant additions, sudden topic shifts, and link/attachment insertions that deviate from thread context.
- **Where it applies:** Email Security page.
- **Integration points:** Alert Management, Identity Governance.
- **Output or results:** Thread injection alerts with affected conversation details and injected content analysis.
- **Related features:** BEC Detection, Alert Management.

### 23.3 Retroactive IOC Scanning

- **Feature Name:** Retroactive Email IOC Scan
- **What it does:** Scans previously delivered emails against newly discovered IOCs to identify past exposure to threats that were not known at delivery time.
- **How it works:** When new IOCs are added to the threat intelligence database, the retroactive scanner checks historical email logs for matching indicators (URLs, domains, file hashes, sender addresses).
- **Where it applies:** Email Security page.
- **Integration points:** Threat Intelligence (IOC updates), Email Provider (M365/Gmail API).
- **Output or results:** Retroactive match alerts with affected emails, recipients, and exposure timeline.
- **Related features:** Threat Intelligence, IOC Management.

### 23.4 Email Provider Integration

- **Feature Name:** M365/Gmail Integration
- **What it does:** Integrates with Microsoft 365 and Google Workspace for email security monitoring, providing visibility into email flow, authentication results, and threat detections.
- **How it works:** API integration with M365 Graph API and Gmail API for email metadata retrieval, authentication result analysis (SPF, DKIM, DMARC), and quarantine management.
- **Where it applies:** Email Security page, Integration tab.
- **Configuration options:** Provider selection (M365/Gmail), API credentials, scan scope.
- **Output or results:** Email provider connection status with sync metrics and authentication result dashboards.
- **Related features:** BEC Detection, Retroactive Scanning.

### 23.5 Email Quarantine Management

- **Feature Name:** Email Quarantine
- **What it does:** Manages quarantined emails that were flagged by security policies, allowing review, release, or permanent block.
- **How it works:** Quarantined email management via email security endpoints. Supports review of quarantined messages, release to recipient, or permanent block with sender feedback.
- **Where it applies:** Email Security page.
- **Output or results:** Quarantine queue with email previews, sender details, and release/block actions.
- **Related features:** Email Provider Integration.

---

## 24. DNS Security

**Source:** `client/src/pages/dns-security.tsx`, `server/routes/dns-security.ts`

### 24.1 DNS Query Monitoring

- **Feature Name:** DNS Query Analytics
- **What it does:** Monitors and analyzes DNS queries across the network to detect suspicious patterns, data exfiltration via DNS tunneling, and connections to malicious domains.
- **How it works:** DNS query logs are ingested and analyzed for anomalous patterns: high-entropy subdomains (tunneling indicator), queries to newly registered domains, excessive NXDOMAIN responses, and fast-flux DNS patterns.
- **Where it applies:** DNS Security page.
- **Integration points:** Alert Management, Threat Intelligence (malicious domain lists).
- **Output or results:** DNS analytics dashboard with query volume charts, anomaly indicators, and top queried domains.
- **Related features:** Alert Management, Threat Intelligence.

### 24.2 DNS Tunneling Detection

- **Feature Name:** DNS Tunneling Detection
- **What it does:** Detects data exfiltration and C2 communication channels hidden within DNS queries using entropy analysis and pattern recognition.
- **How it works:** Analyzes DNS query patterns for tunneling indicators: high subdomain entropy, large TXT record responses, periodic query patterns, and unusual record type usage.
- **Where it applies:** DNS Security page.
- **Integration points:** Alert Management, Data Loss Prevention.
- **Output or results:** Tunneling detection alerts with suspected domains, traffic patterns, and confidence scores.
- **Related features:** Alert Management, Data Loss Prevention.

### 24.3 Malicious Domain Blocking

- **Feature Name:** DNS Threat Feed Blocking
- **What it does:** Blocks DNS resolution for known malicious domains based on threat intelligence feeds.
- **How it works:** Maintains a blocklist of malicious domains from threat intelligence feeds. DNS queries matching blocklist entries are logged and optionally blocked or redirected.
- **Where it applies:** DNS Security page.
- **Integration points:** Threat Intelligence, DNS Infrastructure.
- **Configuration options:** Block mode (block/redirect/log-only), blocklist sources, whitelist exceptions.
- **Output or results:** Block statistics with top blocked domains and category breakdowns.
- **Related features:** Threat Intelligence, Alert Management.

### 24.4 DNS Security Policies

- **Feature Name:** DNS Policy Engine
- **What it does:** Defines and enforces DNS security policies for query filtering, category blocking, and access control.
- **How it works:** Policy CRUD for DNS security rules. Policies define conditions (query patterns, domain categories) and actions (allow, block, redirect, alert).
- **Where it applies:** DNS Security page.
- **Output or results:** Policy management interface with enforcement statistics.
- **Related features:** DNS Query Monitoring.

### 24.5 DNS Metrics Dashboard

- **Feature Name:** DNS Security Metrics
- **What it does:** Aggregated metrics for DNS security including total queries, blocked domains, tunneling attempts, and policy enforcement statistics.
- **How it works:** Dashboard endpoint aggregates DNS query statistics, block counts, and detection metrics.
- **Where it applies:** DNS Security page, Dashboard tab.
- **Output or results:** KPI cards and charts for DNS security posture.
- **Related features:** Security Metrics Intelligence.

---

## 25. Browser Defense

**Source:** `client/src/pages/browser-defense.tsx`

### 25.1 Browser Extension Monitoring

- **Feature Name:** Browser Extension Security
- **What it does:** Monitors and manages browser extensions across the organization, detecting potentially malicious or vulnerable extensions.
- **How it works:** Collects browser extension inventories from managed endpoints. Evaluates extensions against security policies, permission scopes, and known malicious extension databases.
- **Where it applies:** Browser Defense page.
- **Integration points:** Native Sensors (browser extension collection), Alert Management.
- **Configuration options:** Extension allowlist/blocklist, permission scope limits.
- **Output or results:** Extension inventory with risk scores, permission analysis, and policy compliance.
- **Related features:** Native Sensors, Alert Management.

### 25.2 Web Content Filtering

- **Feature Name:** Web Content Filtering
- **What it does:** Enforces web content access policies based on URL categories, reputation scores, and threat intelligence.
- **How it works:** URL requests are evaluated against category databases and threat intelligence. Blocked or flagged URLs generate alerts.
- **Where it applies:** Browser Defense page.
- **Integration points:** DNS Security, Threat Intelligence.
- **Output or results:** Content filtering statistics with category breakdowns and block counts.
- **Related features:** DNS Security, Threat Intelligence.

---

## 26. API Security

**Source:** `client/src/pages/api-security.tsx`, `server/routes/api-security.ts`

### 26.1 API Inventory Discovery

- **Feature Name:** API Inventory
- **What it does:** Discovers and maintains an inventory of all APIs (internal and external) with endpoint details, authentication methods, and traffic patterns.
- **How it works:** CRUD via `/api/api-security/inventory`. APIs are discovered through traffic analysis and manual registration. Each API entry includes endpoint URL, method, authentication type, data classification, owner, and traffic statistics.
- **Where it applies:** API Security page, Inventory tab.
- **Integration points:** Developer Security (CI API scanning), CSPM (cloud API endpoints).
- **Output or results:** API inventory table with endpoint details, authentication status, and traffic indicators.
- **Related features:** Developer Security, CSPM.

### 26.2 API Schema Validation

- **Feature Name:** Schema Validation
- **What it does:** Validates API requests and responses against defined schemas (OpenAPI/Swagger) to detect schema violations and parameter abuse.
- **How it works:** POST validation endpoint checks API traffic against stored schemas. Detects unexpected parameters, type mismatches, missing required fields, and payload size anomalies.
- **Where it applies:** API Security page, Schema tab.
- **Configuration options:** Schema upload (OpenAPI 3.x), validation strictness level.
- **Output or results:** Schema violation alerts with affected endpoints, violation details, and request samples.
- **Related features:** Alert Management.

### 26.3 API Abuse Detection

- **Feature Name:** API Abuse Detection
- **What it does:** Detects API abuse patterns including credential stuffing, enumeration attacks, scraping, and rate limit evasion.
- **How it works:** Analyzes API traffic patterns for abuse indicators: abnormal request rates, systematic parameter variation (enumeration), authentication failure patterns, and geographic anomalies.
- **Where it applies:** API Security page, Abuse tab.
- **Integration points:** Alert Management, Rate Limiting.
- **Output or results:** Abuse detection alerts with attack pattern classification, source identification, and blocking recommendations.
- **Related features:** Alert Management, Rate Limiting.

### 26.4 Sensitive Data Scanning

- **Feature Name:** API Data Exposure Scanning
- **What it does:** Scans API responses for sensitive data exposure (PII, credentials, tokens) that may indicate data leakage vulnerabilities.
- **How it works:** Analyzes API response bodies using regex patterns and ML classifiers to detect sensitive data types: SSN, credit card numbers, API keys, passwords, email addresses, phone numbers.
- **Where it applies:** API Security page, Data tab.
- **Integration points:** Privacy Engineering, Data Loss Prevention.
- **Output or results:** Data exposure findings with affected endpoints, data types detected, and remediation guidance.
- **Related features:** Privacy Engineering, Data Loss Prevention.

### 26.5 DAST (Dynamic Application Security Testing)

- **Feature Name:** API DAST Scanner
- **What it does:** Performs dynamic security testing of APIs, probing for common vulnerabilities (injection, authentication bypass, SSRF, IDOR).
- **How it works:** POST to DAST scan endpoint initiates automated testing. Scanner sends crafted requests to API endpoints testing for: SQL injection, command injection, SSRF, IDOR, authentication bypass, and broken access controls.
- **Where it applies:** API Security page, DAST tab.
- **Output or results:** DAST findings with vulnerability type, affected endpoint, proof-of-concept, and remediation guidance.
- **Related features:** Developer Security, Vulnerability Scanner.

### 26.6 Shadow API Detection

- **Feature Name:** Shadow API Discovery
- **What it does:** Identifies undocumented or shadow APIs that exist in the environment but are not part of the official API inventory.
- **How it works:** Traffic analysis identifies API endpoints receiving requests that are not in the registered API inventory. These shadow APIs are flagged for review and documentation.
- **Where it applies:** API Security page.
- **Output or results:** Shadow API findings with discovered endpoints, traffic patterns, and registration prompts.
- **Related features:** API Inventory.

---

## 27. Developer Security (Shift-Left)

**Source:** `client/src/pages/developer-security.tsx`, `server/routes/developer-security.ts`

### 27.1 SAST Engine

- **Feature Name:** Static Application Security Testing
- **What it does:** Performs static analysis of source code to detect security vulnerabilities, insecure coding patterns, and potential exploits before deployment.
- **How it works:** SAST scan endpoint accepts repository URLs or code snippets. Analysis engine checks for: injection vulnerabilities, hardcoded secrets, insecure cryptography, path traversal, XSS patterns, and unsafe deserialization.
- **Where it applies:** Developer Security page, SAST tab.
- **Integration points:** CI/CD pipelines (GitHub Actions, GitLab CI), Developer workflows.
- **Configuration options:** Language support, severity thresholds, rule customization.
- **Output or results:** SAST findings with vulnerability type, affected code location, severity, and fix suggestions.
- **Related features:** CI Gates, Code Review Assistant.

### 27.2 Secret Scanning

- **Feature Name:** Secret Detection
- **What it does:** Scans source code and configurations for exposed secrets (API keys, passwords, tokens, certificates, private keys).
- **How it works:** Pattern-based and entropy-based scanning of code repositories. Detects known secret formats (AWS keys, GitHub tokens, Stripe keys) and high-entropy strings that may be secrets.
- **Where it applies:** Developer Security page, Secrets tab.
- **Integration points:** CI/CD pipelines, Repository Management.
- **Configuration options:** Custom secret patterns, allowlist for known false positives.
- **Output or results:** Secret findings with location, type classification, and remediation steps (rotation guidance).
- **Related features:** SAST, CI Gates.

### 27.3 CI Security Gates

- **Feature Name:** CI Pipeline Gates
- **What it does:** Enforces security quality gates in CI/CD pipelines, blocking deployments that don't meet security thresholds.
- **How it works:** CI gate configurations define pass/fail criteria based on SAST finding severity, secret scan results, and dependency vulnerability counts. Pipeline integration via GitHub Actions and GitLab CI.
- **Where it applies:** Developer Security page, CI Gates tab.
- **Integration points:** GitHub Actions, GitLab CI, SAST, Secret Scanning.
- **Configuration options:** Severity thresholds (block on critical/high), exception management, grace periods.
- **Output or results:** CI gate configuration panel with pipeline status indicators and recent gate decisions.
- **Related features:** SAST, Secret Scanning.

### 27.4 GitHub/GitLab Integration

- **Feature Name:** SCM Integration
- **What it does:** Integrates with GitHub and GitLab for automated security scanning on pull requests, commit monitoring, and repository management.
- **How it works:** OAuth/webhook integration with GitHub and GitLab. Automatically scans code changes on PR creation, comments findings on PRs, and tracks security debt per repository.
- **Where it applies:** Developer Security page, Integrations tab.
- **Configuration options:** Repository selection, scan triggers, comment behavior.
- **Output or results:** Connected repository list with scan status and finding counts.
- **Related features:** SAST, Secret Scanning, CI Gates.

### 27.5 Code Review Assistant

- **Feature Name:** AI Code Review
- **What it does:** AI-powered code review that identifies security issues in code changes and suggests secure alternatives.
- **How it works:** Uses Claude AI to analyze code diffs for security implications. Provides inline comments with vulnerability explanations and fix suggestions.
- **Where it applies:** Developer Security page, pull request integration.
- **Integration points:** AI Engine, GitHub/GitLab integration.
- **Output or results:** AI-generated code review comments with security findings and fix suggestions.
- **Related features:** AI Engine, SCM Integration.

### 27.6 Security Debt Tracker

- **Feature Name:** Security Debt Management
- **What it does:** Tracks accumulated security technical debt across repositories with prioritization, age tracking, and trend analysis.
- **How it works:** Aggregates unresolved security findings across all repositories. Tracks finding age, severity trends, and team remediation velocity.
- **Where it applies:** Developer Security page, Debt tab.
- **Output or results:** Security debt dashboard with aging charts, severity breakdowns, and team leaderboards.
- **Related features:** SAST, Secret Scanning, Compliance.

---

## 28. Dark Web Monitoring

**Source:** `client/src/pages/dark-web-monitoring.tsx`, `server/routes/dark-web-monitoring.ts`

### 28.1 Credential Exposure Monitoring

- **Feature Name:** Credential Leak Detection
- **What it does:** Monitors dark web sources for exposed organizational credentials (email/password pairs, API keys, session tokens) from data breaches.
- **How it works:** CRUD via `/api/dark-web/exposures`. Monitors configured email domains for appearances in breach databases and dark web marketplaces. Each exposure includes breach source, affected credential types, and exposure timestamp.
- **Where it applies:** Dark Web Monitoring page, Exposures tab.
- **Integration points:** Identity Governance (password reset triggers), Alert Management.
- **Configuration options:** Monitored domains, alert severity thresholds, auto-response actions.
- **Output or results:** Exposure findings with affected accounts, breach sources, and remediation actions (force password reset).
- **Related features:** Identity Governance, Alert Management.

### 28.2 Breach Intelligence Integration

- **Feature Name:** Breach Database Integration
- **What it does:** Integrates with breach intelligence services to check organizational accounts against known data breaches.
- **How it works:** Checks organizational email addresses against breach databases. Returns matched breaches with breach date, data types exposed, and source.
- **Where it applies:** Dark Web Monitoring page.
- **Integration points:** Threat Intelligence, Credential Exposure Monitoring.
- **Output or results:** Breach match results with affected accounts and exposed data types.
- **Related features:** Credential Exposure, Threat Intelligence.

### 28.3 Brand Monitoring

- **Feature Name:** Dark Web Brand Monitoring
- **What it does:** Monitors dark web forums, marketplaces, and paste sites for mentions of the organization's brand, products, and key personnel.
- **How it works:** Keyword monitoring across dark web sources for organization name, product names, executive names, and other brand indicators.
- **Where it applies:** Dark Web Monitoring page, Brand tab.
- **Output or results:** Brand mention alerts with source, context, and threat assessment.
- **Related features:** Threat Intelligence, Alert Management.

### 28.4 Threat Actor Tracking (Dark Web)

- **Feature Name:** Dark Web Threat Actor Monitoring
- **What it does:** Tracks threat actors active on dark web forums who may be targeting the organization or its industry.
- **How it works:** GET `/api/dark-web/actors` returns monitored threat actors with activity summaries, known aliases, and associated campaigns.
- **Where it applies:** Dark Web Monitoring page, Actors tab.
- **Integration points:** Threat Intelligence (threat actor profiles).
- **Output or results:** Threat actor cards with activity timelines, alias lists, and targeting indicators.
- **Related features:** Threat Intelligence, Threat Actor Profiles.

---

## 29. Community Threat Intelligence Network

**Source:** `client/src/pages/community-intel.tsx`, `server/routes/community-intel.ts`

### 29.1 Anonymous IOC Sharing

- **Feature Name:** IOC Sharing Network
- **What it does:** Enables organizations to anonymously share IOCs with the SecureNexus community for collective defense.
- **How it works:** POST to `/api/community-intel/iocs/share` submits IOCs to the shared pool. IOCs are anonymized (submitter identity removed) before distribution. Shared IOCs include type, value, confidence, and category.
- **Where it applies:** Community Intel page, Shared IOCs tab.
- **Integration points:** IOC Management, Threat Intelligence.
- **Configuration options:** Sharing frequency, auto-share criteria, IOC type filters.
- **Output or results:** Shared IOC feed with community confidence scores, usage statistics, and one-click import.
- **Related features:** IOC Management, Threat Intelligence.

### 29.2 Industry-Specific Feeds

- **Feature Name:** Industry Threat Feeds
- **What it does:** Provides curated threat intelligence feeds specific to industry verticals (Financial, Healthcare, Technology, Government, etc.).
- **How it works:** GET `/api/community-intel/industry-feeds` returns IOCs and threat reports filtered by the organization's industry classification.
- **Where it applies:** Community Intel page, Industry Feeds tab.
- **Configuration options:** Industry selection, feed subscription preferences.
- **Output or results:** Industry-specific IOC feeds with relevance scores.
- **Related features:** IOC Management, Threat Intelligence.

### 29.3 Campaign Correlation

- **Feature Name:** Community Campaign Correlation
- **What it does:** Correlates community-shared IOCs to identify coordinated attack campaigns affecting multiple organizations.
- **How it works:** Campaign deduplication and correlation engine groups related IOCs from multiple anonymous contributors into campaign objects.
- **Where it applies:** Community Intel page, Campaigns tab.
- **Output or results:** Campaign cards showing correlated IOCs, affected industry count, and timeline.
- **Related features:** Campaign Tracking, Threat Intelligence.

---

## 30. Security Chaos Engineering

**Source:** `client/src/pages/chaos-engineering.tsx`, `server/routes/chaos-engineering.ts`

### 30.1 BAS (Breach & Attack Simulation)

- **Feature Name:** Breach & Attack Simulation
- **What it does:** Simulates real-world attack techniques against the organization's defenses to validate detection and response capabilities.
- **How it works:** CRUD via `/api/chaos-engineering/simulations`. Simulations define attack scenarios mapped to MITRE ATT&CK techniques. Execution tests detection coverage, alert generation, and response times.
- **Where it applies:** Chaos Engineering page, Simulations tab.
- **Integration points:** Detection Rules (coverage validation), Alert Management (response verification), MITRE ATT&CK.
- **Configuration options:** Attack technique selection, scope/target, schedule, safe mode (non-destructive).
- **Output or results:** Simulation results with detection rate, response time, coverage gaps, and improvement recommendations.
- **Related features:** Detection Rules, MITRE ATT&CK.

### 30.2 Purple Team Automation

- **Feature Name:** Purple Team Exercises
- **What it does:** Automates combined red team (attack) and blue team (defense) exercises with coordinated scenarios and joint reporting.
- **How it works:** Purple team exercise definitions include attack playbooks, expected detections, and evaluation criteria. Automated execution runs attack steps and validates defense responses.
- **Where it applies:** Chaos Engineering page, Purple Team tab.
- **Output or results:** Exercise results with attack-defense correlation matrix and improvement recommendations.
- **Related features:** BAS, Detection Rules.

### 30.3 MITRE ATT&CK Coverage Heatmap (BAS)

- **Feature Name:** BAS Coverage Heatmap
- **What it does:** Visualizes detection coverage gaps identified through BAS testing mapped to the MITRE ATT&CK framework.
- **How it works:** Aggregates simulation results by MITRE technique to show which techniques are detected, partially detected, or missed by current defenses.
- **Where it applies:** Chaos Engineering page.
- **Output or results:** Color-coded MITRE matrix showing detection effectiveness per technique.
- **Related features:** MITRE ATT&CK, Detection Rules.

### 30.4 BAS Dashboard

- **Feature Name:** Chaos Engineering Dashboard
- **What it does:** Aggregated metrics for BAS program including total simulations, average detection rate, coverage score, and trend analysis.
- **How it works:** Dashboard endpoint aggregates simulation statistics and detection metrics.
- **Where it applies:** Chaos Engineering page, Dashboard tab.
- **Output or results:** KPI cards and charts for BAS program effectiveness.
- **Related features:** Security Metrics.

---

## 31. Privacy Engineering (DSPM++)

**Source:** `client/src/pages/privacy-engineering.tsx`, `server/routes/privacy-engineering.ts`

### 31.1 Data Discovery & Classification

- **Feature Name:** Automated Data Discovery
- **What it does:** Discovers and classifies sensitive data across databases, file systems, and cloud storage using pattern matching and ML-based classification.
- **How it works:** Data discovery scans connected data stores for sensitive data patterns (PII, PCI, PHI, credentials). Classification engine labels discovered data with sensitivity levels and regulatory categories.
- **Where it applies:** Privacy Engineering page, Discovery tab.
- **Integration points:** CSPM (cloud storage), Database connections, File systems.
- **Configuration options:** Scan scope, classification rules, sensitivity levels.
- **Output or results:** Data inventory with classification labels, sensitivity scores, and location details.
- **Related features:** CSPM DSPM, Data Residency.

### 31.2 Privacy Impact Assessments (PIAs)

- **Feature Name:** PIA Management
- **What it does:** Creates and manages Privacy Impact Assessments for data processing activities, ensuring compliance with GDPR, CCPA, and other privacy regulations.
- **How it works:** CRUD for PIA records. Each PIA includes processing activity description, data types, legal basis, risk assessment, and mitigation measures.
- **Where it applies:** Privacy Engineering page, PIAs tab.
- **Integration points:** Compliance (privacy regulations), Data Discovery.
- **Output or results:** PIA forms with risk scoring and compliance mapping.
- **Related features:** Compliance, Data Discovery.

### 31.3 Consent Management

- **Feature Name:** Consent Tracking
- **What it does:** Tracks and manages user consent for data processing activities across the organization's services.
- **How it works:** Consent records link users to specific processing activities with consent status, timestamp, and consent mechanism.
- **Where it applies:** Privacy Engineering page, Consent tab.
- **Integration points:** Identity Governance, Compliance.
- **Output or results:** Consent inventory with status tracking and compliance indicators.
- **Related features:** Compliance, Identity Governance.

### 31.4 Cross-Border Data Flow Analysis

- **Feature Name:** Cross-Border Risk Analysis
- **What it does:** Analyzes data flows across geographic boundaries to identify regulatory compliance risks under GDPR, LGPD, PDPA, and other cross-border regulations.
- **How it works:** Maps data flows between jurisdictions and evaluates against transfer mechanism requirements (SCCs, adequacy decisions, APEC CBPR).
- **Where it applies:** Privacy Engineering page, Cross-Border tab.
- **Integration points:** Data Residency, Compliance.
- **Output or results:** Cross-border flow map with compliance risk indicators and transfer mechanism recommendations.
- **Related features:** Data Residency, Compliance.

### 31.5 DSAR Automation

- **Feature Name:** Data Subject Access Request Automation
- **What it does:** Automates handling of data subject access requests (DSARs) including data collection, review, and response delivery.
- **How it works:** DSAR workflow management from request intake through data collection, review, redaction, and response delivery. Automated data discovery locates subject data across systems.
- **Where it applies:** Privacy Engineering page, DSARs tab.
- **Output or results:** DSAR management dashboard with request tracking, SLA timers, and fulfillment status.
- **Related features:** Data Discovery, Compliance.

### 31.6 Privacy Metrics Dashboard

- **Feature Name:** Privacy Metrics
- **What it does:** Aggregated metrics for privacy program including data inventory size, PIA completion rate, DSAR response times, and consent coverage.
- **How it works:** Dashboard aggregates privacy program statistics.
- **Where it applies:** Privacy Engineering page, Dashboard tab.
- **Output or results:** KPI cards and charts for privacy program health.
- **Related features:** Security Metrics.

---

## 32. Data Residency & Sovereignty

**Source:** `client/src/pages/data-residency.tsx`, `server/routes/data-residency.ts`

### 32.1 Region Selection

- **Feature Name:** Data Region Configuration
- **What it does:** Configures the geographic region where organizational data is stored, ensuring compliance with data sovereignty requirements.
- **How it works:** Per-organization region selection from supported regions (US, EU, Asia-Pacific, India, Brazil, etc.). Region setting is enforced at the middleware level, blocking cross-region data movement.
- **Where it applies:** Data Residency page, Region tab.
- **Integration points:** Compliance (GDPR, LGPD, PDPA), Infrastructure.
- **Configuration options:** Primary region selection, secondary/DR region.
- **Output or results:** Region configuration panel with compliance mapping.
- **Related features:** Compliance, Cross-Border Flow.

### 32.2 BYOK (Bring Your Own Key) Management

- **Feature Name:** Customer-Managed Encryption Keys
- **What it does:** Allows organizations to manage their own encryption keys for data-at-rest encryption, ensuring they maintain control over data access.
- **How it works:** CRUD via `/api/data-residency/encryption-keys`. Organizations can register their own KMS keys (AWS KMS, Azure Key Vault, GCP KMS) for data encryption. Key rotation management and usage tracking.
- **Where it applies:** Data Residency page, Encryption tab.
- **Configuration options:** KMS provider selection, key ARN/URI, rotation schedule.
- **Output or results:** Key inventory with rotation status, usage statistics, and compliance indicators.
- **Related features:** Compliance, Security Hardening.

### 32.3 Cross-Border Flow Controls

- **Feature Name:** Cross-Border Data Flow Enforcement
- **What it does:** Defines and enforces rules governing data movement across geographic boundaries with transfer mechanism validation.
- **How it works:** Flow control rules define allowed/blocked data transfers between regions. Each flow is evaluated against configured rules including transfer mechanism requirements (SCCs, adequacy). Fail-closed enforcement blocks unauthorized transfers.
- **Where it applies:** Data Residency page, Flow Controls tab.
- **Integration points:** Privacy Engineering (cross-border analysis), API middleware.
- **Configuration options:** Rule-based flow controls with source/destination regions, data types, and required transfer mechanisms.
- **Output or results:** Flow control rules with enforcement statistics and blocked transfer logs.
- **Related features:** Privacy Engineering, Compliance.

### 32.4 Residency Compliance Dashboard

- **Feature Name:** Residency Compliance
- **What it does:** Displays compliance status for data residency requirements across applicable regulations.
- **How it works:** Evaluates data storage locations and flow controls against regulatory requirements.
- **Where it applies:** Data Residency page, Dashboard tab.
- **Output or results:** Compliance status cards with regulatory mapping.
- **Related features:** Compliance, Data Region Configuration.

---

## 33. Security Data Lake

**Source:** `client/src/pages/data-lake.tsx`, `server/routes/data-lake.ts`

### 33.1 Cold Storage Tiering

- **Feature Name:** Data Tiering
- **What it does:** Automatically tiers security data between hot (active), warm (recent), and cold (archive) storage based on data age and access patterns.
- **How it works:** CRUD via `/api/data-lake/tiers`. Tier policies define criteria for data movement between tiers (hot -> warm after 30 days, warm -> cold after 90 days). Automated tiering runs on schedule.
- **Where it applies:** Data Lake page, Tiering tab.
- **Configuration options:** Tier definitions, age thresholds, storage class selection (S3 Standard, Glacier, Deep Archive).
- **Output or results:** Tier status dashboard with data volume per tier, transition history, and cost estimates.
- **Related features:** Retention Policies, Alert Archive.

### 33.2 Query Federation

- **Feature Name:** Federated Query Engine
- **What it does:** Enables SQL queries across all data tiers (hot, warm, cold) with transparent data retrieval from appropriate storage.
- **How it works:** Query engine routes queries to appropriate storage tier. Hot tier queries execute immediately. Warm/cold tier queries may require data retrieval from archive storage with associated latency.
- **Where it applies:** Data Lake page, Query tab.
- **Integration points:** Threat Hunting (query engine), Advanced Reporting.
- **Output or results:** Query results with data source indicators and retrieval time.
- **Related features:** Threat Hunting, Advanced Reporting.

### 33.3 Retention Policies

- **Feature Name:** Data Retention Management
- **What it does:** Defines and enforces data retention policies specifying how long different data types are kept, compliant with regulatory requirements.
- **How it works:** CRUD via `/api/data-lake/retention`. Retention policies define data categories, retention periods, and purge behaviors. Automated purge jobs run on schedule, with purge date computation hoisted for performance.
- **Where it applies:** Data Lake page, Retention tab.
- **Integration points:** Compliance (regulatory retention requirements).
- **Configuration options:** Data category, retention period, purge behavior (delete/archive), legal hold override.
- **Output or results:** Retention policy list with next purge dates and data volume estimates.
- **Related features:** Compliance, Legal Holds.

### 33.4 Legal Holds

- **Feature Name:** Legal Hold Management
- **What it does:** Places legal holds on specific data sets to prevent deletion during litigation or regulatory proceedings.
- **How it works:** CRUD via `/api/data-lake/legal-holds`. Legal holds override retention policies for specified data sets, preventing purge until hold is released.
- **Where it applies:** Data Lake page, Legal Holds tab.
- **Output or results:** Legal hold list with affected data sets, hold duration, and release controls.
- **Related features:** Retention Policies, Compliance.

### 33.5 eDiscovery

- **Feature Name:** eDiscovery Support
- **What it does:** Facilitates electronic discovery by providing search, collection, and export capabilities for security data in response to legal or regulatory requests.
- **How it works:** eDiscovery endpoints support targeted data searches, collection tagging, and export in standard formats.
- **Where it applies:** Data Lake page, eDiscovery tab.
- **Output or results:** eDiscovery workflow with search, collection, review, and export stages.
- **Related features:** Legal Holds, Query Federation.

### 33.6 Data Lake Statistics

- **Feature Name:** Data Lake Dashboard
- **What it does:** Displays aggregated data lake metrics including total volume, tier distribution, ingestion rates, and storage costs.
- **How it works:** Dashboard endpoint aggregates storage statistics across all tiers.
- **Where it applies:** Data Lake page, Overview tab.
- **Output or results:** KPI cards and charts for data lake health and capacity.
- **Related features:** Operations, Cost Management.

---

## 34. Third-Party Risk Management (TPRM)

**Source:** `client/src/pages/tprm.tsx`, `server/routes/tprm.ts`

### 34.1 Vendor Inventory

- **Feature Name:** Vendor Management
- **What it does:** Maintains a comprehensive inventory of third-party vendors with risk assessments, criticality ratings, and compliance status.
- **How it works:** CRUD via `/api/tprm/vendors`. Each vendor record includes name, category, criticality (critical, high, medium, low), risk score, contract details, data access level, and compliance certifications.
- **Where it applies:** TPRM page, Vendors tab.
- **Configuration options:** Criticality criteria, risk scoring weights, required certifications.
- **Output or results:** Vendor inventory table with risk scores, criticality badges, and compliance indicators.
- **Related features:** Vendor Questionnaires, Continuous Monitoring.

### 34.2 Questionnaire Automation

- **Feature Name:** Security Questionnaires
- **What it does:** Creates, sends, and manages security assessment questionnaires sent to vendors for risk evaluation.
- **How it works:** Questionnaire templates with security and compliance questions. Automated distribution to vendors via email. Response tracking with auto-scoring based on answers.
- **Where it applies:** TPRM page, Questionnaires tab.
- **Output or results:** Questionnaire management with response tracking, auto-scoring, and vendor risk assessment.
- **Related features:** Vendor Inventory, Risk Assessment.

### 34.3 Continuous Vendor Monitoring

- **Feature Name:** Vendor Monitoring
- **What it does:** Continuously monitors vendor security posture through external scanning, breach intelligence, and certificate monitoring.
- **How it works:** Automated monitoring sweeps check vendor domains for: SSL/TLS configuration, DNS security, data breach exposure, dark web mentions, and security header compliance. Results update vendor risk scores.
- **Where it applies:** TPRM page, Monitoring tab.
- **Integration points:** Dark Web Monitoring, DNS Security.
- **Output or results:** Monitoring dashboard with vendor health indicators and risk trend charts.
- **Related features:** Dark Web Monitoring, DNS Security.

### 34.4 Vendor Breach Alerting

- **Feature Name:** Vendor Breach Alerts
- **What it does:** Alerts when a third-party vendor experiences a data breach or security incident.
- **How it works:** Integration with breach intelligence services to monitor vendor domains. Breach detection triggers alerts with vendor impact assessment.
- **Where it applies:** TPRM page.
- **Integration points:** Alert Management, Dark Web Monitoring.
- **Output or results:** Vendor breach alert with impact assessment and response recommendations.
- **Related features:** Dark Web Monitoring, Alert Management.

### 34.5 Contract Risk Mapping

- **Feature Name:** Contract Risk Analysis
- **What it does:** Maps security and data protection obligations in vendor contracts, tracking compliance with contractual requirements.
- **How it works:** GET `/api/tprm/contract-risk-map` returns contract obligations by vendor. Each obligation includes requirement, compliance status, and evidence links.
- **Where it applies:** TPRM page, Contracts tab.
- **Output or results:** Contract obligation matrix with compliance status indicators.
- **Related features:** Vendor Inventory, Compliance.

### 34.6 Fourth-Party Risk

- **Feature Name:** Fourth-Party Risk Analysis
- **What it does:** Extends risk assessment beyond direct vendors to their subcontractors and service providers (fourth parties).
- **How it works:** GET `/api/tprm/fourth-party-risk` maps vendor dependency chains and assesses aggregate risk from downstream providers.
- **Where it applies:** TPRM page, Fourth-Party tab.
- **Output or results:** Fourth-party risk map showing vendor dependency chains and aggregate risk scores.
- **Related features:** Vendor Inventory, Risk Management.

---

## 35. Physical Security Convergence

**Source:** `client/src/pages/physical-security.tsx`, `server/routes/physical-security.ts`

### 35.1 Physical Asset Inventory

- **Feature Name:** Physical Security Assets
- **What it does:** Maintains an inventory of physical security assets including access control systems, cameras, sensors, and barriers.
- **How it works:** CRUD via `/api/physical-security/assets`. Asset types include: access control panels, CCTV cameras, motion sensors, badge readers, alarm systems, and environmental sensors.
- **Where it applies:** Physical Security page, Assets tab.
- **Output or results:** Asset inventory with type icons, location mapping, and status indicators.
- **Related features:** Zone Management, Access Events.

### 35.2 Zone Management

- **Feature Name:** Security Zone Definition
- **What it does:** Defines physical security zones with access requirements, monitoring levels, and alert thresholds.
- **How it works:** CRUD via `/api/physical-security/zones`. Zones define physical areas with access control requirements (badge level, biometric, escort), camera coverage, and alerting rules.
- **Where it applies:** Physical Security page, Zones tab.
- **Output or results:** Zone map with access requirements and monitoring status.
- **Related features:** Physical Assets, Access Events.

### 35.3 Access Events

- **Feature Name:** Physical Access Event Monitoring
- **What it does:** Monitors and logs physical access events (badge swipes, door openings, unauthorized access attempts) with correlation to logical security events.
- **How it works:** GET `/api/physical-security/events` returns access events. Correlation engine links physical access events with logical security events (VPN logins, workstation access) for holistic security analysis.
- **Where it applies:** Physical Security page, Events tab.
- **Integration points:** Identity Governance, Alert Management.
- **Output or results:** Access event timeline with correlation to logical events.
- **Related features:** Identity Governance, Alert Management.

### 35.4 Visitor Management

- **Feature Name:** Visitor Tracking
- **What it does:** Manages visitor check-in/out, badge issuance, and movement tracking within secured facilities.
- **How it works:** Visitor management endpoints handle pre-registration, check-in, badge assignment, escort requirements, and check-out. Time tracking for visitor presence.
- **Where it applies:** Physical Security page.
- **Output or results:** Visitor log with check-in/out times, host, and areas accessed.
- **Related features:** Zone Management, Access Events.

---

## 36. Phishing Simulation & Security Awareness

**Source:** `client/src/pages/phishing-simulation.tsx`, `server/routes/phishing-simulation.ts`

### 36.1 Phishing Campaign Management

- **Feature Name:** Phishing Simulation Campaigns
- **What it does:** Creates and manages phishing simulation campaigns to test employee security awareness and susceptibility to social engineering attacks.
- **How it works:** CRUD via `/api/phishing/campaigns`. Campaigns define target groups, email templates (customizable phishing lures), landing pages, and scheduling. Tracks email delivery, open rates, click rates, and credential submission rates.
- **Where it applies:** Phishing Simulation page, Campaigns tab.
- **Configuration options:** Target groups, email templates, landing pages, schedule, reporting period.
- **Output or results:** Campaign management dashboard with delivery stats, engagement metrics, and susceptibility scores.
- **Related features:** Security Awareness Training, Email Security.

### 36.2 Campaign Results & Analytics

- **Feature Name:** Phishing Results Dashboard
- **What it does:** Analyzes phishing simulation results with metrics for email opens, link clicks, credential submissions, and reporting rates by department.
- **How it works:** GET `/api/phishing/campaigns/:id/results` returns detailed engagement metrics. Dashboard shows org-wide averages, department comparisons, and individual user results.
- **Where it applies:** Phishing Simulation page, Results tab.
- **Output or results:** Results dashboard with funnel charts (sent -> opened -> clicked -> submitted), department heatmaps, and trend analysis.
- **Related features:** Security Awareness, Executive Dashboard.

### 36.3 Template Library

- **Feature Name:** Phishing Template Library
- **What it does:** Provides a library of customizable phishing email templates mimicking real-world attack patterns.
- **How it works:** GET `/api/phishing/templates` returns available templates. Templates include email body, subject line, sender name, and associated landing page. Custom templates can be created.
- **Where it applies:** Phishing Simulation page, Templates tab.
- **Output or results:** Template gallery with preview, customization, and usage statistics.
- **Related features:** Campaign Management.

### 36.4 Security Awareness Training

- **Feature Name:** Training Module Management
- **What it does:** Manages security awareness training content with course assignment, progress tracking, and completion certificates.
- **How it works:** GET `/api/phishing/training` returns available training modules. Modules cover phishing recognition, social engineering, password security, and data handling.
- **Where it applies:** Phishing Simulation page, Training tab.
- **Output or results:** Training catalog with assignment status, completion rates, and quiz scores.
- **Related features:** Phishing Simulation, Compliance.

### 36.5 Phishing Reporting

- **Feature Name:** Report Phishing Button
- **What it does:** Provides a mechanism for employees to report suspected phishing emails, tracking reporting rates as a positive security metric.
- **How it works:** Report button integration submits suspected phishing emails for analysis. Reported emails are checked against active simulation campaigns and real threat indicators.
- **Where it applies:** Email clients (browser extension/add-in).
- **Output or results:** Report confirmation with feedback (simulation or forwarded for analysis).
- **Related features:** Email Security, Security Awareness.

---

## 37. Quantum Readiness Assessment

**Source:** `client/src/pages/quantum-readiness.tsx`, `server/routes/quantum-readiness.ts`

### 37.1 Cryptographic Inventory

- **Feature Name:** Crypto Asset Discovery
- **What it does:** Discovers and catalogs all cryptographic algorithms, keys, and certificates used across the organization's systems.
- **How it works:** CRUD via `/api/quantum/inventory`. Inventory items include algorithm type (RSA, AES, ECC, SHA-2), key lengths, usage context, system/application, and quantum vulnerability assessment.
- **Where it applies:** Quantum Readiness page, Inventory tab.
- **Output or results:** Cryptographic inventory with quantum vulnerability ratings (Safe, At-Risk, Critical).
- **Related features:** PQC Migration, NIST Compliance.

### 37.2 Quantum Vulnerability Scoring

- **Feature Name:** Quantum Risk Assessment
- **What it does:** Scores cryptographic assets for quantum computing vulnerability based on algorithm type, key length, and data sensitivity.
- **How it works:** Scoring engine evaluates each cryptographic asset against known quantum computing threats. RSA and ECC are flagged as quantum-vulnerable. AES-256 and SHA-3 are rated as quantum-safe.
- **Where it applies:** Quantum Readiness page.
- **Output or results:** Vulnerability scores per cryptographic asset with migration urgency indicators.
- **Related features:** Cryptographic Inventory.

### 37.3 PQC Migration Planning

- **Feature Name:** Post-Quantum Cryptography Migration
- **What it does:** Creates and tracks migration plans for transitioning from quantum-vulnerable to quantum-safe cryptographic algorithms.
- **How it works:** CRUD via `/api/quantum/migration-tasks`. Migration tasks define the transition plan for each cryptographic asset, including target algorithm, timeline, dependencies, and status tracking. Safe count formula corrected to accurately reflect quantum-safe assets.
- **Where it applies:** Quantum Readiness page, Migration tab.
- **Output or results:** Migration task board with status tracking, dependency mapping, and timeline visualization.
- **Related features:** Cryptographic Inventory, Compliance.

### 37.4 NIST PQC Compliance

- **Feature Name:** NIST Standards Compliance
- **What it does:** Maps the organization's quantum readiness posture against NIST post-quantum cryptography standards and recommendations.
- **How it works:** Evaluates cryptographic inventory against NIST PQC recommended algorithms (CRYSTALS-Kyber, CRYSTALS-Dilithium, SPHINCS+, FALCON).
- **Where it applies:** Quantum Readiness page, Compliance tab.
- **Output or results:** NIST compliance assessment with gap analysis and remediation recommendations.
- **Related features:** Compliance, Cryptographic Inventory.

---

## 38. Security Posture Score & Trust Center

**Source:** `client/src/pages/security-posture-score.tsx`, `server/routes/security-posture-score.ts`

### 38.1 Real-Time Security Score

- **Feature Name:** Security Posture Score
- **What it does:** Calculates a comprehensive, real-time security posture score based on weighted inputs from all security domains.
- **How it works:** GET `/api/security-posture/score` aggregates scores from: alert severity, vulnerability remediation rate, compliance coverage, detection rule coverage, sensor deployment, and configuration hardening. Weighted scoring produces a composite score (0-100).
- **Where it applies:** Security Posture Score page, SOC Dashboard.
- **Output or results:** Composite security score with factor breakdown, trend chart, and improvement recommendations.
- **Related features:** SOC Dashboard Security Score, Compliance.

### 38.2 Peer Benchmarking

- **Feature Name:** Industry Peer Comparison
- **What it does:** Compares the organization's security posture score against anonymized peer organizations in the same industry and size bracket.
- **How it works:** GET `/api/security-posture/benchmarks` returns peer comparison data. Scores are compared against industry averages, top performers, and bottom performers.
- **Where it applies:** Security Posture Score page, Benchmarking tab.
- **Output or results:** Benchmark comparison charts showing percentile ranking against peers.
- **Related features:** Security Posture Score, Community Intel.

### 38.3 Public Trust Center

- **Feature Name:** Trust Center Portal
- **What it does:** Provides a public-facing trust center page where customers can view the organization's security certifications, compliance status, and security practices.
- **How it works:** GET `/api/security-posture/trust-center` returns public trust center data. Displays compliance certifications, SOC 2 reports, security policies, and uptime metrics.
- **Where it applies:** Security Posture Score page, Trust Center tab; public URL.
- **Configuration options:** Content selection, branding, public URL configuration.
- **Output or results:** Public trust center page with certification badges, compliance status, and security documentation.
- **Related features:** Compliance, MSSP White-Label.

### 38.4 Questionnaire Automation (Trust)

- **Feature Name:** Security Questionnaire Response
- **What it does:** Automates responses to security questionnaires from customers and partners by pre-populating answers from the trust center data.
- **How it works:** Questionnaire engine matches incoming questions against a knowledge base of pre-approved answers. Auto-populates responses for common security assessment questions.
- **Where it applies:** Security Posture Score page, Questionnaires tab.
- **Output or results:** Automated questionnaire responses with review/edit capability before submission.
- **Related features:** Trust Center, Compliance.

### 38.5 Score Trends

- **Feature Name:** Posture Score Trends
- **What it does:** Tracks security posture score changes over time with historical trend analysis and change attribution.
- **How it works:** Historical score data with change attribution showing which factors drove score increases or decreases.
- **Where it applies:** Security Posture Score page, Trends tab.
- **Output or results:** Time-series chart of posture score with change annotations and factor attribution.
- **Related features:** Security Posture Score, Security Metrics.

---

## 39. Compliance & Governance

**Source:** `client/src/pages/compliance.tsx` (3202 lines), `server/routes/compliance.ts` (1673 lines)

### 39.1 Compliance Framework Management

- **Feature Name:** Framework Support
- **What it does:** Manages multiple compliance frameworks with control mapping, evidence collection, and audit readiness tracking.
- **How it works:** Supports 15+ compliance frameworks: SOC 2, ISO 27001, PCI DSS, HIPAA, NIST CSF, NIST 800-53, GDPR, NIS2, DORA, CBEST, MAS TRM, IFSCA, PDPA, POPIA, LGPD, PIPEDA, ASD Essential 8, CCPA/CPRA, CMMC, NERC CIP, SWIFT CSP, IEC 62443. Each framework has controls mapped to platform features.
- **Where it applies:** Compliance page.
- **Integration points:** All security modules (evidence sources), Audit Log.
- **Output or results:** Framework cards with compliance percentage, control status, and gap indicators.
- **Related features:** All security features (evidence contributors).

### 39.2 Compliance Controls

- **Feature Name:** Control Management
- **What it does:** Maps compliance framework requirements to platform controls with implementation status and evidence linking.
- **How it works:** Controls tab displays all requirements for a selected framework. Each control shows: requirement text, implementation status (not started, in progress, implemented, not applicable), evidence items, and responsible party.
- **Where it applies:** Compliance page, Controls tab.
- **Configuration options:** Framework selection, control status updates, evidence linking.
- **Output or results:** Control matrix with status badges, evidence counts, and gap analysis.
- **Related features:** Framework Management, Evidence Collection.

### 39.3 Compliance Evidence Collection

- **Feature Name:** Evidence Management
- **What it does:** Collects, manages, and links evidence artifacts to compliance controls for audit readiness.
- **How it works:** Evidence items are created/uploaded and linked to specific compliance controls. Evidence types include: screenshots, configuration exports, policy documents, log excerpts, and automated scan results.
- **Where it applies:** Compliance page, Evidence tab.
- **Output or results:** Evidence library with control linkage and audit readiness indicators.
- **Related features:** Audit Log, Advanced Reporting.

### 39.4 Compliance Task Management

- **Feature Name:** Compliance Tasks
- **What it does:** Tracks compliance remediation tasks with assignees, due dates, and priority levels.
- **How it works:** Tasks are created for compliance gaps and assigned to team members. Task status tracking with due date reminders and escalation rules.
- **Where it applies:** Compliance page, Tasks tab.
- **Output or results:** Task board with status tracking and due date indicators.
- **Related features:** Team Management.

### 39.5 Audit Log (Compliance)

- **Feature Name:** Comprehensive Audit Log
- **What it does:** Maintains a complete, org-scoped audit trail of all platform actions for compliance and forensic purposes.
- **How it works:** Every user action is logged with actor, action type, timestamp, resource, and details. Category-based filtering supports: authentication, authorization, data access, configuration changes, alert management, incident management, and system events.
- **Where it applies:** Compliance page, Audit Log tab; Settings page.
- **Integration points:** All platform features (log sources).
- **Configuration options:** Log retention period, export format.
- **Output or results:** Searchable, filterable audit log with export capability.
- **Related features:** All platform features.

### 39.6 Compliance Reporting

- **Feature Name:** Compliance Reports
- **What it does:** Generates compliance status reports for specific frameworks, suitable for auditor review and management reporting.
- **How it works:** Report generation aggregates control status, evidence items, and gap analysis into formatted reports. Supports PDF export with organization branding.
- **Where it applies:** Compliance page, Reports tab.
- **Output or results:** Formatted compliance reports with control matrices, evidence summaries, and gap analysis.
- **Related features:** Advanced Reporting, Framework Management.

---

## 40. Advanced Reporting Engine

**Source:** `client/src/pages/advanced-reporting.tsx`, `server/routes/advanced-reporting.ts`

### 40.1 Report Template Library

- **Feature Name:** Report Templates
- **What it does:** Provides a library of pre-built and custom report templates for security, compliance, and executive reporting.
- **How it works:** GET `/api/reports/templates` returns available templates. Templates define report structure, data sources, visualizations, and formatting. Custom templates can be created from scratch or by modifying existing ones.
- **Where it applies:** Advanced Reporting page, Templates tab.
- **Configuration options:** Template customization (sections, data sources, visualizations), scheduling, distribution lists.
- **Output or results:** Template library with preview, customization, and one-click generation.
- **Related features:** Compliance Reporting, Executive Dashboard.

### 40.2 PDF Report Generation with Charts

- **Feature Name:** PDF Report Engine
- **What it does:** Generates professional PDF reports with charts, tables, branding, and letterhead for distribution to stakeholders and auditors.
- **How it works:** Server-side PDF generation using template rendering with embedded charts. Reports include organization branding, confidentiality notices, and professional formatting. Binary download endpoint serves the generated PDF.
- **Where it applies:** Advanced Reporting page.
- **Integration points:** All data sources (alerts, incidents, compliance, posture).
- **Output or results:** Downloadable PDF reports with charts, tables, and branding.
- **Related features:** Compliance Reporting, Executive Dashboard.

### 40.3 White-Label Reports

- **Feature Name:** White-Label Branding
- **What it does:** Customizes report branding with organization logos, colors, and contact information for client-facing deliverables.
- **How it works:** White-label configuration allows overriding default branding with organization-specific logos, color schemes, and contact details. Applied to all generated reports.
- **Where it applies:** Advanced Reporting page; MSSP partner reports.
- **Configuration options:** Logo upload, color scheme, company name, contact info, confidentiality notice.
- **Output or results:** Branded reports with custom letterhead and styling.
- **Related features:** MSSP White-Label.

### 40.4 Compliance Report Templates

- **Feature Name:** Compliance Report Templates
- **What it does:** Pre-built report templates for specific compliance frameworks (SOC 2, ISO 27001, PCI DSS, HIPAA, GDPR).
- **How it works:** Compliance-specific templates pull data from compliance controls, evidence, and audit logs. Reports include control matrices, evidence summaries, and gap analysis.
- **Where it applies:** Advanced Reporting page.
- **Output or results:** Framework-specific compliance reports ready for auditor review.
- **Related features:** Compliance, Audit Log.

### 40.5 Financial Impact Reporting

- **Feature Name:** Financial Impact Analysis
- **What it does:** Estimates the financial impact of security incidents and risk reduction from security investments.
- **How it works:** Financial impact calculations based on incident severity, affected asset value, downtime duration, and regulatory penalties. ROI analysis for security program investments.
- **Where it applies:** Advanced Reporting page; Executive Dashboard.
- **Output or results:** Financial impact reports with cost estimates, ROI analysis, and trend charts.
- **Related features:** Executive Dashboard, Security Metrics.

### 40.6 Scheduled Report Distribution

- **Feature Name:** Report Scheduling
- **What it does:** Automates report generation and distribution on configurable schedules (daily, weekly, monthly) to specified recipients.
- **How it works:** Report schedules define template, generation frequency, recipient list, and delivery method (email, dashboard).
- **Where it applies:** Advanced Reporting page.
- **Configuration options:** Schedule (cron), recipients, delivery method, format (PDF/HTML).
- **Output or results:** Schedule management with delivery history and next-run indicators.
- **Related features:** Email (SES), Notification Channels.

### 40.7 Confidential Report Classification

- **Feature Name:** Report Confidentiality
- **What it does:** Classifies reports with confidentiality levels (Public, Internal, Confidential, Restricted) and enforces access controls accordingly.
- **How it works:** CONFIDENTIAL_REPORT_TYPES constant defines which report types are automatically classified as confidential. Reports include confidentiality headers and access restrictions.
- **Where it applies:** Advanced Reporting page.
- **Output or results:** Confidentiality labels on reports with access control enforcement.
- **Related features:** RBAC, Data Classification.

---

## 41. Executive Risk Dashboard

**Source:** `client/src/pages/board-dashboard.tsx`, `server/routes/dashboard.ts`

### 41.1 Board-Level Risk Overview

- **Feature Name:** Executive Risk Dashboard
- **What it does:** Provides a board-level view of organizational cyber risk with business-focused metrics, financial impact estimates, and risk trend analysis designed for non-technical executive audiences.
- **How it works:** GET `/api/dashboard/board` aggregates high-level risk metrics: overall risk score, top risk categories, financial exposure estimates, regulatory compliance status, and incident trend analysis. Presented with simplified visualizations suitable for board presentations.
- **Where it applies:** Executive Risk Dashboard page (board-dashboard).
- **Integration points:** Security Posture Score, Compliance, Incident Management, Financial Impact.
- **Output or results:** Executive summary dashboard with risk score gauge, financial exposure chart, compliance status cards, and trend indicators.
- **Related features:** Security Posture Score, Compliance, Financial Impact Reporting.

### 41.2 Risk Heat Map

- **Feature Name:** Risk Category Heat Map
- **What it does:** Visualizes risk levels across business domains as a color-coded heat map showing likelihood vs. impact.
- **How it works:** Maps security risks to business domains with likelihood and impact assessments. Renders as a matrix with color coding (green/yellow/orange/red).
- **Where it applies:** Executive Risk Dashboard.
- **Output or results:** Interactive heat map with drill-down to risk details per category.
- **Related features:** Security Posture Score.

### 41.3 Regulatory Compliance Summary

- **Feature Name:** Compliance Scorecard
- **What it does:** Summarizes compliance posture across all active regulatory frameworks in a single view for executive reporting.
- **How it works:** Aggregates compliance percentages from all active frameworks and presents as a scorecard.
- **Where it applies:** Executive Risk Dashboard.
- **Output or results:** Compliance scorecard with framework-by-framework status and trend indicators.
- **Related features:** Compliance & Governance.

### 41.4 Incident Impact Summary

- **Feature Name:** Incident Business Impact
- **What it does:** Summarizes the business impact of security incidents including downtime, financial loss, and reputational risk.
- **How it works:** Aggregates incident severity, duration, affected assets, and estimated financial impact.
- **Where it applies:** Executive Risk Dashboard.
- **Output or results:** Incident impact summary with financial estimates and trend analysis.
- **Related features:** Incident Management, Financial Impact.

---

## 42. Security Metrics Intelligence

**Source:** `client/src/pages/security-metrics.tsx`, `server/routes/security-metrics.ts`

### 42.1 MTTD (Mean Time to Detect)

- **Feature Name:** MTTD Tracking
- **What it does:** Measures and tracks the average time between threat occurrence and detection across the organization.
- **How it works:** Calculates the time delta between estimated threat start (from timeline analysis) and first alert generation. Aggregates across all incidents for rolling averages.
- **Where it applies:** Security Metrics page, SOC Dashboard.
- **Output or results:** MTTD metric with trend chart and breakdown by threat category.
- **Related features:** Alert Management, Incident Management.

### 42.2 MTTR (Mean Time to Respond)

- **Feature Name:** MTTR Tracking
- **What it does:** Measures and tracks the average time between detection and incident resolution.
- **How it works:** Calculates time delta between first alert and incident closure. Tracks by incident severity and category for trending analysis.
- **Where it applies:** Security Metrics page, SOC Dashboard.
- **Output or results:** MTTR metric with trend chart and breakdown by severity and category.
- **Related features:** Incident Management, Playbooks.

### 42.3 Alert-to-Incident Ratio

- **Feature Name:** Alert Efficiency Metrics
- **What it does:** Tracks the ratio of alerts that result in confirmed incidents, measuring alert quality and triage effectiveness.
- **How it works:** Calculates the percentage of alerts that are escalated to incidents vs. dismissed as false positives or benign.
- **Where it applies:** Security Metrics page.
- **Output or results:** Ratio metrics with trend charts and breakdown by alert source.
- **Related features:** Alert Management, AI Triage.

### 42.4 SOC Analyst Workload

- **Feature Name:** Analyst Workload Metrics
- **What it does:** Tracks SOC analyst workload including alerts per analyst, incidents per analyst, and response time by analyst.
- **How it works:** Aggregates alert and incident assignment data by analyst. Tracks individual and team-level workload metrics.
- **Where it applies:** Security Metrics page.
- **Output or results:** Workload distribution charts with per-analyst metrics and team averages.
- **Related features:** Team Management, Alert Management.

### 42.5 Detection Coverage Score

- **Feature Name:** Detection Coverage
- **What it does:** Measures the organization's detection capability coverage across MITRE ATT&CK techniques.
- **How it works:** Maps active detection rules and sensor coverage against the full MITRE ATT&CK matrix. Calculates percentage coverage by tactic and technique.
- **Where it applies:** Security Metrics page.
- **Output or results:** Coverage percentage with MITRE ATT&CK heatmap and gap analysis.
- **Related features:** Detection Rules, MITRE ATT&CK, Threat Hunting.

### 42.6 Custom Metric Dashboards

- **Feature Name:** Custom Metrics Builder
- **What it does:** Allows creation of custom security metric dashboards with user-defined KPIs, data sources, and visualizations.
- **How it works:** Dashboard builder with selectable metrics, time ranges, grouping options, and chart types. Custom dashboards are saved per user/team.
- **Where it applies:** Security Metrics page.
- **Configuration options:** Metric selection, time range, grouping, chart type, refresh interval.
- **Output or results:** Custom metric dashboards with configurable visualizations.
- **Related features:** All security features (data sources).

---

## 43. MSSP White-Label & Partner Portal

**Source:** `client/src/pages/mssp-portal.tsx`, `server/routes/mssp.ts`

### 43.1 White-Label Branding

- **Feature Name:** MSSP White-Label Configuration
- **What it does:** Allows MSSP partners to customize platform branding with their own logos, colors, and company information for client-facing deployments.
- **How it works:** CRUD via `/api/mssp/white-label`. White-label configuration includes: logo upload, primary/secondary colors, company name, support contact, and custom domain. Applied to all client-facing interfaces.
- **Where it applies:** MSSP Portal page, Branding tab.
- **Configuration options:** Logo, color scheme, company name, support info, custom domain, email templates.
- **Output or results:** Branded platform interface with MSSP partner identity.
- **Related features:** Advanced Reporting (branded reports).

### 43.2 Client Tenant Management

- **Feature Name:** Multi-Tenant Client Management
- **What it does:** Manages MSSP client tenants with independent data isolation, billing, and configuration.
- **How it works:** Client management via MSSP endpoints. Each client is an independent tenant with isolated data, configurable feature access, and billing tracking.
- **Where it applies:** MSSP Portal page, Clients tab.
- **Integration points:** Multi-Tenant Isolation, Billing.
- **Output or results:** Client tenant list with health indicators, feature access, and billing status.
- **Related features:** Multi-Tenant Isolation, Billing.

### 43.3 SLA Management

- **Feature Name:** SLA Tracking
- **What it does:** Defines and tracks service level agreements for MSSP clients including response times, uptime commitments, and reporting schedules.
- **How it works:** SLA definitions with response time targets by severity, uptime percentage commitments, and reporting frequency. Automated SLA compliance tracking and breach alerting.
- **Where it applies:** MSSP Portal page, SLAs tab.
- **Configuration options:** Response time targets, uptime commitments, reporting schedules, breach notifications.
- **Output or results:** SLA compliance dashboard with target vs. actual metrics and breach indicators.
- **Related features:** Incident Management, Notifications.

### 43.4 Usage Billing

- **Feature Name:** MSSP Usage Billing
- **What it does:** Tracks and bills MSSP client usage based on data volume, feature consumption, and user counts with configurable pricing.
- **How it works:** Usage tracking aggregates per-client metrics: ingestion volume, user count, feature usage, and API calls. Base fee conversion uses Math.round for consistent billing.
- **Where it applies:** MSSP Portal page, Billing tab.
- **Output or results:** Usage reports with billing summaries, invoice generation, and payment tracking.
- **Related features:** Billing & Subscription.

### 43.5 MSSP Onboarding

- **Feature Name:** Client Onboarding Workflow
- **What it does:** Guided workflow for onboarding new MSSP clients including tenant creation, connector setup, and initial configuration.
- **How it works:** Step-by-step onboarding wizard for new client tenants. Steps include: tenant creation, admin account setup, connector configuration, alert policy setup, and SLA definition.
- **Where it applies:** MSSP Portal page.
- **Output or results:** Automated client onboarding with progress tracking and checklist completion.
- **Related features:** Onboarding Wizard, Connectors.

### 43.6 Aggregated Reporting

- **Feature Name:** Cross-Client Reporting
- **What it does:** Generates aggregated security reports across all MSSP client tenants for portfolio-level risk visibility.
- **How it works:** Aggregates metrics across client tenants while maintaining data isolation. Produces portfolio-level dashboards and reports.
- **Where it applies:** MSSP Portal page, Reporting tab.
- **Output or results:** Cross-client reports with portfolio risk metrics and client comparison.
- **Related features:** Advanced Reporting.

---

## 44. Connectors & Integrations

**Source:** `client/src/pages/connectors.tsx`, `client/src/pages/integrations.tsx`, `server/routes/connectors.ts`

### 44.1 Connector Management

- **Feature Name:** Data Source Connectors
- **What it does:** Manages bidirectional connections to external security tools and services for data ingestion and action dispatch.
- **How it works:** CRUD via `/api/connectors`. Each connector has a type (SIEM, EDR, Cloud, Identity, etc.), configuration (API endpoint, credentials), sync schedule, and health status. Supports pull-based (polling) and push-based (webhook) data collection.
- **Where it applies:** Connectors page.
- **Integration points:** All external security tools (CrowdStrike, Sentinel, Splunk, Palo Alto, etc.).
- **Configuration options:** Connector type, API endpoint, credentials, sync schedule, data mapping rules.
- **Output or results:** Connector inventory with health badges, sync status, and data volume metrics.
- **Related features:** Data Ingestion, Alert Management.

### 44.2 Connector Health Monitoring

- **Feature Name:** Connector Health
- **What it does:** Monitors the operational health of all configured connectors with real-time status, error tracking, and alerting.
- **How it works:** Periodic health checks validate connector connectivity, authentication, and data flow. Health states: Healthy, Degraded, Error, Disconnected.
- **Where it applies:** Connectors page, SOC Dashboard.
- **Integration points:** Alert Management (connector-down alerts), Operations.
- **Output or results:** Health status cards with last sync timestamps, error counts, and data volume charts.
- **Related features:** SOC Dashboard, Operations.

### 44.3 Dead Letter Queue

- **Feature Name:** Dead Letter Queue UI
- **What it does:** Displays and manages failed connector sync events that could not be processed, with retry and investigation capabilities.
- **How it works:** Events that fail processing are routed to the dead letter queue. DLQ UI shows failed events with error details, retry buttons, and bulk management.
- **Where it applies:** Connectors page, DLQ tab.
- **Output or results:** Dead letter queue with event details, error messages, and retry/discard actions.
- **Related features:** Connector Management, Operations.

### 44.4 Sync History

- **Feature Name:** Connector Sync History
- **What it does:** Tracks and displays the history of connector synchronization operations with timing, volume, and success/failure metrics.
- **How it works:** Sync history endpoint returns chronological sync records with start/end times, event counts, error counts, and duration.
- **Where it applies:** Connectors page.
- **Output or results:** Sync history timeline with volume charts and error indicators.
- **Related features:** Connector Management.

### 44.5 Test Preview

- **Feature Name:** Connector Test & Preview
- **What it does:** Tests connector connectivity and previews sample data before full deployment, reducing configuration errors.
- **How it works:** Test endpoint validates credentials and retrieves sample data from the external system. Preview shows formatted sample events.
- **Where it applies:** Connectors page (during setup/edit).
- **Output or results:** Test results with connectivity status and sample data preview.
- **Related features:** Connector Management.

### 44.6 Integration Marketplace

- **Feature Name:** Integration Hub
- **What it does:** Provides a marketplace of pre-built integrations with popular security and IT tools organized by category.
- **How it works:** GET `/api/integrations` returns available integrations. Categories include: SIEM, EDR, Cloud, Identity, Ticketing, Communication, and Custom. Each integration has setup guides and configuration templates.
- **Where it applies:** Integrations page.
- **Output or results:** Integration catalog with category filtering, setup guides, and one-click deployment.
- **Related features:** Connector Management.

### 44.7 Notification Channels

- **Feature Name:** Notification Channel Configuration
- **What it does:** Configures notification delivery channels (email, Slack, Microsoft Teams, PagerDuty, webhooks) for alert and incident notifications.
- **How it works:** CRUD for notification channel configurations. Each channel defines: type, credentials, default recipients, and message templates.
- **Where it applies:** Integrations page, Settings.
- **Configuration options:** Channel type, credentials, recipients, message templates, severity filters.
- **Output or results:** Notification channel list with test capability and delivery history.
- **Related features:** Alert Management, Incident Management.

---

## 45. Data Ingestion

**Source:** `client/src/pages/ingestion.tsx`, `server/routes/ingestion.ts`

### 45.1 Event Ingestion API

- **Feature Name:** Event Ingestion Endpoint
- **What it does:** Provides a high-throughput API endpoint for ingesting security events from any source using API keys for authentication.
- **How it works:** POST to `/api/ingestion/events` accepts batched event payloads. Events are validated, deduplicated, parsed, and stored. Supports JSON format with flexible schema. Rate limiting and authentication via API keys.
- **Where it applies:** Data Ingestion page; external systems via API.
- **Integration points:** Native Sensors, External systems, Connectors.
- **Configuration options:** API key management, rate limits, schema validation rules.
- **Output or results:** Ingestion statistics with success/failure counts, deduplication metrics, and throughput indicators.
- **Related features:** Connectors, Alert Management.

### 45.2 Ingestion Statistics

- **Feature Name:** Ingestion Metrics Dashboard
- **What it does:** Displays real-time and historical ingestion metrics including volume, throughput, error rates, and source distribution.
- **How it works:** GET `/api/ingestion/stats` returns aggregate ingestion metrics: total events ingested, alerts created, deduplicated events, failed events, and per-source breakdowns.
- **Where it applies:** Data Ingestion page, SOC Dashboard.
- **Output or results:** Metrics dashboard with KPI cards and time-series charts.
- **Related features:** SOC Dashboard, Operations.

### 45.3 API Key Management

- **Feature Name:** Ingestion API Keys
- **What it does:** Manages API keys used for authenticating event ingestion requests, with scope restrictions and usage tracking.
- **How it works:** CRUD via `/api/ingestion/api-keys`. Each API key has a name, scoped permissions, rate limit, and usage statistics. Keys can be rotated and revoked.
- **Where it applies:** Data Ingestion page, API Keys tab; Settings.
- **Configuration options:** Key name, scope (read/write/admin), rate limit, expiration.
- **Output or results:** API key management interface with usage statistics and rotation controls.
- **Related features:** Security Hardening.

### 45.4 Log Source Configuration

- **Feature Name:** Log Source Management
- **What it does:** Configures and manages log sources with deployment guides, parsing rules, and health monitoring.
- **How it works:** Log source definitions include: source type (syslog, API, file, agent), parsing rules (regex, JSON path), normalization mappings, and health checks. Deployment guides provide step-by-step setup instructions per source type.
- **Where it applies:** Data Ingestion page, Log Sources tab.
- **Configuration options:** Source type, parsing rules, normalization mapping, collection schedule.
- **Output or results:** Log source inventory with configuration status, health indicators, and deployment guides.
- **Related features:** Connectors, Native Sensors.

### 45.5 Event Deduplication

- **Feature Name:** Event Deduplication Engine
- **What it does:** Automatically deduplicates incoming events to prevent alert fatigue and storage waste from duplicate event submissions.
- **How it works:** Deduplication engine compares incoming events against recent events using configurable matching criteria (event hash, source+timestamp, content similarity). Duplicate events increment counters on existing records rather than creating new entries.
- **Where it applies:** Ingestion pipeline.
- **Configuration options:** Deduplication window, matching criteria.
- **Output or results:** Deduplication statistics showing events deduplicated vs. unique.
- **Related features:** Alert Management.

---

## 46. Entity Graph & Correlation

**Source:** `client/src/pages/entity-graph.tsx`, `server/routes/entity-graph.ts`

### 46.1 Entity Graph Visualization

- **Feature Name:** Entity Relationship Graph
- **What it does:** Visualizes relationships between security entities (IP addresses, domains, users, hosts, file hashes) as an interactive force-directed graph.
- **How it works:** GET `/api/entity-graph` returns entity nodes and relationship edges. Graph visualization uses force-directed layout with entity type coloring and relationship labels. Supports filtering by entity type, time range, and relationship strength.
- **Where it applies:** Entity Graph page, Incident Detail (attack graph).
- **Integration points:** Alert Management (entity extraction), Threat Intelligence (IOC enrichment).
- **Output or results:** Interactive graph with clickable nodes, relationship edges, and detail panels.
- **Related features:** Alert Entity Extraction, Attack Graph, Threat Intelligence.

### 46.2 Entity Search

- **Feature Name:** Entity Lookup
- **What it does:** Searches for specific entities across all security data to find associated alerts, incidents, and threat intelligence.
- **How it works:** GET `/api/entity-graph/search` queries entities by type and value. Returns all associated alerts, incidents, and intelligence hits for the searched entity.
- **Where it applies:** Entity Graph page, Alert Detail, Threat Hunting.
- **Output or results:** Entity detail card with associated alerts, incidents, intelligence hits, and relationship map.
- **Related features:** Alert Management, Threat Intelligence, Threat Hunting.

### 46.3 Entity Enrichment

- **Feature Name:** Automatic Entity Enrichment
- **What it does:** Automatically enriches entities with external intelligence: IP geolocation, domain WHOIS, file hash reputation, and threat intelligence lookups.
- **How it works:** On entity discovery, enrichment pipeline queries external services for additional context. Results are cached and attached to entity records.
- **Where it applies:** Entity Graph, Alert Detail.
- **Integration points:** Threat Intelligence feeds, WHOIS services, geolocation databases.
- **Output or results:** Enriched entity cards with geolocation, reputation scores, and intelligence context.
- **Related features:** Threat Intelligence, Alert Enrichment.

### 46.4 Entity Timeline

- **Feature Name:** Entity Activity Timeline
- **What it does:** Shows the chronological activity history for a specific entity across all security data sources.
- **How it works:** Aggregates all events, alerts, and incidents associated with an entity into a chronological timeline.
- **Where it applies:** Entity Graph page (entity detail view).
- **Output or results:** Timeline visualization showing entity activity across time with event type indicators.
- **Related features:** Alert Management, Incident Management.

---

## 47. Autonomous Response

**Source:** `server/routes/autonomous-response.ts`, referenced from multiple UI pages

### 47.1 Automated Response Actions

- **Feature Name:** Autonomous Response Engine
- **What it does:** Executes automated response actions based on predefined rules and AI recommendations, including host isolation, account lockout, firewall rule creation, and process termination.
- **How it works:** Response action pipeline receives triggers from AI triage, playbooks, and manual analyst actions. Actions are dispatched to target systems via integrations. Supports: host isolation, account disable, firewall block, process kill, and DNS sinkhole.
- **Where it applies:** Autonomous SOC, Playbooks, Incident Response.
- **Integration points:** Native Sensors (host actions), Identity Governance (account actions), Network Security (firewall actions).
- **Configuration options:** Action types, approval requirements, scope limitations, rollback capabilities.
- **Output or results:** Action execution log with status, target, and timing.
- **Related features:** Autonomous SOC, Playbooks, Incident Management.

### 47.2 Response Action Rollback

- **Feature Name:** Action Rollback
- **What it does:** Reverses previously executed autonomous response actions when determined to be incorrect or no longer needed.
- **How it works:** Each response action records its inverse operation. Rollback endpoint executes the inverse action and updates the audit trail.
- **Where it applies:** Autonomous Response, Playbooks.
- **Output or results:** Rollback confirmation with before/after status.
- **Related features:** Playbook Rollback, Autonomous SOC.

### 47.3 Response Action Audit

- **Feature Name:** Response Action Audit Trail
- **What it does:** Complete audit trail of all autonomous response actions with actor, target, action type, timing, and outcome.
- **How it works:** Every response action is logged to the audit trail with full context.
- **Where it applies:** Autonomous Response, Compliance.
- **Output or results:** Audit log of response actions with filtering and export.
- **Related features:** Audit Log, Compliance.

---

## 48. Agent Response Actions

**Source:** `server/routes/agent-response.ts`, `client/src/pages/agent-response.tsx`

### 48.1 Remote Agent Commands

- **Feature Name:** Agent Remote Response
- **What it does:** Sends response action commands to native sensor agents deployed on endpoints, enabling remote containment and investigation actions.
- **How it works:** POST to `/api/agent-response/actions` queues commands for specific sensors. Action types include: isolate host, collect forensic artifacts, terminate process, block IP, scan for IOCs, and capture memory dump. Agents poll for pending commands and report results.
- **Where it applies:** Agent Response page, Incident Detail.
- **Integration points:** Native Sensors (agent communication), Incident Management.
- **Configuration options:** Action type, target sensor, parameters, timeout.
- **Output or results:** Command queue with execution status per agent and result collection.
- **Related features:** Native Sensors, Autonomous Response.

### 48.2 Agent Action Results

- **Feature Name:** Action Result Collection
- **What it does:** Collects and displays results from remote agent response actions including forensic artifacts, scan results, and action confirmations.
- **How it works:** Agents report action results back via the heartbeat/events pipeline. Results are linked to the originating action request.
- **Where it applies:** Agent Response page.
- **Output or results:** Action results with collected artifacts, scan findings, and execution logs.
- **Related features:** Native Sensors, Incident Evidence.

---

## 49. AI Prompt Registry

**Source:** `server/routes/ai.ts` (prompt management section)

### 49.1 Prompt Template Management

- **Feature Name:** AI Prompt Registry
- **What it does:** Manages versioned prompt templates used by all AI features, enabling consistent AI behavior and prompt optimization.
- **How it works:** CRUD via `/api/ai/prompts`. Each prompt has a unique ID, name, template text, version number, and usage statistics. Prompts support variable substitution and conditional sections. Dedicated prompt IDs for different AI features (triage, correlation, deep investigation, playbook authoring).
- **Where it applies:** AI Engine configuration.
- **Configuration options:** Prompt text editing, version management, A/B testing.
- **Output or results:** Prompt template library with version history, usage statistics, and diff viewing.
- **Related features:** AI Engine, AI Triage, AI Correlation.

### 49.2 Prompt Version Diff

- **Feature Name:** Prompt Version Comparison
- **What it does:** Compares different versions of AI prompts side-by-side to track changes and evaluate prompt engineering iterations.
- **How it works:** GET `/api/ai/prompts/:id/versions` returns version history. Diff viewer shows text changes between versions with highlighting.
- **Where it applies:** AI Prompt Registry.
- **Output or results:** Side-by-side diff view with change highlighting.
- **Related features:** AI Prompt Registry.

### 49.3 Test Prompt Interface

- **Feature Name:** Prompt Testing
- **What it does:** Provides an interface to test AI prompts with sample data before deploying to production.
- **How it works:** Test endpoint sends prompt with sample context to the AI model and returns the response for evaluation.
- **Where it applies:** AI Prompt Registry.
- **Output or results:** Test execution with AI response preview and evaluation.
- **Related features:** AI Prompt Registry, AI Engine.

---

## 50. AI Model Health & Inference

**Source:** `client/src/pages/ai-model-health.tsx`, `server/routes/ai.ts`

### 50.1 Model Health Dashboard

- **Feature Name:** AI Model Health Monitoring
- **What it does:** Monitors the health, performance, and availability of configured AI models with real-time metrics.
- **How it works:** GET `/api/ai/model-health` returns per-model health metrics: availability, response latency (p50, p95, p99), error rates, token throughput, and circuit breaker status.
- **Where it applies:** AI Model Health page.
- **Integration points:** AI Engine, Operations.
- **Output or results:** Model health cards with latency charts, availability indicators, and error rate trends.
- **Related features:** AI Engine, Operations.

### 50.2 Inference History

- **Feature Name:** Inference History Dashboard
- **What it does:** Logs and displays all AI inference requests with timing, token usage, cost, and result quality metrics.
- **How it works:** GET `/api/ai/inference-history` returns paginated inference logs. Each entry includes: timestamp, model used, prompt ID, input/output tokens, latency, cost, and result hash. Org-scoped for multi-tenant isolation.
- **Where it applies:** AI Model Health page, Inference tab.
- **Output or results:** Inference log table with filtering and aggregate statistics.
- **Related features:** AI Budget Controls, AI Engine.

### 50.3 Inference Statistics

- **Feature Name:** Inference Analytics
- **What it does:** Aggregated analytics for AI inference patterns including usage trends, cost analysis, and performance benchmarks.
- **How it works:** GET `/api/ai/inference-stats` returns aggregate metrics: total inferences, average latency, total tokens, total cost, and per-feature breakdowns. Org-scoped.
- **Where it applies:** AI Model Health page.
- **Output or results:** Analytics dashboard with usage trends, cost breakdown, and performance metrics.
- **Related features:** AI Budget Controls.

---

## 51. AI Budget Controls

**Source:** `client/src/pages/ai-budget.tsx`, `server/routes/ai.ts`

### 51.1 Budget Configuration

- **Feature Name:** AI Spending Limits
- **What it does:** Sets and enforces spending limits for AI API usage, preventing unexpected costs from excessive AI inference.
- **How it works:** CRUD via `/api/ai/budget`. Budget configuration includes: monthly spending cap, daily limit, per-request token limit, and alert thresholds. Atomic upsert operation prevents race conditions in budget updates.
- **Where it applies:** AI Budget page.
- **Configuration options:** Monthly cap, daily limit, per-request limit, alert thresholds (50%, 75%, 90%, 100%).
- **Output or results:** Budget configuration panel with current usage vs. limits.
- **Related features:** AI Engine, Billing.

### 51.2 Usage Tracking

- **Feature Name:** AI Cost Tracking
- **What it does:** Tracks AI API usage and costs in real-time with per-feature and per-model breakdowns.
- **How it works:** Every AI inference logs token counts and estimated costs. Dashboard aggregates usage by model, feature, and time period.
- **Where it applies:** AI Budget page.
- **Output or results:** Usage dashboard with cost breakdown charts and daily/monthly totals.
- **Related features:** AI Model Health, Billing.

### 51.3 Budget Alerts

- **Feature Name:** Budget Threshold Alerts
- **What it does:** Sends alerts when AI spending approaches or exceeds configured budget thresholds.
- **How it works:** Automated monitoring compares current spending against budget thresholds. Alerts are sent via configured notification channels when thresholds are crossed.
- **Where it applies:** AI Budget page.
- **Integration points:** Notification Channels.
- **Output or results:** Budget alert notifications with current usage and projected overage.
- **Related features:** Notifications, AI Engine.

---

## 52. RAG Knowledge Layer

**Source:** `server/routes/ai.ts` (RAG section), `server/rag-engine.ts`

### 52.1 Document Indexing

- **Feature Name:** RAG Document Indexing
- **What it does:** Indexes security knowledge documents (threat intelligence reports, incident reports, playbooks, runbooks) into a vector database for AI-powered retrieval.
- **How it works:** POST to `/api/ai/rag/index` accepts documents for indexing. Documents are chunked, embedded using text-to-vector models, and stored in pgvector for similarity search. Auto-indexing triggers on incident create/update.
- **Where it applies:** RAG Knowledge configuration.
- **Integration points:** Incident Management (auto-index), Threat Intelligence, Playbooks.
- **Output or results:** Indexed document count with indexing status and coverage metrics.
- **Related features:** AI Engine, Incident Management.

### 52.2 Vector Search

- **Feature Name:** Semantic Knowledge Search
- **What it does:** Provides semantic search across indexed security knowledge, finding relevant context for AI analysis based on meaning rather than exact keywords.
- **How it works:** GET `/api/ai/rag/search` converts search query to vector embedding and performs cosine similarity search against indexed documents. Returns ranked results with relevance scores.
- **Where it applies:** AI Engine (context injection), Threat Hunting.
- **Output or results:** Ranked search results with relevance scores and document excerpts.
- **Related features:** AI Engine, Threat Intelligence.

### 52.3 Ranked Context Packing

- **Feature Name:** Context Packing for AI
- **What it does:** Optimally packs relevant context into AI prompts by scoring and ranking retrieved documents, maximizing AI analysis quality within token limits.
- **How it works:** Retrieved RAG results are scored by relevance and recency. High-score items are included in full; low-score items are summarized. Tag-inclusive token estimation ensures accurate budget calculations.
- **Where it applies:** AI Engine (all AI features).
- **Output or results:** Optimized context injection into AI prompts.
- **Related features:** AI Engine, AI Prompt Registry.

### 52.4 RAG Document Management

- **Feature Name:** Knowledge Base Management
- **What it does:** Manages the RAG knowledge base with CRUD operations for indexed documents, including manual and bulk management.
- **How it works:** CRUD for RAG documents with org ownership checks on delete operations. Supports bulk indexing and selective removal.
- **Where it applies:** RAG Knowledge configuration.
- **Output or results:** Document management interface with indexing status and search capability.
- **Related features:** AI Engine.

---

## 53. Active Learning Feedback Loop

**Source:** `server/routes/active-learning.ts`, `client/src/pages/ai-engine.tsx`

### 53.1 Few-Shot Injection

- **Feature Name:** Few-Shot Learning from Feedback
- **What it does:** Injects analyst feedback (corrections, false positive confirmations) as few-shot examples into AI prompts, continuously improving AI accuracy.
- **How it works:** Analyst feedback on AI outputs (triage, correlation, narratives) is stored as feedback examples. On subsequent AI calls, relevant feedback examples are injected as few-shot context, teaching the AI from organizational-specific patterns.
- **Where it applies:** AI Engine (all AI features).
- **Integration points:** AI Feedback System, AI Prompt Registry.
- **Output or results:** Improved AI accuracy over time through organizational learning.
- **Related features:** AI Feedback, AI Triage.

### 53.2 False Positive Tracking

- **Feature Name:** FP Rate Monitoring
- **What it does:** Tracks false positive rates across AI features and alert sources, identifying areas for detection improvement.
- **How it works:** When analysts mark AI outputs as false positives, the feedback is aggregated to calculate FP rates by source, category, and AI feature.
- **Where it applies:** Active Learning dashboard, AI Engine.
- **Output or results:** FP rate metrics with trend charts and source breakdowns.
- **Related features:** AI Triage, Detection Rules.

### 53.3 Source Suppression

- **Feature Name:** Feedback-Based Source Suppression
- **What it does:** Automatically suggests alert suppression rules when specific sources consistently generate false positives based on analyst feedback patterns.
- **How it works:** When FP rate for a specific source/category exceeds a threshold, the system suggests suppression rules to reduce noise.
- **Where it applies:** Active Learning, Alert Suppression.
- **Output or results:** Suppression rule suggestions based on FP patterns.
- **Related features:** Alert Suppression Rules, AI Triage.

---

## 54. Onboarding & Wizard

**Source:** `client/src/pages/onboarding.tsx`, `server/routes/onboarding.ts`

### 54.1 Onboarding Wizard

- **Feature Name:** Multi-Step Onboarding Wizard
- **What it does:** Guides new organizations through initial platform setup with a step-by-step wizard covering organization details, team creation, connector setup, sensor deployment, and plan selection.
- **How it works:** 5-step wizard (totalSteps=5): Step 1 (Organization Details), Step 2 (Invite Team Members), Step 3 (Connect Data Sources), Step 4 (Deploy Native Sensors), Step 5 (Choose Plan). Each step validates completion before allowing progression. Mandatory step validation blocks wizard completion when required steps are skipped.
- **Where it applies:** Post-registration, first-time login.
- **Integration points:** Organization Management, Team Management, Connectors, Native Sensors, Billing.
- **Configuration options:** Step-specific configurations (org name, industry, team invitations, connector selection, sensor platforms, plan choice).
- **Output or results:** Guided setup flow with progress indicator (step X of 5) and completion tracking.
- **Related features:** Organization Management, Team Management, Connectors, Native Sensors, Billing.

### 54.2 Organization Setup

- **Feature Name:** Organization Creation
- **What it does:** Creates the organization entity with name, industry, size, and initial configuration.
- **How it works:** Step 1 of the onboarding wizard. Collects organization name, industry sector, company size, and primary contact. Creates the organization record and establishes tenant isolation.
- **Where it applies:** Onboarding wizard, Step 1.
- **Output or results:** Organization created with tenant isolation established.
- **Related features:** Multi-Tenant Isolation.

### 54.3 Team Invitation

- **Feature Name:** Team Member Onboarding
- **What it does:** Invites team members during initial setup with role assignment and email notification.
- **How it works:** Step 2 of onboarding. Accepts email addresses and role assignments (admin, analyst, viewer). Sends invitation emails via SES.
- **Where it applies:** Onboarding wizard, Step 2.
- **Output or results:** Team invitations sent with role assignments.
- **Related features:** Team Management, Email (SES).

### 54.4 Connector Quick Setup

- **Feature Name:** Quick Connector Setup
- **What it does:** Streamlined connector configuration during onboarding with pre-built templates for popular security tools.
- **How it works:** Step 3 of onboarding. Presents connector templates for popular tools with simplified configuration forms.
- **Where it applies:** Onboarding wizard, Step 3.
- **Output or results:** Initial connectors configured and tested.
- **Related features:** Connectors.

### 54.5 Sensor Deployment Guide

- **Feature Name:** Sensor Deployment Onboarding
- **What it does:** Guides deployment of native sensors across supported platforms (Linux, Windows, macOS, iOS, Android, Docker, Kubernetes) during initial setup.
- **How it works:** Step 4 of onboarding. Displays platform-specific deployment instructions, command-line scripts, and configuration files for each supported platform.
- **Where it applies:** Onboarding wizard, Step 4.
- **Output or results:** Deployment guides with copy-ready commands for each platform.
- **Related features:** Native Sensors.

### 54.6 Plan Selection

- **Feature Name:** Billing Plan Selection
- **What it does:** Presents available subscription plans and facilitates plan selection during onboarding.
- **How it works:** Step 5 of onboarding. Displays plan tiers (Starter, Professional, Enterprise, Ultimate) with feature comparisons and pricing.
- **Where it applies:** Onboarding wizard, Step 5.
- **Output or results:** Plan selected and billing initiated.
- **Related features:** Billing & Subscription.

---

## 55. Billing & Subscription

**Source:** `client/src/pages/billing.tsx`, `server/routes/billing.ts`

### 55.1 Subscription Plan Management

- **Feature Name:** Plan Tiers
- **What it does:** Manages subscription plans with tier-based feature access, usage limits, and pricing.
- **How it works:** PLAN_TIERS constant defines available plans: Starter, Professional, Enterprise, Ultimate. Each tier specifies: price, included users, data volume, feature access, and API limits. GET `/api/billing/plans` returns plans from the constant (source of truth) rather than stale database entries.
- **Where it applies:** Billing page, Onboarding.
- **Integration points:** Stripe (payment processing), Feature Gates.
- **Configuration options:** Plan selection, annual/monthly billing toggle.
- **Output or results:** Plan comparison cards with feature matrices and pricing.
- **Related features:** Onboarding, Feature Gates.

### 55.2 Stripe Payment Integration

- **Feature Name:** Payment Processing
- **What it does:** Handles payment processing, subscription creation, and billing management through Stripe integration.
- **How it works:** Stripe checkout sessions for new subscriptions. Webhook handling for payment events. Subscription management (upgrade, downgrade, cancel). DB UUID stored in Stripe metadata instead of tier name for consistent plan lookup.
- **Where it applies:** Billing page.
- **Integration points:** Stripe API.
- **Output or results:** Payment forms, invoice history, and subscription management interface.
- **Related features:** Plan Management.

### 55.3 Usage & Limits

- **Feature Name:** Usage vs. Limits Dashboard
- **What it does:** Displays current usage against plan limits for all metered resources (users, data volume, API calls, AI inferences).
- **How it works:** GET `/api/billing/usage` returns current usage metrics against plan limits. Plan lookup supports both DB UUID and tier name fallback.
- **Where it applies:** Billing page.
- **Output or results:** Usage meters with percentage bars and overage indicators.
- **Related features:** Plan Management, AI Budget.

### 55.4 Invoice Management

- **Feature Name:** Invoice History
- **What it does:** Displays and manages billing invoices with payment status, download links, and payment retry options.
- **How it works:** GET `/api/billing/invoices` returns invoice history from Stripe. Currency normalized to uppercase for consistent display (handles Stripe lowercase currency codes).
- **Where it applies:** Billing page, Invoices tab.
- **Output or results:** Invoice table with amounts, dates, status badges, and PDF download links.
- **Related features:** Payment Processing.

### 55.5 Add-On Management

- **Feature Name:** Billing Add-Ons
- **What it does:** Manages optional add-on features that can be purchased on top of base plans (additional data volume, premium integrations, dedicated support).
- **How it works:** Add-on definitions with pricing and feature descriptions. Add-on purchase flow through Stripe.
- **Where it applies:** Billing page, Add-Ons tab.
- **Output or results:** Add-on catalog with purchase options and active add-on management.
- **Related features:** Plan Management.

---

## 56. Team Management & RBAC

**Source:** `client/src/pages/settings.tsx` (team section), `server/routes/orgs.ts`

### 56.1 Team Member Management

- **Feature Name:** Team Member CRUD
- **What it does:** Manages organization team members with invitation, role assignment, and access control.
- **How it works:** CRUD via `/api/orgs/:orgId/members`. Supports invitation (email), role assignment (superadmin, admin, analyst, viewer), and member removal. Team members display with full names from user profiles.
- **Where it applies:** Settings page, Team tab.
- **Integration points:** SSO (federated identity), SCIM (automated provisioning).
- **Configuration options:** Role assignment, invitation management.
- **Output or results:** Team member list with role badges, last activity, and management controls.
- **Related features:** SSO, RBAC.

### 56.2 Role-Based Access Control

- **Feature Name:** RBAC Engine
- **What it does:** Enforces role-based access control across all platform features, restricting actions based on user role.
- **How it works:** Four role levels: superadmin (full platform access), admin (org management), analyst (investigation and response), viewer (read-only). Each API endpoint checks user role before allowing access. Mutation endpoints require analyst or above.
- **Where it applies:** All platform features.
- **Output or results:** Feature access restrictions based on role; unauthorized access returns 403.
- **Related features:** All features, Multi-Tenant Isolation.

### 56.3 Team Invitations

- **Feature Name:** Email Invitations
- **What it does:** Sends email invitations to new team members with secure registration links.
- **How it works:** POST invitation endpoint creates invitation record and sends email via SES with registration link. Invitations checked during user registration for auto-org assignment.
- **Where it applies:** Settings page, Team tab; Onboarding wizard.
- **Integration points:** Email (SES).
- **Output or results:** Invitation sent with tracking status (pending, accepted, expired).
- **Related features:** Onboarding, Email.

---

## 57. SSO / SAML Integration

**Source:** `server/routes/auth.ts`, `server/auth/session.ts`

### 57.1 Google OAuth

- **Feature Name:** Google OAuth Login
- **What it does:** Provides single sign-on authentication via Google OAuth 2.0, enabling users to log in with their Google Workspace accounts.
- **How it works:** OAuth 2.0 authorization code flow with Google. Callback handler validates tokens, creates/links user accounts, and establishes sessions. Absolute callback URL configured for staging/production environment consistency. Session rotation on login for security.
- **Where it applies:** Login page, Registration page.
- **Integration points:** Google Identity Platform, User Management.
- **Configuration options:** Google client ID/secret, authorized domains.
- **Output or results:** One-click Google login with automatic account creation/linking.
- **Related features:** User Management, Session Management.

### 57.2 Session Management

- **Feature Name:** Secure Session Handling
- **What it does:** Manages user authentication sessions with secure cookie-based session tokens, rotation, and expiration.
- **How it works:** Session tokens stored as HTTP-only secure cookies. Session rotation on login prevents session fixation. Configurable session timeout and idle timeout.
- **Where it applies:** All authenticated pages.
- **Configuration options:** Session duration, idle timeout, secure cookie settings.
- **Output or results:** Authenticated user sessions with automatic expiration.
- **Related features:** Authentication, RBAC.

### 57.3 Superadmin Auto-Promotion

- **Feature Name:** Superadmin Bootstrap
- **What it does:** Automatically promotes the configured superadmin email to superadmin role on login, ensuring platform administrator access.
- **How it works:** On login, if the authenticated user's email matches the configured SUPERADMIN_EMAIL, their role is automatically set to superadmin.
- **Where it applies:** Authentication flow.
- **Output or results:** Superadmin role auto-assigned on login.
- **Related features:** RBAC, Team Management.

---

## 58. Multi-Tenant Isolation

**Source:** `server/routes/*.ts` (org-scoping throughout), `server/auth/session.ts`

### 58.1 Org-Scoped Data Access

- **Feature Name:** Multi-Tenant Data Isolation
- **What it does:** Ensures complete data isolation between organizations, preventing any cross-tenant data access or leakage.
- **How it works:** Every database query includes `orgId` filter matching the authenticated user's organization. All API endpoints enforce org-scoping on both read and write operations. IDOR protection validates resource ownership before access. Fail-closed patterns ensure missing org context blocks access rather than allowing it.
- **Where it applies:** All API endpoints, all data access.
- **Output or results:** Complete data isolation between tenants; unauthorized cross-tenant access returns 403/404.
- **Related features:** RBAC, All data features.

### 58.2 Tenant Creation

- **Feature Name:** New Tenant Provisioning
- **What it does:** Creates new organizational tenants with isolated data partitioning and initial configuration.
- **How it works:** Organization creation establishes a new tenant with unique orgId. All subsequent data is partitioned by this orgId. Auto-org creation deferred to onboarding wizard instead of registration to prevent orphan tenants.
- **Where it applies:** Onboarding, MSSP client creation.
- **Output or results:** New tenant with isolated data space and initial admin account.
- **Related features:** Onboarding, MSSP.

### 58.3 CSRF Protection

- **Feature Name:** CSRF Token Validation
- **What it does:** Protects against cross-site request forgery attacks using token-based validation on all state-changing requests.
- **How it works:** CSRF tokens are generated per session and included in all POST/PUT/PATCH/DELETE requests. Server validates token presence and correctness before processing mutations.
- **Where it applies:** All mutation endpoints.
- **Output or results:** CSRF token validation on all state changes; invalid tokens return 403.
- **Related features:** Security Hardening.

---

## 59. Operations & Observability

**Source:** `server/routes/admin.ts`, `server/error-tracker.ts`, various operations endpoints

### 59.1 Error Tracking

- **Feature Name:** Application Error Tracker
- **What it does:** Captures, categorizes, and tracks application errors with stack traces, context, and occurrence counts for debugging and reliability improvement.
- **How it works:** Global error handler captures unhandled exceptions and route-level errors. Each error is logged with stack trace, request context, user context, and occurrence count. Errors are grouped by signature for deduplication.
- **Where it applies:** Server-side error handling.
- **Output or results:** Error dashboard with grouped errors, occurrence counts, and stack traces.
- **Related features:** Operations, Notifications.

### 59.2 Job Queue Dashboard

- **Feature Name:** Background Job Monitoring
- **What it does:** Monitors and manages background job queues with job status, execution timing, retry counts, and failure tracking.
- **How it works:** GET `/api/admin/jobs` returns job queue status. Jobs include: scheduled scans, data tiering, report generation, alert processing, and sync operations. Direct job lookup with org check for retry operations (IDOR protection).
- **Where it applies:** Job Queue Dashboard page.
- **Output or results:** Job queue table with status indicators, timing, and retry/cancel controls.
- **Related features:** Operations, Scheduled Tasks.

### 59.3 Prometheus Metrics

- **Feature Name:** Prometheus Metrics Endpoint
- **What it does:** Exposes platform metrics in Prometheus format for integration with monitoring and alerting infrastructure.
- **How it works:** GET `/metrics` returns platform metrics: HTTP request counts/latency (histogram), active connections, database pool stats, AI inference counts, and custom business metrics. Histogram double-counting fixed for accurate percentile calculations.
- **Where it applies:** Operations infrastructure (Prometheus/Grafana).
- **Output or results:** Prometheus-compatible metrics endpoint.
- **Related features:** Operations, Kubernetes HPA.

### 59.4 Health Check Endpoints

- **Feature Name:** Liveness & Readiness Probes
- **What it does:** Provides health check endpoints for container orchestration platforms to determine application health and readiness.
- **How it works:** Liveness endpoint (`/health`) returns basic health. Readiness endpoint (`/ready`) checks database connectivity and dependent services. Used by Kubernetes probes for pod lifecycle management.
- **Where it applies:** Operations, Kubernetes deployment.
- **Output or results:** Health status response with component-level details.
- **Related features:** Kubernetes Deployment, Operations.

### 59.5 Platform Administration

- **Feature Name:** Admin Console
- **What it does:** Provides platform-level administration tools for managing organizations, users, system configuration, and operations.
- **How it works:** Admin routes at `/api/admin/*` provide: organization management, user management, system configuration, feature flag management, and operational controls. Restricted to superadmin role.
- **Where it applies:** Admin pages.
- **Integration points:** RBAC (superadmin only).
- **Output or results:** Admin console with organization, user, and system management tools.
- **Related features:** RBAC, Multi-Tenant Isolation.

---

## 60. Cross-Cutting Capabilities

### 60.1 Animated Loading Screen

- **Feature Name:** Platform Loading Screen
- **What it does:** Displays an animated loading screen with the ATS (Arica Tech Security) logo during initial application load, providing visual feedback and branding.
- **How it works:** CSS animation-based loading screen rendered before React application mount. Features logo animation with pulsing effect.
- **Where it applies:** Application startup, page transitions.
- **Output or results:** Branded loading animation during application initialization.
- **Related features:** UI/UX.

### 60.2 Notification Bell

- **Feature Name:** In-App Notification Center
- **What it does:** Provides an in-application notification center showing unread alerts, approvals, and system messages with bell icon and badge count.
- **How it works:** Notification bell in the application header shows unread notification count. Click reveals notification drawer with categorized messages. Real-time updates via WebSocket.
- **Where it applies:** Application header (all pages).
- **Integration points:** Alert Management, Approval Workflows, System Notifications.
- **Output or results:** Notification bell with unread count badge and notification drawer.
- **Related features:** Alert Management, Approval Workflows.

### 60.3 Contextual Empty States

- **Feature Name:** Contextual Empty States
- **What it does:** Displays helpful, context-specific empty state messages when data pages have no content, guiding users toward first actions.
- **How it works:** Empty state components check data availability and render domain-specific guidance with action buttons (e.g., "Create your first playbook" on empty Playbooks page).
- **Where it applies:** All data pages.
- **Output or results:** Helpful empty state messages with action buttons for first-time setup.
- **Related features:** Onboarding.

### 60.4 Dashboard Personalization

- **Feature Name:** User Dashboard Preferences
- **What it does:** Persists user-specific dashboard layout, widget selection, and viewing preferences across sessions.
- **How it works:** User preferences stored in localStorage. Dashboard widget visibility, position, and preset selection persisted per user.
- **Where it applies:** SOC Dashboard.
- **Output or results:** Personalized dashboard that persists across sessions.
- **Related features:** SOC Dashboard.

### 60.5 PDF Report Download

- **Feature Name:** On-Demand PDF Reports
- **What it does:** Generates and downloads PDF reports on demand via binary download endpoint, with proper error handling.
- **How it works:** Binary endpoint generates PDF server-side and streams to client. Error handling prevents contradictory success toast after download failure.
- **Where it applies:** Advanced Reporting, Compliance.
- **Output or results:** Downloaded PDF file with professional formatting.
- **Related features:** Advanced Reporting.

### 60.6 Mobile Responsive Layout

- **Feature Name:** Mobile Viewport Support
- **What it does:** Responsive layout that adapts to mobile and tablet viewports for on-the-go SOC access.
- **How it works:** CSS media queries and responsive component layouts adapt UI for smaller screens. Sidebar collapses to hamburger menu, tables become scrollable, and widgets stack vertically.
- **Where it applies:** All pages.
- **Output or results:** Usable platform interface on mobile and tablet devices.
- **Related features:** All UI features.

### 60.7 WebSocket Real-Time Updates

- **Feature Name:** WebSocket Communication
- **What it does:** Provides real-time bidirectional communication for live updates, notifications, and collaborative features.
- **How it works:** WebSocket connections established on page load. Used for: real-time alert notifications, war room chat, dashboard live updates, and job status streaming. Backpressure handling prevents client overwhelm during high event volumes.
- **Where it applies:** SOC Dashboard, War Room, Notifications.
- **Output or results:** Real-time data updates without page refresh.
- **Related features:** War Room, Notifications, Dashboard.

---

## 61. Platform Hardening & Production Readiness

**Source:** `server/index.ts`, `docker-compose.production.yml`, Kubernetes manifests, CI/CD workflows

### 61.1 Response Compression

- **Feature Name:** HTTP Response Compression
- **What it does:** Compresses HTTP responses using gzip/brotli to reduce bandwidth usage and improve page load times.
- **How it works:** Express compression middleware applied to all responses. Supports gzip and brotli encoding based on client Accept-Encoding headers.
- **Where it applies:** All HTTP responses.
- **Configuration options:** Compression level, minimum size threshold.
- **Output or results:** Reduced response sizes (typically 60-80% reduction for text content).
- **Related features:** Performance.

### 61.2 Global Rate Limiting

- **Feature Name:** API Rate Limiting
- **What it does:** Enforces request rate limits to prevent abuse, brute force attacks, and resource exhaustion.
- **How it works:** express-rate-limit middleware applies per-IP rate limits. Rate limiting disabled in dev mode (max:0 treated as block-all in v7). Production limits configured per endpoint category. Graph scan endpoint has dedicated rate limiter.
- **Where it applies:** All API endpoints.
- **Configuration options:** Rate limit windows, request counts per window, per-endpoint overrides.
- **Output or results:** Rate-limited responses with 429 status code and retry-after header when limits exceeded.
- **Related features:** Security Hardening, API Security.

### 61.3 Request Timeouts

- **Feature Name:** Request Timeout Enforcement
- **What it does:** Enforces maximum request processing time to prevent long-running requests from consuming server resources.
- **How it works:** Server-side request timeout middleware terminates requests exceeding configured duration.
- **Where it applies:** All API endpoints.
- **Configuration options:** Default timeout, per-endpoint overrides for long-running operations.
- **Output or results:** 408 Request Timeout response for exceeded requests.
- **Related features:** Operations, Performance.

### 61.4 Content Security Policy

- **Feature Name:** CSP Headers
- **What it does:** Implements Content Security Policy headers to prevent XSS, code injection, and other client-side attacks.
- **How it works:** CSP headers set on all responses defining allowed sources for scripts, styles, images, and connections. Nonce-based script allowlisting in production; unsafe-inline permitted in dev mode for Vite HMR compatibility. CSP nonce excluded in dev mode so unsafe-inline takes effect.
- **Where it applies:** All HTTP responses.
- **Configuration options:** CSP directives, nonce generation.
- **Output or results:** CSP-protected responses preventing unauthorized script execution.
- **Related features:** Security Hardening.

### 61.5 Security Headers

- **Feature Name:** HTTP Security Headers
- **What it does:** Applies comprehensive HTTP security headers (HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy) to all responses.
- **How it works:** Helmet middleware applies security headers. Includes: Strict-Transport-Security, X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Referrer-Policy: strict-origin-when-cross-origin.
- **Where it applies:** All HTTP responses.
- **Output or results:** Security headers on all responses.
- **Related features:** Security Hardening.

### 61.6 Static Asset Caching

- **Feature Name:** Static File Caching
- **What it does:** Configures long-lived cache headers for static assets (JS, CSS, images) to improve load times and reduce server load.
- **How it works:** Static file serving middleware with cache-control headers. Fingerprinted assets get immutable cache headers; non-fingerprinted assets get shorter cache durations.
- **Where it applies:** All static assets.
- **Output or results:** Cached static assets with appropriate cache-control headers.
- **Related features:** Performance.

### 61.7 SSRF Protection

- **Feature Name:** SSRF Validation
- **What it does:** Validates and blocks server-side request forgery (SSRF) attempts by checking outbound request targets against allowlists and blocking internal network access.
- **How it works:** SSRF validation on all outbound HTTP requests from user-controlled URLs (webhook targets, integration endpoints). Blocks requests to internal IP ranges, localhost, and metadata endpoints. Redirect bypass protection prevents SSRF via HTTP redirects.
- **Where it applies:** Ticketing webhooks, integration endpoints, any user-supplied URLs.
- **Output or results:** SSRF attempts blocked with security event logging.
- **Related features:** Security Hardening.

### 61.8 Input Validation & Sanitization

- **Feature Name:** Input Sanitization
- **What it does:** Validates and sanitizes all user inputs to prevent injection attacks (SQL, XSS, command injection).
- **How it works:** Zod schema validation on all request bodies. HTML escaping in JSON responses. LIKE wildcard escaping in database queries. Mass assignment protection via field allowlists on PATCH endpoints.
- **Where it applies:** All API endpoints.
- **Output or results:** Validated and sanitized inputs preventing injection attacks.
- **Related features:** Security Hardening.

### 61.9 Docker Production Configuration

- **Feature Name:** Production Docker Setup
- **What it does:** Provides production-optimized Docker and Docker Compose configurations for deployment.
- **How it works:** `docker-compose.production.yml` defines production services: app server, PostgreSQL with persistent volume, environment configuration. Multi-stage Dockerfile with build optimization.
- **Where it applies:** Production deployment.
- **Configuration options:** Environment variables, resource limits, health check intervals.
- **Output or results:** Production-ready container deployment.
- **Related features:** Operations.

### 61.10 Kubernetes Deployment

- **Feature Name:** Kubernetes Manifests
- **What it does:** Provides Kubernetes deployment manifests with HPA (Horizontal Pod Autoscaler), Ingress, and service definitions.
- **How it works:** K8s manifests define: Deployment (with resource requests/limits), Service, Ingress (with TLS), HPA (CPU/memory-based autoscaling), and ConfigMap/Secret references. Staging ingress service name corrected for proper routing.
- **Where it applies:** Kubernetes deployment.
- **Configuration options:** Replica counts, resource limits, autoscaling thresholds, ingress configuration.
- **Output or results:** Kubernetes-native deployment with autoscaling.
- **Related features:** Operations, Prometheus Metrics.

### 61.11 CI/CD Pipeline

- **Feature Name:** GitHub Actions CI/CD
- **What it does:** Comprehensive CI/CD pipeline with type checking, linting, security scanning, and deployment automation.
- **How it works:** 4 GitHub Actions workflows with 116 checks covering: TypeScript type checking, ESLint linting, dependency audit, SAST scanning, container image scanning, and deployment gates. Self-hosted runner support on AWS for performance.
- **Where it applies:** GitHub repository.
- **Configuration options:** Workflow triggers (push/PR/manual), check severity thresholds.
- **Output or results:** Automated quality gates on all code changes.
- **Related features:** Developer Security.

### 61.12 security.txt

- **Feature Name:** Security Contact Disclosure
- **What it does:** Provides a standard security.txt file at /.well-known/security.txt for responsible vulnerability disclosure.
- **How it works:** Static file served at standard location per RFC 9116 with contact information, encryption key, and disclosure policy.
- **Where it applies:** Public web endpoint.
- **Output or results:** Standardized security contact information for researchers.
- **Related features:** Security Hardening.

---

_End of Feature Catalog_

**Total Features Documented:** 350+  
**Total Security Domains:** 61  
**Document Generated From:** SecureNexus platform codebase analysis  
**Source Files Analyzed:** 150+ client pages (136,590+ lines), 100+ server routes (67,388+ lines)
