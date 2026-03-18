# SecureNexus - Comprehensive Feature Documentation

> **Version**: 1.0 | **Last Updated**: March 2026 | **Platform**: SecureNexus by Arica Technology Solutions

---

## Table of Contents

1. [Platform Overview](#1-platform-overview)
2. [Getting Started & Onboarding](#2-getting-started--onboarding)
3. [Core Features](#3-core-features)
   - [Dashboard](#31-dashboard)
   - [Alerts](#32-alerts)
   - [Incidents](#33-incidents)
4. [Watch & Recon](#4-watch--recon)
   - [Threat Intel Feeds](#41-threat-intel-feeds)
   - [OSINT Monitoring](#42-osint-monitoring)
   - [IOC Management](#43-ioc-management)
   - [CVE Database](#44-cve-database)
   - [Campaign Viewer](#45-campaign-viewer)
   - [MITRE ATT&CK Navigator](#46-mitre-attck-navigator)
   - [Kill Chain Visualization](#47-kill-chain-visualization)
5. [Investigation](#5-investigation)
   - [Security Graph](#51-security-graph)
   - [Attack Paths](#52-attack-paths)
   - [Entity Explorer & Resolution](#53-entity-explorer--resolution)
   - [War Room](#54-war-room)
   - [Threat Hunting Workbench](#55-threat-hunting-workbench)
   - [Investigation Timeline](#56-investigation-timeline)
   - [Evidence Chain & Locker](#57-evidence-chain--locker)
6. [Response & Automation](#6-response--automation)
   - [Playbooks](#61-playbooks)
   - [Autonomous Response](#62-autonomous-response)
   - [Rollback History](#63-rollback-history)
   - [Playbook & Runbook Libraries](#64-playbook--runbook-libraries)
7. [Posture Management](#7-posture-management)
   - [CSPM (Cloud Security Posture)](#71-cspm)
   - [Endpoint Telemetry](#72-endpoint-telemetry)
   - [Vulnerability Management](#73-vulnerability-management)
   - [JIT Access & Secret Rotation](#74-jit-access--secret-rotation)
8. [AI Analyst](#8-ai-analyst)
   - [AI Correlation Engine](#81-ai-correlation-engine)
   - [SOC Co-Pilot](#82-soc-co-pilot)
   - [Prompt Builder](#83-prompt-builder)
   - [Model Gateway](#84-model-gateway)
   - [Prompt Registry](#85-prompt-registry)
   - [Feedback Loop (Active Learning)](#86-feedback-loop-active-learning)
   - [Budget & Limits](#87-budget--limits)
9. [Data & Integrations](#9-data--integrations)
   - [Connectors](#91-connectors)
   - [Integration Marketplace](#92-integration-marketplace)
   - [Native Collectors](#93-native-collectors)
   - [Webhooks](#94-webhooks)
   - [Ingestion Pipeline](#95-ingestion-pipeline)
   - [Job Queue](#96-job-queue)
   - [Outbox Monitor](#97-outbox-monitor)
   - [Data Lake](#98-data-lake)
10. [Standalone Security Modules](#10-standalone-security-modules)
    - [Asset Inventory](#101-asset-inventory)
    - [Risk Register](#102-risk-register)
    - [Native Sensors](#103-native-sensors)
    - [Detection Rules](#104-detection-rules)
    - [Vulnerability Scanner](#105-vulnerability-scanner)
    - [Agent Response](#106-agent-response)
    - [UEBA Analytics](#107-ueba-analytics)
    - [Supply Chain Security](#108-supply-chain-security)
    - [Identity Governance & PAM](#109-identity-governance--pam)
    - [Deception Technology](#1010-deception-technology)
    - [OT/ICS Security](#1011-otics-security)
    - [Mobile & Remote Security](#1012-mobile--remote-security)
    - [API Security](#1013-api-security)
    - [Ransomware Defense](#1014-ransomware-defense)
    - [Community Threat Intel](#1015-community-threat-intel)
    - [Security Posture Score & Trust Center](#1016-security-posture-score--trust-center)
    - [Security Chaos Engineering](#1017-security-chaos-engineering)
    - [AI Detection Rules](#1018-ai-detection-rules)
    - [Autonomous SOC](#1019-autonomous-soc)
    - [Developer Security (Shift-Left)](#1020-developer-security-shift-left)
    - [TPRM (Third-Party Risk)](#1021-tprm-third-party-risk)
    - [Dark Web Monitoring](#1022-dark-web-monitoring)
    - [Physical Security](#1023-physical-security)
    - [Phishing & Security Awareness](#1024-phishing--security-awareness)
    - [Quantum Readiness](#1025-quantum-readiness)
    - [Privacy Engineering](#1026-privacy-engineering)
    - [DNS Security](#1027-dns-security)
    - [Email Security](#1028-email-security)
    - [MSSP Dashboard & Partner Portal](#1029-mssp-dashboard--partner-portal)
    - [Security Assessments & Reports](#1030-security-assessments--reports)
    - [Advanced Reporting](#1031-advanced-reporting)
11. [Governance](#11-governance)
    - [Compliance Center](#111-compliance-center)
    - [Trust Center](#112-trust-center)
    - [Gap Analysis](#113-gap-analysis)
    - [Audit Log](#114-audit-log)
    - [Policy Packs](#115-policy-packs)
    - [Reports](#116-reports)
    - [Data Residency](#117-data-residency)
    - [Board Dashboard](#118-board-dashboard)
12. [Admin & Settings](#12-admin--settings)
    - [Onboarding Wizard](#121-onboarding-wizard)
    - [Team & Invites](#122-team--invites)
    - [Org Settings](#123-org-settings)
    - [Developer Portal](#124-developer-portal)
    - [Billing & Usage](#125-billing--usage)
    - [MFA Setup](#126-mfa-setup)
13. [Asset Onboarding Guide](#13-asset-onboarding-guide)
14. [Environment Variables & Configuration](#14-environment-variables--configuration)
15. [AI Configuration & Troubleshooting](#15-ai-configuration--troubleshooting)
16. [API Reference](#16-api-reference)
17. [Supported Ingestion Sources](#17-supported-ingestion-sources)

---

## 1. Platform Overview

SecureNexus is a comprehensive Security Information and Event Management (SIEM) / Security Operations Center (SOC) platform built by Arica Technology Solutions. It combines:

- **Real-time alert ingestion** from 22+ security vendors (CrowdStrike, Splunk, Palo Alto, AWS GuardDuty, Microsoft Defender, etc.)
- **AI-powered analysis** using Claude Sonnet 4 and Claude Opus 4 via AWS Bedrock for triage, correlation, narrative generation, deep investigation, threat hunting, and behavioral analytics
- **Multi-tenant architecture** with organization-scoped data isolation, RBAC (admin/analyst/viewer roles), and plan-based feature enforcement
- **190+ feature pages** covering the full security operations lifecycle
- **108+ backend API routes** with validated inputs, audit logging, and CSRF/rate-limit protections

### Architecture

```
Client (React + Vite + Tailwind)
  |
  v
Express.js Server (Node.js / TypeScript)
  |
  +-- PostgreSQL (via Drizzle ORM)
  +-- AWS Bedrock (Claude AI models)
  +-- AWS S3 (file storage)
  +-- AWS SES (email)
  +-- pgvector (RAG vector search)
```

### Multi-Tenancy Model

Every resource in SecureNexus is scoped to an **organization** (`orgId`). When a user logs in, they are associated with one or more organizations via memberships. All API requests are validated to ensure the requesting user belongs to the organization that owns the resource.

Roles:
| Role | Capabilities |
|------|-------------|
| **Admin** | Full access: manage team, billing, connectors, org settings, all features |
| **Analyst** | Operational access: alerts, incidents, investigations, AI tools, playbooks |
| **Viewer** | Read-only access: dashboards, reports, audit logs |

---

## 2. Getting Started & Onboarding

### 2.1 Registration & Login

1. Navigate to the SecureNexus login page
2. Sign up with email/password or use **Google OAuth** / **GitHub OAuth**
3. After first login, you are redirected to the **Onboarding Wizard**

### 2.2 Onboarding Wizard

**Sidebar**: Admin & Settings > Onboarding  
**Route**: `/onboarding`  
**API**: `GET /api/onboarding/status`, `POST /api/onboarding/step/:step`

The wizard has 5 steps:

| Step | Name                    | Required? | What It Does                                                                                                                                     |
| ---- | ----------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1    | **Create Organization** | Yes       | Creates your workspace. Set org name, industry, company size.                                                                                    |
| 2    | **Choose Plan**         | Skippable | Select Free, Pro, or Enterprise tier. Determines feature limits.                                                                                 |
| 3    | **Invite Team**         | Skippable | Send email invitations to colleagues with role assignments (admin/analyst/viewer). Up to 20 invitations at once.                                 |
| 4    | **Connect Integration** | Skippable | Connect your first SIEM/EDR/collaboration tool (Splunk, CrowdStrike, SentinelOne, Microsoft Sentinel, Slack, PagerDuty, AWS Security Hub, Jira). |
| 5    | **Dashboard Tour**      | Yes       | Interactive guided tour of the platform showing sidebar navigation, alert management, AI capabilities, reporting, and settings.                  |

**How to complete onboarding**:

1. Enter your organization name (minimum 2 characters)
2. Optionally select industry and company size
3. Click "Create Organization"
4. Choose a plan (Free is default) or skip
5. Add team member emails with roles or skip
6. Select and connect an integration or skip
7. Complete the dashboard tour

> **Note**: The `create_org` step is mandatory and cannot be skipped. The `choose_plan` step is also required for wizard completion but can be done later from Billing settings.

---

## 3. Core Features

### 3.1 Dashboard

**Route**: `/`  
**API**: `GET /api/dashboard/stats`, `GET /api/dashboard/posture`

The main dashboard shows at-a-glance security metrics:

- **Total Alerts** with severity breakdown (critical/high/medium/low)
- **Open Incidents** count
- **Mean Time to Resolve (MTTR)**
- **Security Posture Score** (0-100)
- **Alert trend charts** (daily/weekly)
- **Recent alerts** list with quick actions
- **Connector health** status

**How it works**: The dashboard aggregates data from alerts, incidents, connectors, and posture checks. All data is org-scoped and refreshes on page load.

### 3.2 Alerts

**Route**: `/alerts`  
**API**: `GET /api/v1/alerts`, `PATCH /api/v1/alerts/:id`, `POST /api/v1/alerts/bulk`

Alerts are the fundamental unit of security data in SecureNexus. They flow in from connectors, the ingestion API, or native sensors.

**Features**:

- Paginated alert list with filtering by severity, status, source, category, date range
- Alert detail view with full normalized data, raw payload, entity links
- Status management: `new` -> `triaged` -> `in_progress` -> `resolved` / `false_positive`
- Bulk actions: acknowledge, assign, change severity, close
- One-click AI triage (sends alert to Claude for analysis)

**Alert fields**:
| Field | Description |
|-------|------------|
| `title` | Alert headline |
| `severity` | critical / high / medium / low / informational |
| `category` | malware, intrusion, phishing, data_exfiltration, etc. |
| `source` | Origin system (CrowdStrike EDR, Splunk SIEM, etc.) |
| `sourceIp` / `destIp` | Network addresses |
| `hostname` | Affected host |
| `mitreTactic` / `mitreTechnique` | MITRE ATT&CK mapping |
| `status` | new / triaged / in_progress / resolved / false_positive |

**How to onboard alerts**:

1. **Via Connector**: Go to Connectors, add your SIEM/EDR, click Sync
2. **Via API**: Create an API key (Developer Portal), then `POST /api/ingest/:source` with alert payload
3. **Via Webhook**: Configure your security tool to send webhooks to the SecureNexus ingestion endpoint

### 3.3 Incidents

**Route**: `/incidents`, `/incidents/:id`  
**API**: `GET /api/v1/incidents`, `POST /api/v1/incidents`, `PATCH /api/v1/incidents/:id`

Incidents group related alerts into a single investigation unit.

**Features**:

- Create incidents manually or via AI correlation
- Link alerts to incidents
- Assign incidents to team members
- Track status: `open` -> `investigating` -> `contained` -> `resolved` -> `closed`
- AI-generated narrative (summary, timeline, attacker profile, IOCs, mitigation steps)
- Deep investigation with attack graph visualization
- SSE streaming for real-time AI analysis
- Multi-turn investigation chat

**How incidents work**:

1. Alerts are correlated by the AI engine or manually grouped
2. An incident is created with linked alerts
3. Analysts investigate using the War Room, Timeline, and AI tools
4. AI generates a narrative with MITRE ATT&CK mapping and Diamond Model analysis
5. Playbooks can be triggered for automated response
6. Incident is resolved and closed with documentation

---

## 4. Watch & Recon

### 4.1 Threat Intel Feeds

**Route**: `/threat-intel-feeds`  
**API**: `GET /api/threat-intel/feeds`, `POST /api/threat-intel/feeds`

Manage external threat intelligence feeds that enrich alerts and IOCs.

**Features**:

- Add/remove threat intel feed sources
- Configure polling intervals
- View feed health and last sync timestamps
- Feed types: STIX/TAXII, CSV, JSON, custom API

**How to onboard**:

1. Navigate to Watch & Recon > Threat Intel Feeds
2. Click "Add Feed"
3. Enter feed URL, authentication credentials, format type
4. Set polling interval (how often to check for updates)
5. Click "Save" -- the feed will begin syncing automatically

### 4.2 OSINT Monitoring

**Route**: `/osint-feeds-config`  
**API**: `GET /api/threat-intel/osint`, `POST /api/threat-intel/osint`

Configure Open Source Intelligence monitoring feeds.

**Features**:

- Monitor public threat intelligence sources
- Configure alert thresholds for OSINT matches
- Track IOC matches against OSINT data

**How to onboard**:

1. Navigate to Watch & Recon > OSINT Monitoring
2. Enable desired OSINT sources
3. Configure matching rules and thresholds
4. OSINT data is automatically correlated with your alerts

### 4.3 IOC Management

**Route**: `/ioc-ingestion-matching`  
**API**: `GET /api/ioc-match`, `POST /api/ioc-match/ingest`, `POST /api/ioc-match/search`

Ingest, search, and match Indicators of Compromise across your alert data.

**Features**:

- Ingest IOCs (IP addresses, domains, file hashes, URLs, email addresses)
- Real-time matching against incoming alerts
- IOC enrichment from threat intel feeds
- Bulk IOC import (CSV/JSON)
- IOC aging and confidence scoring

**How to onboard IOCs**:

1. Navigate to Watch & Recon > IOC Management
2. Click "Ingest IOCs" and upload a CSV/JSON file or enter manually
3. IOCs are automatically matched against all incoming alerts
4. Matches appear in the IOC Match dashboard with confidence scores

### 4.4 CVE Database

**Route**: `/cve-browser`  
**API**: `GET /api/threat-intel/cves`, `GET /api/threat-intel/cves/:id`

Browse and search the CVE (Common Vulnerabilities and Exposures) database.

**Features**:

- Search CVEs by ID, vendor, product, severity
- View CVSS scores and affected products
- Track which CVEs affect your asset inventory
- Link CVEs to vulnerability scan results

### 4.5 Campaign Viewer

**Route**: `/campaign-viewer`  
**API**: `GET /api/threat-intel/campaigns`

Track and visualize threat actor campaigns.

**Features**:

- View active threat campaigns
- Link campaigns to observed alerts and IOCs
- Campaign timeline visualization
- Threat actor attribution

### 4.6 MITRE ATT&CK Navigator

**Route**: `/mitre-attack`  
**API**: `GET /api/threat-intel/mitre-coverage`

Interactive MITRE ATT&CK framework navigator.

**Features**:

- Heatmap showing your detection coverage across all MITRE techniques
- Click any technique to see related alerts and detection rules
- Gap analysis: identify techniques you have no detection for
- Export coverage reports

**How it works**: The navigator automatically maps your alerts, detection rules, and incidents to MITRE ATT&CK techniques, showing where you have coverage and where gaps exist.

### 4.7 Kill Chain Visualization

**Route**: `/kill-chain`  
**API**: `GET /api/threat-intel/kill-chain`

Visualize alerts and incidents mapped to the Cyber Kill Chain phases.

**Features**:

- Reconnaissance -> Weaponization -> Delivery -> Exploitation -> Installation -> C2 -> Actions on Objectives
- View which kill chain phases your alerts cover
- Identify gaps in detection at each phase

---

## 5. Investigation

### 5.1 Security Graph

**Route**: `/security-graph`  
**API**: `GET /api/security-graph`, `GET /api/security-graph/nodes`, `GET /api/security-graph/edges`

Interactive graph visualization of security entities and their relationships.

**Features**:

- Visualize relationships between IPs, hostnames, users, files, domains
- Click nodes to expand connections
- Filter by entity type, time range, severity
- Discover lateral movement paths

**How to onboard**:

- Assets from the graph are automatically created from alert data. When an alert arrives with an IP, hostname, or user, the entity resolver automatically creates nodes and links them.

### 5.2 Attack Paths

**Route**: `/attack-graph`  
**API**: `GET /api/attack-graphs`, `GET /api/attack-graphs/:id`

View AI-generated attack path graphs from deep investigations.

**Features**:

- Visual attack graph with nodes (TTPs, hosts, accounts) and edges (relationships)
- Generated automatically during AI deep investigation
- Shows initial access, lateral movement, and objectives
- Confidence scoring per node

### 5.3 Entity Explorer & Resolution

**Route**: `/entity-graph`, `/entity-merge-alias`  
**API**: `GET /api/entities`, `POST /api/entities/merge`, `POST /api/entities/alias`

Explore and manage security entities (IPs, hostnames, users, files).

**Features**:

- Entity Explorer: search and browse all entities with their alert/incident associations
- Entity Resolution: automatically merge duplicate entities (e.g., same IP appearing from different sources)
- Alias management: link related entities together (e.g., user@email.com = username = employee ID)

**How it works**: When alerts are ingested, the entity resolver (`resolveAndLinkEntities`) automatically extracts entities from alert fields (sourceIp, hostname, userId, fileHash, domain, url) and creates/links them in the entity graph.

### 5.4 War Room

**Route**: `/war-room`  
**API**: `GET /api/war-rooms`, `POST /api/war-rooms`, `POST /api/war-rooms/:id/messages`

Collaborative investigation workspace for incident response.

**Features**:

- Persistent war rooms tied to incidents
- Real-time messaging between team members
- Attach evidence, screenshots, and notes
- Timeline of all investigation actions
- Status updates and task assignment

**How to use**:

1. Navigate to Investigate > War Room
2. Create a new war room linked to an incident
3. Invite team members
4. Share findings, attach evidence, and coordinate response

### 5.5 Threat Hunting Workbench

**Route**: `/threat-hunting`  
**API**: `GET /api/threat-hunting/hunts`, `POST /api/threat-hunting/hunts`, `POST /api/threat-hunting/execute`

Proactive threat hunting with query engine and hypothesis testing.

**Features**:

- Custom threat hunting queries using the built-in query language
- Hunt library with pre-built hunt templates
- Pivot interface for drilling into results
- MITRE ATT&CK navigator integration
- AI-assisted hypothesis generation
- Hunt session tracking and documentation

**How to use**:

1. Navigate to Investigate > Threat Hunting
2. Create a new hunt with a hypothesis
3. Write queries to search across your alert data and telemetry
4. Analyze results and pivot to related data
5. Document findings and create incidents if threats are confirmed

### 5.6 Investigation Timeline

**Route**: `/investigation-timeline`  
**API**: `GET /api/investigation-timeline/:incidentId`

Chronological view of all events related to an incident.

**Features**:

- Visual timeline of alert events, analyst actions, and automated responses
- Filter by event type, severity, source
- Zoom into specific time windows
- Export timeline for reporting

### 5.7 Evidence Chain & Locker

**Route**: `/evidence-chain-viewer`, `/evidence-custody`  
**API**: `GET /api/evidence-custody`, `POST /api/evidence-custody`

Chain of custody tracking for digital evidence.

**Features**:

- Evidence Chain Viewer: visualize the chain of custody for each piece of evidence
- Evidence Locker: secure storage for investigation artifacts
- Custody transfer logging
- Tamper-proof hashing
- Export for legal proceedings

---

## 6. Response & Automation

### 6.1 Playbooks

**Route**: `/playbooks`  
**API**: `GET /api/playbooks`, `POST /api/playbooks`, `POST /api/playbooks/:id/execute`

Automated security response playbooks (SOAR).

**Features**:

- Visual playbook builder with drag-and-drop steps
- Conditional branching logic
- Integration with ticketing systems (Jira, ServiceNow)
- Notification actions (Slack, PagerDuty, email)
- Containment actions (isolate host, block IP, disable account)
- Manual approval gates for high-impact actions
- Execution history and audit trail

**How to onboard**:

1. Navigate to Respond > Playbooks
2. Click "Create Playbook"
3. Add steps: trigger conditions, enrichment actions, response actions
4. Set auto-trigger rules or manually trigger on incidents
5. Test with dry-run mode before enabling

### 6.2 Autonomous Response

**Route**: `/autonomous-response`  
**API**: `GET /api/autonomous-response/actions`, `POST /api/autonomous-response/execute`

AI-powered autonomous response actions for time-critical threats.

**Features**:

- Pre-defined response actions: isolate host, block IP, revoke session, disable user
- Confidence-gated execution: only auto-execute above configurable threshold
- Human-in-the-loop approval for medium-confidence actions
- Rollback capability for every action
- Risk scoring before execution

**How it works**: When the AI triage engine determines an alert is high-confidence and critical, it can automatically propose or execute response actions based on your configured policies.

### 6.3 Rollback History

**Route**: `/rollback-history`  
**API**: `GET /api/autonomous-response/rollbacks`

View and manage rollback operations for automated response actions.

**Features**:

- Full history of autonomous actions with rollback status
- One-click rollback for any automated action
- Impact assessment before rollback

### 6.4 Playbook & Runbook Libraries

**Route**: `/playbook-templates`, `/runbook-templates`  
**API**: `GET /api/playbook-templates`, `GET /api/runbook-templates`

Pre-built templates for common security scenarios.

**Features**:

- Playbook Library: SOAR automation templates (phishing response, malware containment, data breach, etc.)
- Runbook Library: step-by-step manual procedures for incident response
- Import/export templates
- Community-contributed templates

---

## 7. Posture Management

### 7.1 CSPM

**Route**: `/cspm`  
**API**: `GET /api/cspm/findings`, `POST /api/cspm/scan`, `GET /api/cspm/drift`

Cloud Security Posture Management for AWS, Azure, and GCP.

**Features**:

- **Cloud connectors**: AWS (via AssumeRole), Azure (via Service Principal), GCP (via Service Account)
- **Configuration scanning**: Check cloud resources against CIS benchmarks, NIST, PCI-DSS
- **Drift detection**: Monitor infrastructure changes and alert on deviations
- **DSPM (Data Security Posture)**: Find sensitive data in cloud storage
- **Attack path analysis**: Map cloud-specific attack paths
- **Auto-remediation**: Fix misconfigurations with one-click remediation scripts

**How to onboard cloud accounts**:

1. Navigate to Posture > CSPM
2. Click "Add Cloud Account"
3. Select provider (AWS/Azure/GCP)
4. Enter credentials:
   - **AWS**: Account ID, IAM Role ARN (for AssumeRole), External ID
   - **Azure**: Tenant ID, Subscription ID, Client ID, Client Secret
   - **GCP**: Project ID, Service Account JSON key
5. Select regions to scan
6. Choose compliance frameworks to check against
7. Click "Connect & Scan"

### 7.2 Endpoint Telemetry

**Route**: `/endpoint-telemetry`  
**API**: `GET /api/endpoint-telemetry`, `GET /api/endpoint-telemetry/agents`

Monitor endpoint agents and telemetry data.

**Features**:

- View all enrolled endpoint agents
- Monitor agent health and last check-in
- View telemetry data: process executions, file changes, network connections
- Agent version management

### 7.3 Vulnerability Management

**Route**: `/security-posture`  
**API**: `GET /api/security-posture`, `GET /api/security-posture/scores`

Unified vulnerability management and security posture scoring.

**Features**:

- Aggregate vulnerability data from scanners (Qualys, Tenable, Rapid7)
- Risk-prioritized vulnerability list
- Remediation tracking
- Security posture score (0-100) based on vulnerability severity distribution
- Trend charts showing posture improvement over time

### 7.4 JIT Access & Secret Rotation

**Route**: `/jit-secret-access`, `/secret-rotation-overview`  
**API**: `GET /api/jit-access`, `POST /api/jit-access/request`, `GET /api/secret-rotation`

Just-In-Time access provisioning and secret rotation management.

**Features**:

- **JIT Access**: Request time-limited elevated access to systems. Requires approval from admin. Access auto-revokes after the configured window.
- **Secret Rotation**: Track and automate rotation of API keys, passwords, certificates. Set rotation policies and get alerts before secrets expire.

---

## 8. AI Analyst

SecureNexus uses **Claude Sonnet 4** (for triage, correlation, narrative, and general analysis) and **Claude Opus 4** (for deep investigation) via **AWS Bedrock**.

### 8.1 AI Correlation Engine

**Route**: `/ai-engine`  
**API**: `POST /api/ai/correlate`, `POST /api/ai/correlate/apply`, `POST /api/ai/triage/:alertId`

The primary AI analysis interface.

**Features**:

- **Alert Correlation**: Select multiple alerts and ask the AI to find patterns, group them into incidents, and suggest incident titles
- **Single Alert Triage**: Deep AI analysis of a single alert -- severity assessment, MITRE mapping, false positive likelihood, containment advice, related IOCs
- **Apply Correlation**: One-click to create an incident from AI-correlated alert groups
- **Feedback Loop**: Rate AI outputs (thumbs up/down) to improve accuracy over time
- **Health Dashboard**: Monitor AI model status, latency, and error rates

**How to use**:

1. Navigate to AI Analyst > AI Engine
2. **Correlate**: Select "All pending" or manually pick alerts, click "Run Correlation"
3. **Triage**: Select an alert from the dropdown, click "Run Triage"
4. Review the AI output (MITRE mapping, severity, reasoning, IOCs)
5. Provide feedback using the thumbs up/down buttons

**How it works technically**:

1. Alerts are sent to the prompt registry which looks up the appropriate prompt template
2. Threat intelligence context is built from IOC enrichment, OSINT feeds, and RAG vector search
3. The prompt + context + alert data is sent to Claude via AWS Bedrock
4. Response is parsed and stored in the database
5. Audit log records the AI action
6. Usage is tracked against the org's AI budget

### 8.2 SOC Co-Pilot

**Route**: `/soc-copilot`  
**API**: `POST /api/ai/multi-turn-investigation`

Interactive AI chat for security investigations.

**Features**:

- Multi-turn conversation with Claude about incidents
- Context-aware: the AI has access to incident data, alert details, and entity information
- Ask follow-up questions, request deeper analysis, or ask for recommendations
- Conversation history is maintained per session

**How to use**:

1. Navigate to AI Analyst > SOC Co-Pilot
2. Select an incident to investigate
3. Type your question (e.g., "What is the attacker's likely objective?")
4. The AI responds with analysis based on incident context
5. Continue the conversation with follow-up questions

### 8.3 Prompt Builder

**Route**: `/prompt-to-artifact`  
**API**: `POST /api/ai/prompt-to-artifact`

Build custom AI prompts for security artifact generation.

**Features**:

- Create custom prompt templates for specific analysis tasks
- Generate security artifacts: detection rules, incident reports, threat assessments
- Template library with pre-built prompts

### 8.4 Model Gateway

**Route**: `/model-gateway`  
**API**: `GET /api/ai/health`, `GET /api/ai/config`, `GET /api/ai/inference-metrics`, `POST /api/ai/cache/clear`

Monitor and manage AI model infrastructure.

**Features**:

- **Health monitoring**: Check model availability and latency
- **Configuration view**: See active model IDs, temperature, max tokens
- **Inference metrics**: Latency percentiles, error rates, throughput
- **Response caching**: Cached responses for identical queries (5-minute TTL, 200-entry max)
- **Circuit breaker**: Automatically disables AI calls after repeated failures, auto-recovers after cooldown
- **Cost estimation**: Per-invocation cost tracking based on input/output token counts
- **Cache clearing**: Manually clear the response cache

**How it works**: The model gateway sits between application code and AWS Bedrock. It adds caching, circuit breaking, cost tracking, budget enforcement, and metrics collection to every AI invocation.

### 8.5 Prompt Registry

**Route**: `/ai-prompt-registry`  
**API**: `GET /api/ai/prompts`, `GET /api/ai/prompts/audit`

Versioned prompt template management.

**Features**:

- View all registered AI prompts with their versions
- Prompt audit log: track who changed which prompt and when
- Version history: see how prompts have evolved
- Prompt IDs: `triage`, `correlation`, `narrative`, `investigation`, `threat_hunt`, `behavioral_analysis`, `attack_path`, `detection_rule_generation`, `multi_turn_investigation`

### 8.6 Feedback Loop (Active Learning)

**Route**: `/ai-feedback`  
**API**: `POST /api/ai/feedback`, `GET /api/ai/feedback/metrics`, `POST /api/ai/feedback/:id/outcome`

Active learning system that improves AI accuracy based on analyst feedback.

**Features**:

- Rate AI outputs (1-5 stars)
- Mark AI decisions: approve, reject, or correct
- Feedback is injected as few-shot examples into future prompts
- False positive suppression: if analysts repeatedly reject a specific pattern, the AI learns to suppress it
- Source-level suppression: downweight noisy alert sources
- Drift detection: track if AI accuracy is improving or degrading over time

**How to onboard**:

1. Use the AI Engine or SOC Co-Pilot to generate AI analyses
2. After each analysis, use the feedback buttons to rate the output
3. If the AI was wrong, select "Correct" and provide the right answer
4. Over time, the system accumulates corrections that improve future analyses

### 8.7 Budget & Limits

**Route**: `/ai-budget-controls`  
**API**: `GET /api/ai/budget`, `PUT /api/ai/budget`, `GET /api/ai/budget/all`

Control AI spending per organization.

**Features**:

- Set monthly AI budget per org (in tokens or USD)
- View current usage vs. budget
- Per-model cost tracking (Claude Sonnet: $0.003/1K input, $0.015/1K output; Claude Opus: $0.015/1K input, $0.075/1K output)
- Automatic enforcement: AI calls are rejected when budget is exceeded
- Usage history and trend charts

---

## 9. Data & Integrations

### 9.1 Connectors

**Route**: `/connectors`  
**API**: `GET /api/connectors`, `POST /api/connectors`, `POST /api/connectors/:id/sync`, `POST /api/connectors/:id/test`

Pre-built integrations for pulling security data from external systems.

**Supported connector types**:
| Connector | Category | Auth Type |
|-----------|----------|-----------|
| CrowdStrike | EDR | API Key |
| Splunk | SIEM | Token |
| Microsoft Sentinel | SIEM | OAuth |
| SentinelOne | EDR | API Key |
| Palo Alto | Firewall | API Key |
| AWS GuardDuty | Cloud | IAM Role |
| Microsoft Defender | EDR | OAuth |
| Elastic Security | SIEM | API Key |
| IBM QRadar | SIEM | Token |
| Fortinet FortiGate | Firewall | API Key |
| Carbon Black | EDR | API Key |
| Qualys | Vuln Scanner | API Key |
| Tenable | Vuln Scanner | API Key |
| Cisco Umbrella | DNS Security | API Key |
| Darktrace | NDR | Token |
| Rapid7 InsightIDR | SIEM | API Key |
| Trend Micro Vision One | XDR | API Key |
| Okta | Identity | API Key |
| Proofpoint | Email Security | API Key |
| Snort | IDS | Syslog |
| Zscaler | Web Security | API Key |
| Check Point | Firewall | API Key |

**How to onboard a connector**:

1. Navigate to Data & Integrations > Connectors
2. Click "Add Connector"
3. Select the connector type from the list
4. Enter a name and authentication credentials:
   - **API Key connectors**: Enter the API URL and API key from your security tool
   - **OAuth connectors**: Follow the OAuth flow to authorize SecureNexus
   - **Token connectors**: Enter the token provided by your SIEM
5. Click "Test Connection" to verify connectivity
6. Set the polling interval (how often to sync, default 5 minutes)
7. Click "Save"
8. Click "Sync Now" for the initial data pull

**Connector features**:

- **Auto-sync**: Connectors poll automatically at the configured interval
- **Health checks**: Monitor connector health and credential validity
- **Secret rotation**: Schedule automatic credential rotation
- **Job history**: View all sync jobs with success/failure status
- **Dead letter queue**: Failed syncs are retried with exponential backoff
- **Concurrency control**: Rate limiting to prevent overwhelming source APIs
- **Metrics**: Track alerts synced, deduplication rate, error rate per connector

### 9.2 Integration Marketplace

**Route**: `/integration-marketplace`  
**API**: `GET /api/integration-marketplace`

Browse and install integrations.

**Features**:

- Catalog of available integrations organized by category
- One-click installation
- Configuration wizard for each integration
- Version management and updates

### 9.3 Native Collectors

**Route**: `/native-collectors`  
**API**: `GET /api/native-collectors`, `POST /api/native-collectors`

SecureNexus-native data collection agents.

**Features**:

- Lightweight agents for direct log collection
- Syslog receiver
- Windows Event Log collector
- File integrity monitoring
- Agent deployment guides

**How to onboard**:

1. Navigate to Data & Integrations > Native Collectors
2. Download the agent for your OS
3. Install and configure with your SecureNexus API key
4. The agent will begin sending telemetry automatically

### 9.4 Webhooks

**Route**: `/webhook-security-center`  
**API**: `GET /api/webhooks`, `POST /api/webhooks`

Manage outbound webhook notifications.

**Features**:

- Configure webhooks for alert/incident events
- Webhook signature verification (HMAC)
- Delivery tracking and retry logic
- Filter events by type, severity, source

### 9.5 Ingestion Pipeline

**Route**: `/ingestion`  
**API**: `POST /api/ingest/:source`, `POST /api/ingest/:source/bulk`, `GET /api/ingestion/logs`, `GET /api/ingestion/stats`

Direct API ingestion for custom data sources.

**How to ingest data via API**:

1. **Create an API key** (Admin & Settings > Developer Portal)
2. **Send data** to the ingestion endpoint:

```bash
# Single alert
curl -X POST https://your-securenexus.com/api/ingest/custom \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Suspicious login from unusual location",
    "severity": "high",
    "category": "intrusion",
    "source_ip": "203.0.113.42",
    "hostname": "web-server-01",
    "user": "admin",
    "description": "Login from IP not seen in last 90 days"
  }'

# Bulk ingestion (up to 1000 events)
curl -X POST https://your-securenexus.com/api/ingest/custom/bulk \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '[
    {"title": "Alert 1", "severity": "high", ...},
    {"title": "Alert 2", "severity": "medium", ...}
  ]'
```

**Supported source keys for `/api/ingest/:source`**:
`crowdstrike`, `splunk`, `paloalto`, `guardduty`, `suricata`, `defender`, `elastic`, `qradar`, `fortigate`, `carbonblack`, `qualys`, `tenable`, `umbrella`, `darktrace`, `rapid7`, `trendmicro`, `okta`, `proofpoint`, `snort`, `zscaler`, `checkpoint`, `custom`

Each source has a specialized normalizer that maps vendor-specific fields to the SecureNexus alert schema. The `custom` source accepts arbitrary JSON and maps common field names automatically.

**What happens during ingestion**:

1. Payload is validated
2. Alert is normalized to the standard schema
3. Alert is deduplicated (based on sourceEventId + source)
4. Entity resolution: IPs, hostnames, users, domains are extracted and linked in the entity graph
5. Correlation engine checks for pattern matches with existing alerts
6. Real-time event broadcast to connected UI clients
7. Ingestion log is recorded
8. Usage counter is incremented

### 9.6 Job Queue

**Route**: `/job-queue-dashboard`  
**API**: `GET /api/job-queue`, `POST /api/job-queue/:id/retry`

Monitor and manage background processing jobs.

**Features**:

- View all queued, running, completed, and failed jobs
- Retry failed jobs
- Job execution history with timing data
- Filter by job type, status, connector

### 9.7 Outbox Monitor

**Route**: `/outbox-monitor`  
**API**: `GET /api/outbox-events`, `POST /api/outbox-events/replay`

Monitor the transactional outbox for event delivery.

**Features**:

- View pending and delivered outbox events
- Replay failed events
- Event delivery status tracking

### 9.8 Data Lake

**Route**: `/data-lake`  
**API**: `GET /api/data-lake/tables`, `POST /api/data-lake/query`, `GET /api/data-lake/retention-policies`

Cold storage and long-term data retention.

**Features**:

- **Hot/Warm/Cold tiering**: Automatically tier data based on age
- **Query federation**: Search across all data tiers with a unified query interface
- **Retention policies**: Configure how long data is retained per category
- **Legal holds**: Freeze data deletion for legal/compliance requirements
- **eDiscovery**: Search and export data for legal proceedings
- **Data purge**: Scheduled purging of expired data

**How to onboard**:

1. Navigate to Data & Integrations > Data Lake
2. Configure retention policies for each data type (alerts, incidents, audit logs)
3. Set hot-to-warm and warm-to-cold transition periods
4. Data tiers automatically based on configured policies

---

## 10. Standalone Security Modules

### 10.1 Asset Inventory

**Route**: `/asset-inventory`  
**API**: `GET /api/assets`, `POST /api/assets`, `PATCH /api/assets/:id`, `DELETE /api/assets/:id`

Complete organizational asset management with risk scoring.

**Asset types**: server, workstation, laptop, mobile, network_device, firewall, cloud_instance, container, database, application, iot_device, printer, storage, virtual_machine, other

**Fields per asset**:
| Field | Description |
|-------|------------|
| `name` | Asset name (required) |
| `assetType` | Type from the list above |
| `criticality` | critical / high / medium / low |
| `lifecycleStatus` | active / procurement / maintenance / decommissioning / retired |
| `environment` | production / staging / development / testing / dr |
| `ipAddress` | IP address |
| `hostname` | Hostname or FQDN |
| `owner` | Responsible team or person |
| `department` | Owning department |
| `location` | Physical or cloud location |
| `operatingSystem` | OS name and version |
| `manufacturer` | Hardware/cloud vendor |
| `model` | Hardware model or instance type |
| `riskScore` | Computed risk score (0-100) |
| `vulnerabilityCount` | Number of known vulnerabilities |
| `tags` | Custom tags for categorization |

**How to onboard assets**:

**Method 1: Manual Entry**

1. Navigate to Standalone Security > Asset Inventory
2. Click "Add Asset"
3. Fill in the form:
   - Asset Name (required, e.g., "Production Web Server 01")
   - Type (server, workstation, etc.)
   - Criticality (critical, high, medium, low)
   - Environment (production, staging, etc.)
   - IP Address, Hostname, Owner, Department, Location
   - OS, Manufacturer, Model
   - Notes
4. Click "Create Asset"

**Method 2: Via API**

```bash
curl -X POST https://your-securenexus.com/api/assets \
  -H "Authorization: Bearer YOUR_SESSION_COOKIE" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production Web Server 01",
    "assetType": "server",
    "criticality": "critical",
    "environment": "production",
    "ipAddress": "10.0.1.100",
    "hostname": "web-prod-01",
    "owner": "IT Operations",
    "department": "Engineering",
    "location": "AWS us-east-1",
    "operatingSystem": "Ubuntu 22.04",
    "manufacturer": "AWS",
    "model": "t3.large"
  }'
```

**Method 3: Auto-Discovery**

- Assets are automatically created when alerts arrive with new IPs, hostnames, or identities
- CSPM scanning discovers cloud resources automatically
- Native sensor agents register themselves as assets

**How assets connect to other features**:

- **Vulnerability Scanner**: Scans assets for known vulnerabilities
- **UEBA**: Monitors user/entity behavior against baselines
- **Detection Rules**: Trigger on events related to specific assets
- **CSPM**: Maps cloud resources as assets
- **Risk Register**: Assets are associated with risk entries
- **Compliance**: Assets are mapped to compliance control requirements

### 10.2 Risk Register

**Route**: `/risk-register`  
**API**: `GET /api/risk-register`, `POST /api/risk-register`, `PATCH /api/risk-register/:id`

Organizational risk tracking and management.

**Features**:

- Create and track security risks with impact/likelihood scoring
- Risk categories: technical, operational, compliance, strategic
- Risk treatments: accept, mitigate, transfer, avoid
- Link risks to assets, incidents, and compliance controls
- Risk heatmap visualization
- Risk trend tracking over time

### 10.3 Native Sensors

**Route**: `/native-sensors`  
**API**: `GET /api/native-sensors`, `POST /api/native-sensors/deploy`, `GET /api/native-sensors/telemetry`

Deploy lightweight detection sensors to endpoints and networks.

**Features**:

- Agent protocol for sensor communication
- 45 pre-built MITRE ATT&CK detection rules
- Sensor health monitoring
- Telemetry collection (process, file, network, registry events)
- Sensor deployment guides for Linux, Windows, macOS

**How to onboard**:

1. Navigate to Standalone Security > Native Sensors
2. Click "Deploy Sensor"
3. Select target OS and download the installer
4. Install on target endpoints
5. Sensors auto-register and begin reporting telemetry

### 10.4 Detection Rules

**Route**: `/detection-rules`  
**API**: `GET /api/detection-rules`, `POST /api/detection-rules`, `PATCH /api/detection-rules/:id`

Create and manage detection rules for alerting.

**Features**:

- Rule types: Sigma, YARA, custom
- JSON rule builder for complex conditions
- MITRE ATT&CK technique mapping per rule
- Type filter: filter rules by detection type
- MITRE ATT&CK heatmap showing rule coverage
- Rule severity assignment
- Enable/disable rules
- Rule testing against historical data

**How to onboard detection rules**:

1. Navigate to Standalone Security > Detection Rules
2. Click "Create Rule"
3. Choose rule format (Sigma, YARA, or Custom JSON)
4. Define the detection logic:
   - For Sigma: enter the YAML-based rule definition
   - For YARA: enter the YARA rule syntax
   - For Custom: use the JSON rule builder
5. Map to MITRE ATT&CK techniques
6. Set severity and enable/disable
7. Click "Save"

### 10.5 Vulnerability Scanner

**Route**: `/vuln-scanner`  
**API**: `GET /api/vuln-scanner/scans`, `POST /api/vuln-scanner/scans`, `GET /api/vuln-scanner/findings`

Built-in vulnerability scanning capabilities.

**Features**:

- Scan assets for known vulnerabilities
- Integration with CVE database
- Prioritized findings by CVSS score and asset criticality
- Remediation tracking
- Scan scheduling

**How to onboard**:

1. Navigate to Standalone Security > Vuln Scanner
2. Click "New Scan"
3. Select target assets (from Asset Inventory)
4. Choose scan profile (quick/full/custom)
5. Run scan and view findings

### 10.6 Agent Response

**Route**: `/agent-response`  
**API**: `GET /api/agent-response/actions`, `POST /api/agent-response/execute`

Execute remote response actions on managed endpoints.

**Features**:

- Isolate host from network
- Kill malicious processes
- Quarantine suspicious files
- Collect forensic artifacts
- Push configuration changes
- Response action audit trail

### 10.7 UEBA Analytics

**Route**: `/ueba`  
**API**: `GET /api/ueba/entities`, `GET /api/ueba/baselines`, `POST /api/ueba/analyze`

User and Entity Behavior Analytics for insider threat detection.

**Features**:

- Behavioral baselining for users and entities
- Anomaly detection (unusual login times, locations, data access patterns)
- Risk scoring per entity
- Peer group comparison
- AI-powered behavioral analysis (via Claude)
- Timeline of behavioral anomalies

**How to onboard**:

1. Ensure alerts are flowing in from identity providers (Okta, Azure AD) and endpoint tools
2. Navigate to Standalone Security > UEBA Analytics
3. The system automatically builds behavioral baselines over 30 days
4. Review anomalies and tune sensitivity thresholds

### 10.8 Supply Chain Security

**Route**: `/supply-chain`  
**API**: `GET /api/supply-chain/sboms`, `POST /api/supply-chain/sbom/upload`, `GET /api/supply-chain/dependencies`

Software supply chain security management.

**Features**:

- **SBOM ingestion**: Upload CycloneDX or SPDX Software Bills of Materials
- **Dependency graph**: Visualize your software dependency tree
- **Typosquatting detection**: Identify potentially malicious package names
- **IaC scanning**: Scan Terraform/CloudFormation templates for misconfigurations
- **Vulnerability mapping**: Cross-reference dependencies with CVE database
- **License compliance**: Track open-source license obligations

**How to onboard**:

1. Navigate to Standalone Security > Supply Chain Security
2. Upload your SBOM files (CycloneDX JSON/XML or SPDX)
3. Or connect your CI/CD pipeline to auto-submit SBOMs on each build
4. Review the dependency graph and vulnerability findings
5. Set up alerts for new vulnerabilities in your dependencies

### 10.9 Identity Governance & PAM

**Route**: `/identity-governance`  
**API**: `GET /api/identity-governance/users`, `POST /api/identity-governance/access-reviews`, `GET /api/identity-governance/pam-sessions`

Identity threat detection and privileged access management.

**Features**:

- **Access reviews**: Periodic certification of user access rights
- **Privileged Access Management**: Checkout/checkin sessions for admin accounts
- **SCIM provisioning**: Automated user lifecycle management
- **Blast radius analysis**: What can a compromised account access?
- **Lateral movement detection**: Identify suspicious access patterns
- **Orphaned accounts**: Find accounts with no owner

**How to onboard**:

1. Navigate to Standalone Security > Identity Governance
2. Connect your identity provider (Okta, Azure AD, etc.) via Connectors
3. Import user directory
4. Configure access review schedules
5. Set up PAM checkout policies for privileged accounts

### 10.10 Deception Technology

**Route**: `/deception`  
**API**: `GET /api/deception/tokens`, `POST /api/deception/tokens`, `GET /api/deception/honeypots`

Deploy decoys to detect attackers who have bypassed perimeter defenses.

**Features**:

- **Canary tokens**: Deploy fake credentials, documents, or URLs that alert when accessed
- **Honeypots**: Virtual systems that look like real infrastructure to attract attackers
- **Network decoys**: Fake services that alert on connection attempts
- **Deployment wizard**: Step-by-step guide to deploying deception assets

**How to onboard**:

1. Navigate to Standalone Security > Deception Technology
2. Click "Create Canary Token" or "Deploy Honeypot"
3. For canary tokens: choose type (API key, AWS credential, document, URL), generate, and place in your environment
4. For honeypots: select a service template (SSH, RDP, HTTP, SMB), configure the decoy, and deploy
5. Any interaction with deception assets generates high-confidence alerts

### 10.11 OT/ICS Security

**Route**: `/ot-security`  
**API**: `GET /api/ot-security/assets`, `POST /api/ot-security/assets`, `GET /api/ot-security/protocols`

Operational Technology and Industrial Control System security.

**Features**:

- **Passive asset discovery**: Identify OT/ICS devices without active scanning
- **Protocol parsers**: Modbus, DNP3, BACnet, EtherNet/IP, OPC UA, PROFINET, S7comm, IEC 61850
- **Purdue Model visualization**: Map your OT architecture across Purdue Model levels (0-5)
- **IT/OT boundary monitoring**: Monitor traffic crossing IT/OT boundaries
- **Anomaly detection**: Detect unusual OT protocol behavior
- **Asset lifecycle management**: Track PLC, HMI, RTU, SCADA assets

**How to onboard OT assets**:

1. Navigate to Standalone Security > OT/ICS Security
2. Click "Add Asset" in the Asset Discovery tab
3. Enter device details: name, type (PLC, HMI, RTU, SCADA, DCS, SIS, Historian, Engineering Workstation, Network Switch, Gateway), manufacturer, model, firmware version
4. Set Purdue Model level (0=Process, 1=Control, 2=Supervisory, 3=Operations, 3.5=DMZ, 4=Enterprise, 5=Internet)
5. Assign zone and network segment
6. Configure protocol monitoring for the asset

### 10.12 Mobile & Remote Security

**Route**: `/mobile-security`  
**API**: `GET /api/mobile-security/devices`, `POST /api/mobile-security/policies`, `GET /api/mobile-security/posture-checks`

Secure mobile devices and remote workers.

**Features**:

- **MDM integration**: Connect Microsoft Intune, Jamf, VMware Workspace ONE
- **Device posture checks**: Verify OS version, encryption, jailbreak status, screen lock
- **ZTNA policies**: Zero Trust Network Access policies based on device posture and user identity
- **Mobile threat detection**: Detect malicious apps, network attacks, phishing
- **Remote worker risk scoring**: Assess risk based on location, network, device state

**How to onboard**:

1. Navigate to Standalone Security > Mobile Security
2. Click "Configure MDM" to connect your MDM provider
3. Set up posture check policies (required OS version, encryption, etc.)
4. Create ZTNA policies for conditional access
5. Mobile devices are automatically enrolled via MDM

### 10.13 API Security

**Route**: `/api-security`  
**API**: `GET /api/api-security/inventory`, `POST /api/api-security/scan`, `GET /api/api-security/findings`

Protect and monitor your APIs.

**Features**:

- **API inventory discovery**: Automatically discover and catalog your APIs
- **Schema validation**: Check API schemas against OpenAPI/Swagger specs
- **Abuse detection**: Identify API abuse patterns (credential stuffing, scraping, fuzzing)
- **Sensitive data scanning**: Find PII/PHI/PCI data in API responses
- **DAST testing**: Dynamic application security testing for APIs
- **Shadow API detection**: Find undocumented APIs

**How to onboard**:

1. Navigate to Standalone Security > API Security
2. Upload your OpenAPI/Swagger specs or enable auto-discovery
3. Configure API traffic monitoring (via reverse proxy or agent)
4. Set up abuse detection rules
5. Schedule DAST scans

### 10.14 Ransomware Defense

**Route**: `/ransomware-defense`  
**API**: `GET /api/ransomware-defense/indicators`, `POST /api/ransomware-defense/kill-switch`, `GET /api/ransomware-defense/exercises`

Comprehensive ransomware prevention, detection, and response.

**Features**:

- **Kill switch**: Emergency network isolation to stop ransomware spread
- **Canary files**: Deploy canary files that alert when encrypted (early ransomware detection)
- **Ransomware intelligence**: Track known ransomware variants and TTPs
- **AI recovery runbooks**: AI-generated step-by-step recovery procedures
- **Tabletop exercises**: Simulate ransomware scenarios for team training
- **Backup verification**: Validate backup integrity and recoverability

**How to onboard**:

1. Navigate to Standalone Security > Ransomware Defense
2. Deploy canary files across critical file shares
3. Configure the kill switch with network isolation rules
4. Subscribe to ransomware intelligence feeds
5. Schedule regular tabletop exercises

### 10.15 Community Threat Intel

**Route**: `/community-intel`  
**API**: `GET /api/community-intel/iocs`, `POST /api/community-intel/submit`, `GET /api/community-intel/feeds`

Anonymous threat intelligence sharing with the security community.

**Features**:

- **Anonymous IOC sharing**: Submit IOCs without revealing your identity
- **Industry feeds**: Subscribe to threat intel from your industry sector
- **Campaign correlation**: Automatically correlate community IOCs with your alerts
- **Confidence scoring**: Community-voted IOC quality scoring

### 10.16 Security Posture Score & Trust Center

**Route**: `/posture-trust-center`  
**API**: `GET /api/posture-trust/score`, `GET /api/posture-trust/benchmarks`, `GET /api/posture-trust/public`

Real-time security posture scoring and public trust pages.

**Features**:

- **Posture score** (0-100) based on: vulnerability severity, compliance status, incident MTTR, detection coverage, configuration drift
- **Peer benchmarking**: Compare your posture against industry peers
- **Public trust center**: Customer-facing page showing your security certifications and posture
- **Questionnaire automation**: Auto-fill vendor security questionnaires
- **Score trend charts**: Track posture improvement over time

### 10.17 Security Chaos Engineering

**Route**: `/chaos-engineering`  
**API**: `GET /api/chaos-engineering/exercises`, `POST /api/chaos-engineering/exercises`, `GET /api/chaos-engineering/coverage`

Test your defenses by simulating attacks.

**Features**:

- **MITRE ATT&CK coverage heatmap**: Visualize which techniques you can detect
- **Purple team automation**: Automated red+blue team exercises
- **BAS dashboard**: Breach and Attack Simulation results
- **Exercise tracking**: Schedule and track chaos engineering exercises
- **Gap identification**: Find weaknesses in your detection capabilities

### 10.18 AI Detection Rules

**Route**: `/ai-detection-rules`  
**API**: `POST /api/ai/generate-detection-rules`, `GET /api/ai-detection-rules/rules`

AI-generated detection rule creation.

**Features**:

- **LLM-powered rule generation**: Describe a threat in natural language, get Sigma/YARA rules
- **Quality scoring**: AI-generated rules are scored for coverage, false positive rate, and specificity
- **A/B testing**: Test new rules against historical data before deployment
- **Lifecycle management**: Rules go through draft -> testing -> active -> deprecated states
- **Community marketplace**: Share and discover AI-generated rules

**How to use**:

1. Navigate to Standalone Security > AI Detection Rules
2. Describe the threat you want to detect (e.g., "Detect PowerShell downloading executables from unusual domains")
3. Click "Generate Rules"
4. Review the AI-generated Sigma/YARA rules
5. Test against historical data
6. Deploy to production

### 10.19 Autonomous SOC

**Route**: `/autonomous-soc`  
**API**: `GET /api/autonomous-soc/tiers`, `POST /api/autonomous-soc/analyze`, `GET /api/autonomous-soc/decisions`

AI-native 3-tier SOC analyst automation.

**Features**:

- **Tier 1 (Autonomous)**: Fully automated alert triage, false positive filtering, and initial enrichment
- **Tier 2 (Semi-Autonomous)**: AI-assisted investigation with human approval for actions
- **Tier 3 (Assisted)**: Deep investigation support for senior analysts with AI recommendations
- **Decision audit trail**: Every AI decision is logged with reasoning
- **Escalation policies**: Configure when to escalate between tiers

**How it works**:

1. Alerts enter the Tier 1 queue for autonomous processing
2. The AI triages each alert, enriches with threat intel, and assigns confidence
3. High-confidence false positives are auto-closed (with audit log)
4. Medium-confidence alerts are escalated to Tier 2 for human review
5. Complex incidents are escalated to Tier 3 for deep investigation

### 10.20 Developer Security (Shift-Left)

**Route**: `/developer-security`  
**API**: `GET /api/developer-security/repos`, `POST /api/developer-security/scan`, `GET /api/developer-security/findings`

Security tools for the development pipeline.

**Features**:

- **SAST engine**: Static Application Security Testing for code repositories
- **Secret scanning**: Find hardcoded secrets in source code
- **CI gates**: Block deployments with critical security findings
- **GitHub/GitLab integration**: Automated PR comments with security findings
- **Code review assistant**: AI-powered security review suggestions
- **Security debt tracker**: Track and prioritize security tech debt

**How to onboard**:

1. Navigate to Standalone Security > Developer Security
2. Connect your GitHub/GitLab organization
3. Select repositories to scan
4. Configure CI gate policies (block on critical, warn on high)
5. Enable automated PR comments
6. Set up scheduled scans

### 10.21 TPRM (Third-Party Risk)

**Route**: `/tprm`  
**API**: `GET /api/tprm/vendors`, `POST /api/tprm/vendors`, `GET /api/tprm/questionnaires`

Third-Party Risk Management for vendor security assessment.

**Features**:

- **Vendor inventory**: Track all third-party vendors with risk ratings
- **Questionnaire automation**: Send and collect security questionnaires
- **Continuous monitoring**: Monitor vendor breach news and reputation
- **Breach alerting**: Get notified when a vendor has a public breach
- **Contract risk mapping**: Map contract terms to risk categories
- **Fourth-party risk**: Assess the risks of your vendors' vendors

**How to onboard vendors**:

1. Navigate to Standalone Security > TPRM
2. Click "Add Vendor"
3. Enter vendor details: name, category, criticality, contact
4. Send a security questionnaire
5. Review responses and assign a risk rating
6. Enable continuous monitoring for breach alerts

### 10.22 Dark Web Monitoring

**Route**: `/dark-web-monitoring`  
**API**: `GET /api/dark-web/alerts`, `POST /api/dark-web/monitors`, `GET /api/dark-web/credentials`

Monitor the dark web for threats to your organization.

**Features**:

- **Credential exposure**: Find leaked credentials for your domain
- **Breach integration**: Correlate dark web finds with known breaches
- **Brand monitoring**: Track mentions of your brand on dark web forums
- **Threat actor tracking**: Monitor specific threat actors targeting your industry

**How to onboard**:

1. Navigate to Standalone Security > Dark Web Monitoring
2. Add your domains and email patterns to monitor
3. Configure alert thresholds
4. Review dark web findings as they arrive

### 10.23 Physical Security

**Route**: `/physical-security`  
**API**: `GET /api/physical-security/zones`, `POST /api/physical-security/zones`, `GET /api/physical-security/incidents`

Physical security convergence with cyber security.

**Features**:

- **Zone management**: Define physical security zones (buildings, floors, rooms)
- **Access control integration**: Connect badge readers and access control systems
- **Physical-cyber correlation**: Correlate physical access events with cyber alerts
- **Incident tracking**: Track physical security incidents alongside cyber incidents
- **Camera integration**: Link camera feeds to security zones

### 10.24 Phishing & Security Awareness

**Route**: `/security-awareness`  
**API**: `GET /api/security-awareness/campaigns`, `POST /api/security-awareness/campaigns`, `GET /api/security-awareness/metrics`

Run phishing simulations and security awareness training.

**Features**:

- **Phishing simulation campaigns**: Send realistic phishing emails to test employees
- **Click tracking**: Track who opens, clicks, and reports phishing emails
- **Training modules**: Assign and track security awareness training
- **Risk scoring**: Per-employee and per-department phishing risk scores
- **Campaign templates**: Pre-built phishing email templates
- **Reporting**: Campaign results with improvement trends

**How to onboard**:

1. Navigate to Standalone Security > Phishing & Awareness
2. Create a new campaign
3. Select a phishing template or create custom
4. Choose target user groups
5. Set schedule and launch
6. Monitor results in real-time

### 10.25 Quantum Readiness

**Route**: `/quantum-readiness`  
**API**: `GET /api/quantum-readiness/inventory`, `POST /api/quantum-readiness/scan`, `GET /api/quantum-readiness/migration`

Prepare for the post-quantum cryptography transition.

**Features**:

- **Cryptographic inventory**: Discover and catalog all cryptographic algorithms in use
- **Vulnerability scoring**: Assess quantum vulnerability of each algorithm
- **PQC migration planning**: Create a migration plan to post-quantum cryptographic algorithms
- **NIST compliance tracking**: Track progress against NIST PQC standards
- **Algorithm classification**: Safe (PQC-ready), Vulnerable (RSA, ECDSA), Unknown

**How to onboard**:

1. Navigate to Standalone Security > Quantum Readiness
2. Click "Scan" to discover cryptographic algorithms in your infrastructure
3. Review the inventory and vulnerability scores
4. Create a migration plan for vulnerable algorithms
5. Track migration progress against NIST PQC recommendations

### 10.26 Privacy Engineering

**Route**: `/privacy-engineering`  
**API**: `GET /api/privacy-engineering/data-stores`, `POST /api/privacy-engineering/pia`, `GET /api/privacy-engineering/consents`

Data Security Posture Management and privacy compliance.

**Features**:

- **Data discovery**: Scan data stores to find PII, PHI, PCI data
- **Classification engine**: Automatically classify data by sensitivity level
- **Privacy Impact Assessments (PIAs)**: Structured assessment templates
- **Consent management**: Track user consent for data processing
- **Cross-border risk**: Assess data transfer risks between jurisdictions
- **DSAR automation**: Automate Data Subject Access Request processing
- **Data mapping**: Visualize data flows across systems

**How to onboard**:

1. Navigate to Standalone Security > Privacy Engineering
2. Add data stores to scan (databases, file shares, cloud storage)
3. Run a discovery scan to find sensitive data
4. Review classification results
5. Create PIAs for systems processing personal data
6. Set up consent tracking and DSAR workflows

### 10.27 DNS Security

**Route**: `/dns-security`  
**API**: `GET /api/dns-security/queries`, `POST /api/dns-security/policies`, `GET /api/dns-security/analytics`

DNS-layer threat detection and protection.

**Features**:

- **DNS query monitoring**: Log and analyze all DNS queries
- **Threat detection**: Detect DNS tunneling, DGA domains, fast-flux networks
- **Policy enforcement**: Block malicious domains
- **Analytics**: DNS query volume, top queried domains, geographic distribution
- **Controlled domains**: Manage domain allowlists and blocklists
- **DNS sinkholing**: Redirect malicious domains to a sinkhole

**How to onboard**:

1. Navigate to Standalone Security > DNS Security
2. Configure DNS log forwarding from your DNS servers
3. Set up detection policies for DNS-based threats
4. Configure domain blocklists/allowlists
5. Monitor the analytics dashboard for anomalies

### 10.28 Email Security

**Route**: `/email-security`  
**API**: `GET /api/email-security/threats`, `POST /api/email-security/scan`, `GET /api/email-security/policies`

Email-based threat detection and protection.

**Features**:

- **BEC detection**: Business Email Compromise detection using AI
- **Thread injection detection**: Detect conversation hijacking
- **Retroactive IOC scanning**: Scan historical emails against new IOCs
- **M365/Gmail integration**: Connect Microsoft 365 or Google Workspace
- **Email header analysis**: Analyze email authentication (SPF, DKIM, DMARC)
- **Quarantine management**: Review and release quarantined emails

**How to onboard**:

1. Navigate to Standalone Security > Email Security
2. Connect your email provider (M365 or Gmail) via OAuth
3. Configure scanning policies
4. Set up BEC detection rules
5. Review threats in the dashboard

### 10.29 MSSP Dashboard & Partner Portal

**Route**: `/mssp-dashboard`, `/mssp-partner-portal`  
**API**: `GET /api/mssp-portal/clients`, `POST /api/mssp-portal/clients`, `GET /api/mssp-portal/branding`

Multi-tenant management for Managed Security Service Providers.

**Features**:

- **Client management**: Manage multiple client organizations from a single dashboard
- **White-label branding**: Customize logos, colors, and domain for each client
- **SLA management**: Define and track SLAs per client
- **Usage billing**: Track and bill usage per client
- **Onboarding wizard**: Streamlined client onboarding
- **Aggregated reporting**: Cross-client security metrics

### 10.30 Security Assessments & Reports

**Route**: `/security-assessments`, `/threat-reports`  
**API**: `GET /api/security-assessments`, `POST /api/security-assessments`, `GET /api/threat-reports`

Structured security assessment and reporting.

**Features**:

- **Assessment templates**: Pre-built templates for various assessment types
- **Finding tracking**: Track findings with remediation status
- **Threat reports**: Generate periodic threat landscape reports
- **Compliance reports**: Automated compliance status reports

### 10.31 Advanced Reporting

**Route**: `/advanced-reporting`  
**API**: `GET /api/advanced-reports`, `POST /api/advanced-reports`, `GET /api/advanced-reports/:id/download`

Enterprise-grade reporting with PDF generation.

**Features**:

- **PDF report generation** with charts, tables, and executive summaries
- **Compliance report templates**: PCI-DSS, SOC 2, ISO 27001, HIPAA, GDPR
- **White-label reports**: Add your organization's logo and branding
- **Financial impact analysis**: Quantify risk in monetary terms
- **Scheduled reports**: Auto-generate and email reports on a schedule
- **Report gallery**: Browse and re-run historical reports

---

## 11. Governance

### 11.1 Compliance Center

**Route**: `/compliance`  
**API**: `GET /api/compliance/frameworks`, `GET /api/compliance/controls`, `POST /api/compliance/assessments`

Compliance framework management.

**Supported frameworks** (15+ pre-built):

- SOC 2 Type II
- ISO 27001:2022
- PCI-DSS 4.0
- HIPAA
- GDPR
- NIST CSF 2.0
- NIS2
- DORA
- CBEST
- MAS TRM
- IFSCA Cybersecurity
- PDPA (Thailand)
- POPIA (South Africa)
- LGPD (Brazil)
- PIPEDA (Canada)
- ASD Essential 8
- CCPA/CPRA
- CMMC 2.0
- NERC CIP
- SWIFT CSP
- IEC 62443

**Features**:

- Control mapping to compliance frameworks
- Evidence collection and attachment
- Assessment scheduling
- Compliance score per framework
- Gap identification

### 11.2 Trust Center

**Route**: `/trust-center`  
**API**: `GET /api/trust-center`

Public-facing trust and transparency page.

**Features**:

- Display certifications and compliance badges
- Security policy documentation
- Incident disclosure timeline
- Sub-processor list
- Data processing agreements

### 11.3 Gap Analysis

**Route**: `/compliance-gap`  
**API**: `GET /api/compliance-gap`

Identify gaps in your compliance posture.

**Features**:

- Compare current controls against framework requirements
- Prioritized gap list by risk impact
- Remediation recommendations
- Gap closure tracking

### 11.4 Audit Log

**Route**: `/audit-log`  
**API**: `GET /api/v1/audit-logs`

Immutable record of all platform actions.

**Features**:

- Every user action is logged: login, logout, data changes, configuration changes, AI invocations
- Filter by user, action type, resource type, date range
- Category-based filtering (security, data, admin, ai, system)
- Export for compliance audits
- Tamper-proof logging

**Tracked actions include**: user logins, alert status changes, incident creation/updates, connector operations, AI analyses, playbook executions, team changes, billing operations, and more.

### 11.5 Policy Packs

**Route**: `/policy-packs`  
**API**: `GET /api/policy-packs`, `POST /api/policy-packs`

Pre-defined security policy bundles.

**Features**:

- Policy templates for common standards (CIS, NIST, ISO)
- Custom policy creation
- Policy assignment to assets and groups
- Policy compliance monitoring
- Violation alerting

### 11.6 Reports

**Route**: `/reports`  
**API**: `GET /api/reports`, `POST /api/reports`

General reporting engine.

**Features**:

- Pre-built report templates
- Custom report builder
- Scheduled report generation
- PDF and CSV export
- Email delivery

### 11.7 Data Residency

**Route**: `/data-residency`  
**API**: `GET /api/data-residency/config`, `POST /api/data-residency/config`, `GET /api/data-residency/keys`

Data sovereignty and encryption key management.

**Features**:

- **Per-org region selection**: Choose where your data is stored (US, EU, APAC, etc.)
- **BYOK key management**: Bring Your Own Key for encryption at rest
- **Cross-border flow controls**: Enforce data transfer policies between regions
- **Data residency compliance**: Automatic enforcement of GDPR, PIPEDA, PDPA data localization rules

### 11.8 Board Dashboard

**Route**: `/board-dashboard`  
**API**: `GET /api/security-metrics/executive-summary`, `GET /api/security-metrics/kpis`

Executive-level security metrics for board reporting.

**Features**:

- **Security KPIs**: MTTR, MTTD, alert volume trends, incident counts, false positive rate
- **Risk posture**: Aggregate risk score with trend
- **Compliance status**: Summary across all frameworks
- **Financial impact**: Estimated cost of security incidents
- **Executive report generation**: One-click PDF for board meetings

---

## 12. Admin & Settings

### 12.1 Onboarding Wizard

See [Section 2.2](#22-onboarding-wizard).

### 12.2 Team & Invites

**Route**: `/team`  
**API**: `GET /api/team`, `POST /api/team/invite`, `PATCH /api/team/:memberId`

Manage organization members and invitations.

**Features**:

- View all team members with roles
- Send email invitations
- Change member roles (admin/analyst/viewer)
- Remove members
- Pending invitation management

### 12.3 Org Settings

**Route**: `/org-settings`  
**API**: `GET /api/orgs/:id`, `PATCH /api/orgs/:id`

Organization-level configuration.

**Features**:

- Organization name and details
- Industry and company size
- Logo upload
- Security policies configuration
- Default settings

### 12.4 Developer Portal

**Route**: `/developer-portal`  
**API**: `GET /api/api-keys`, `POST /api/api-keys`, `DELETE /api/api-keys/:id`

API key management for programmatic access.

**Features**:

- Create API keys with specific scopes
- Scope options: `ingest:write`, `alerts:read`, `alerts:write`, `incidents:read`, `incidents:write`
- View key usage statistics
- Revoke keys
- Key rotation reminders

**Scope templates**:
| Template | Description | Scopes |
|----------|------------|--------|
| Read-only | Read alerts and incidents | `alerts:read`, `incidents:read` |
| Ingestion only | Send data into platform | `ingest:write` |
| Integration (full) | Ingest and manage alerts | `ingest:write`, `alerts:read`, `alerts:write` |

### 12.5 Billing & Usage

**Route**: `/billing`, `/usage-billing`, `/tiered-packaging`  
**API**: `GET /api/billing/plans`, `POST /api/billing/checkout`, `GET /api/usage`

Subscription management and usage tracking.

**Plan tiers**:
| Feature | Free | Pro | Enterprise |
|---------|------|-----|-----------|
| Alerts/month | 1,000 | 50,000 | Unlimited |
| Connectors | 2 | 10 | Unlimited |
| AI analyses/month | 50 | 2,000 | Unlimited |
| Team members | 3 | 25 | Unlimited |
| Data retention | 30 days | 1 year | Custom |
| Compliance frameworks | 1 | 5 | All |
| API keys | 2 | 10 | Unlimited |

### 12.6 MFA Setup

**Route**: `/mfa-setup`  
**API**: `POST /api/mfa/setup`, `POST /api/mfa/verify`

Multi-factor authentication configuration.

**Features**:

- TOTP-based MFA (Google Authenticator, Authy, etc.)
- QR code enrollment
- Backup codes
- Enforcement policies (require MFA for admin accounts)

---

## 13. Asset Onboarding Guide

This section provides a consolidated guide for onboarding all types of assets into SecureNexus.

### 13.1 Quick Start: What You Need

| What You Have                        | Where to Start                     |
| ------------------------------------ | ---------------------------------- |
| A SIEM (Splunk, QRadar, etc.)        | Connectors (Section 9.1)           |
| An EDR (CrowdStrike, Defender, etc.) | Connectors (Section 9.1)           |
| Custom security tools                | Ingestion API (Section 9.5)        |
| Physical/virtual servers             | Asset Inventory (Section 10.1)     |
| Cloud infrastructure (AWS/Azure/GCP) | CSPM (Section 7.1)                 |
| OT/ICS devices                       | OT/ICS Security (Section 10.11)    |
| Mobile devices                       | Mobile Security (Section 10.12)    |
| APIs to protect                      | API Security (Section 10.13)       |
| Source code repositories             | Developer Security (Section 10.20) |
| Third-party vendors                  | TPRM (Section 10.21)               |
| User directory (Okta/Azure AD)       | Identity Governance (Section 10.9) |
| Email (M365/Gmail)                   | Email Security (Section 10.28)     |
| DNS servers                          | DNS Security (Section 10.27)       |

### 13.2 Step-by-Step Onboarding Flow

**Phase 1: Foundation (Day 1)**

1. Complete the onboarding wizard (create org, choose plan)
2. Invite your security team
3. Connect your primary SIEM/EDR via Connectors
4. Run initial sync to pull in existing alerts

**Phase 2: Asset Discovery (Week 1)** 5. Add critical assets manually to Asset Inventory 6. Connect cloud accounts to CSPM for auto-discovery 7. Deploy native sensors to key endpoints 8. Import your SBOM for supply chain visibility

**Phase 3: AI & Detection (Week 2)** 9. Run your first AI correlation on pending alerts 10. Review and provide feedback on AI triage results 11. Create custom detection rules or use AI-generated rules 12. Set up playbooks for common response scenarios

**Phase 4: Governance (Month 1)** 13. Configure compliance frameworks relevant to your industry 14. Set up data residency policies 15. Enable audit logging and review policies 16. Create executive dashboards and scheduled reports

**Phase 5: Advanced Features (Ongoing)** 17. Deploy deception assets (canary tokens, honeypots) 18. Enable UEBA behavioral baselining 19. Configure threat hunting workbench 20. Set up phishing simulation campaigns 21. Run chaos engineering exercises

### 13.3 Onboarding Assets to Specific Features

#### Connecting a SIEM/EDR (Connector)

```
1. Sidebar > Data & Integrations > Connectors
2. Click "Add Connector"
3. Choose type (e.g., "CrowdStrike")
4. Name: "Production CrowdStrike"
5. API URL: https://api.crowdstrike.com
6. API Key: [your-api-key]
7. Click "Test Connection" -- should show green checkmark
8. Polling Interval: 5 minutes
9. Click "Save"
10. Click "Sync Now" for the first pull
11. Navigate to Alerts to see incoming data
```

#### Sending Custom Data (API Ingestion)

```
1. Sidebar > Admin & Settings > Developer Portal
2. Click "Create API Key"
3. Name: "SIEM Integration"
4. Scopes: ingest:write
5. Click "Create" -- copy the key (shown once only!)
6. Use the key in your integration:

   POST /api/ingest/custom
   Authorization: Bearer snx_your_api_key_here
   Content-Type: application/json

   {
     "title": "Unauthorized SSH access attempt",
     "severity": "high",
     "category": "intrusion",
     "source_ip": "203.0.113.42",
     "dest_ip": "10.0.1.50",
     "hostname": "bastion-01",
     "user": "root",
     "description": "Multiple failed SSH login attempts from external IP"
   }
```

#### Registering an Asset

```
1. Sidebar > Standalone Security > Asset Inventory
2. Click "Add Asset"
3. Fill in:
   - Name: "Production Database Server"
   - Type: database
   - Criticality: critical
   - Environment: production
   - IP: 10.0.2.50
   - Hostname: db-prod-01
   - Owner: DBA Team
   - Department: Engineering
   - Location: AWS us-east-1a
   - OS: Amazon Linux 2
   - Manufacturer: AWS
   - Model: r5.2xlarge
4. Click "Create Asset"
```

#### Adding a Cloud Account (CSPM)

```
1. Sidebar > Posture > CSPM
2. Click "Add Cloud Account"
3. Provider: AWS
4. Account ID: 123456789012
5. IAM Role ARN: arn:aws:iam::123456789012:role/SecureNexusReadOnly
6. External ID: [auto-generated]
7. Regions: us-east-1, us-west-2, eu-west-1
8. Frameworks: CIS AWS Benchmark, SOC 2
9. Click "Connect & Scan"
```

---

## 14. Environment Variables & Configuration

### Required Variables

| Variable         | Description                                         | Example                                        |
| ---------------- | --------------------------------------------------- | ---------------------------------------------- |
| `DATABASE_URL`   | PostgreSQL connection string                        | `postgresql://user:pass@host:5432/securenexus` |
| `SESSION_SECRET` | Session encryption key (min 32 chars in production) | `your-cryptographically-random-string`         |
| `S3_BUCKET_NAME` | AWS S3 bucket for file storage                      | `securenexus-uploads-prod`                     |

### Optional Variables

| Variable                | Default         | Description                                        |
| ----------------------- | --------------- | -------------------------------------------------- |
| `PORT`                  | `5000`          | Server port                                        |
| `NODE_ENV`              | `development`   | Environment: development, staging, uat, production |
| `FORCE_HTTPS`           | `false`         | Set to `true` in production for secure cookies     |
| `AWS_REGION`            | `us-east-1`     | AWS region                                         |
| `AWS_ACCESS_KEY_ID`     | (from IAM role) | AWS access key (use IRSA on EKS instead)           |
| `AWS_SECRET_ACCESS_KEY` | (from IAM role) | AWS secret key (use IRSA on EKS instead)           |

### AI Configuration

| Variable                       | Default                                   | Description                          |
| ------------------------------ | ----------------------------------------- | ------------------------------------ |
| `AI_BACKEND`                   | `bedrock`                                 | AI backend: `bedrock` or `sagemaker` |
| `AI_MODEL_ID`                  | `anthropic.claude-sonnet-4-20250514-v1:0` | Primary AI model                     |
| `AI_MAX_TOKENS`                | `4096`                                    | Max response tokens                  |
| `AI_TEMPERATURE`               | `0.1`                                     | Model temperature (0-2)              |
| `AI_TOP_P`                     | `0.9`                                     | Nucleus sampling parameter           |
| `AI_TRIAGE_MODEL_ID`           | `anthropic.claude-sonnet-4-20250514-v1:0` | Triage model                         |
| `AI_TRIAGE_MAX_TOKENS`         | `2048`                                    | Triage max tokens                    |
| `AI_TRIAGE_TEMPERATURE`        | `0.05`                                    | Triage temperature                   |
| `AI_INVESTIGATION_MODEL_ID`    | `anthropic.claude-opus-4-20250514-v1:0`   | Deep investigation model             |
| `AI_INVESTIGATION_MAX_TOKENS`  | `8192`                                    | Investigation max tokens             |
| `AI_INVESTIGATION_TEMPERATURE` | `0.15`                                    | Investigation temperature            |
| `SAGEMAKER_ENDPOINT`           | -                                         | Required when AI_BACKEND=sagemaker   |

### OAuth Configuration

| Variable               | Description                                                      |
| ---------------------- | ---------------------------------------------------------------- |
| `GOOGLE_CLIENT_ID`     | Google OAuth client ID                                           |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret                                       |
| `GOOGLE_CALLBACK_URL`  | Google OAuth callback URL (default: `/api/auth/google/callback`) |
| `GITHUB_CLIENT_ID`     | GitHub OAuth client ID                                           |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth client secret                                       |
| `GITHUB_CALLBACK_URL`  | GitHub OAuth callback URL (default: `/api/auth/github/callback`) |

---

## 15. AI Configuration & Troubleshooting

### Why AI Might Not Work

1. **No AWS Bedrock access**: Your AWS account must have access to the Claude models on Bedrock. Go to the AWS Console > Bedrock > Model Access and request access to:
   - `anthropic.claude-sonnet-4-20250514-v1:0` (for triage, correlation, narrative)
   - `anthropic.claude-opus-4-20250514-v1:0` (for deep investigation)

2. **Missing AWS credentials**: The server needs valid AWS credentials to call Bedrock. Either:
   - Set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` environment variables
   - Use IAM roles (IRSA on EKS, instance profile on EC2)

3. **Wrong region**: Bedrock model availability varies by region. Ensure `AWS_REGION` is set to a region where your models are enabled (default: `us-east-1`).

4. **Budget exceeded**: If your org's AI budget is exhausted, AI calls will be rejected. Check AI Analyst > Budget & Limits.

5. **Circuit breaker open**: After repeated AI failures, the circuit breaker trips and blocks calls for a cooldown period. Check AI Analyst > Model Gateway for health status.

### Heuristic Fallback

When the AI backend is unavailable, SecureNexus automatically falls back to **heuristic analysis**:

- Uses statistical pattern matching instead of LLM analysis
- Extracts MITRE ATT&CK mappings from alert metadata
- Provides basic correlation based on IP, hostname, and timestamp proximity
- Clearly labels results as "heuristic" with lower confidence scores
- Recommends enabling AI for deeper analysis

This ensures the platform remains functional even without AI connectivity.

### How AI Integrates with Features

| Feature                   | AI Model        | What It Does                                               |
| ------------------------- | --------------- | ---------------------------------------------------------- |
| Alert Triage              | Claude Sonnet 4 | Severity assessment, MITRE mapping, false positive scoring |
| Alert Correlation         | Claude Sonnet 4 | Group related alerts, suggest incident titles              |
| Incident Narrative        | Claude Sonnet 4 | Generate investigation summary with timeline               |
| Deep Investigation        | Claude Opus 4   | Forensic analysis, attack graph, threat actor profiling    |
| Threat Hunting            | Claude Sonnet 4 | Hypothesis generation, anomaly analysis                    |
| Behavioral Analysis       | Claude Sonnet 4 | UEBA anomaly detection, baseline comparison                |
| Attack Path Prediction    | Claude Sonnet 4 | Predict attacker's next moves                              |
| Detection Rule Generation | Claude Sonnet 4 | Generate Sigma/YARA rules from descriptions                |
| SOC Co-Pilot              | Claude Sonnet 4 | Multi-turn investigation chat                              |
| Autonomous SOC            | Claude Sonnet 4 | Automated tier-1 triage                                    |

### RAG Vector Search

SecureNexus uses **pgvector** for Retrieval Augmented Generation:

- Incidents, threat intel, and knowledge base articles are embedded and stored in vector tables
- When AI is invoked, relevant context is retrieved via semantic similarity search
- Context is ranked by relevance and packed into the prompt within token limits
- This grounds AI responses in your organization's actual security data

---

## 16. API Reference

### Authentication

All API endpoints require authentication via one of:

- **Session cookie**: Set after login (for browser-based access)
- **API key**: `Authorization: Bearer snx_...` header (for programmatic access)

### Common Response Format

Most paginated endpoints return:

```json
{
  "data": [...],
  "meta": {
    "offset": 0,
    "limit": 50,
    "total": 1234
  }
}
```

### Key Endpoints

| Method | Path                                            | Description                     |
| ------ | ----------------------------------------------- | ------------------------------- |
| `GET`  | `/api/dashboard/stats`                          | Dashboard statistics            |
| `GET`  | `/api/v1/alerts`                                | List alerts (paginated)         |
| `POST` | `/api/v1/alerts/:id`                            | Update alert                    |
| `GET`  | `/api/v1/incidents`                             | List incidents                  |
| `POST` | `/api/v1/incidents`                             | Create incident                 |
| `POST` | `/api/ai/triage/:alertId`                       | AI triage an alert              |
| `POST` | `/api/ai/correlate`                             | AI correlate alerts             |
| `POST` | `/api/ai/narrative/:incidentId`                 | Generate AI narrative           |
| `GET`  | `/api/ai/narrative/:incidentId/stream`          | Stream AI narrative (SSE)       |
| `GET`  | `/api/ai/deep-investigation/:incidentId/stream` | Stream deep investigation (SSE) |
| `POST` | `/api/ai/multi-turn-investigation`              | Multi-turn AI chat              |
| `POST` | `/api/ai/generate-detection-rules`              | AI rule generation              |
| `POST` | `/api/ai/feedback`                              | Submit AI feedback              |
| `GET`  | `/api/ai/health`                                | AI model health check           |
| `GET`  | `/api/ai/config`                                | AI model configuration          |
| `POST` | `/api/ingest/:source`                           | Ingest single alert             |
| `POST` | `/api/ingest/:source/bulk`                      | Bulk ingest alerts              |
| `GET`  | `/api/connectors`                               | List connectors                 |
| `POST` | `/api/connectors`                               | Create connector                |
| `POST` | `/api/connectors/:id/sync`                      | Sync connector                  |
| `GET`  | `/api/assets`                                   | List assets                     |
| `POST` | `/api/assets`                                   | Create asset                    |
| `GET`  | `/api/v1/audit-logs`                            | List audit logs                 |
| `GET`  | `/api/onboarding/status`                        | Onboarding wizard status        |
| `POST` | `/api/onboarding/step/:step`                    | Complete onboarding step        |

---

## 17. Supported Ingestion Sources

SecureNexus includes specialized normalizers for 22 security data sources. Each normalizer maps vendor-specific fields to the unified SecureNexus alert schema.

| Source Key    | Product                | Data Type              | Key Fields Extracted                                                     |
| ------------- | ---------------------- | ---------------------- | ------------------------------------------------------------------------ |
| `crowdstrike` | CrowdStrike EDR        | Endpoint detections    | detection_id, tactic, technique, computer_name, sha256, local_ip         |
| `splunk`      | Splunk SIEM            | SIEM alerts            | sid, search_name, src_ip, dest_ip, user, sourcetype                      |
| `paloalto`    | Palo Alto Firewall     | Network threats        | serial, rule_name, src, dst, action, app, zone_src/dst                   |
| `guardduty`   | AWS GuardDuty          | Cloud findings         | finding_type, severity, instance_id, vpc_id, s3_bucket                   |
| `suricata`    | Suricata IDS           | Network IDS alerts     | signature_id, src_ip, dest_ip, proto, flow_id, community_id              |
| `defender`    | Microsoft Defender     | Endpoint/M365 alerts   | alertId, category, severity, computerDnsName, mitreTechniques            |
| `elastic`     | Elastic Security       | SIEM detections        | rule_id, host_name, source_ip, agent_type                                |
| `qradar`      | IBM QRadar             | SIEM offenses          | offense_id, magnitude, category, source_ip, protocol                     |
| `fortigate`   | Fortinet FortiGate     | UTM alerts             | logid, src_ip, dst_ip, action, attack_name                               |
| `carbonblack` | Carbon Black EDR       | Endpoint alerts        | alert_id, process_name, process_hash, device_name                        |
| `qualys`      | Qualys VMDR            | Vulnerability findings | qid, severity, ip, hostname, os, solution                                |
| `tenable`     | Tenable Nessus         | Vulnerability findings | plugin_id, risk_factor, host_ip, synopsis                                |
| `umbrella`    | Cisco Umbrella         | DNS security events    | domain, categories, action_taken, externalIp                             |
| `darktrace`   | Darktrace              | Network anomalies      | model_name, score, device_hostname, src_ip                               |
| `rapid7`      | Rapid7 InsightIDR      | SIEM/UBA alerts        | investigation_id, priority, rrn, source_ip                               |
| `trendmicro`  | Trend Micro Vision One | XDR alerts             | alert_id, severity, detection_type, endpoint_name                        |
| `okta`        | Okta Identity          | Identity events        | eventType, severity, actor_email, client_ip                              |
| `proofpoint`  | Proofpoint Email       | Email threats          | messageID, threat_type, sender, recipients, spamScore                    |
| `snort`       | Snort IDS              | Network IDS alerts     | signature_id, src_addr, dst_addr, protocol, classification               |
| `zscaler`     | Zscaler ZIA            | Web security events    | url, action, department, user, threatname                                |
| `checkpoint`  | Check Point            | Firewall/IPS events    | log_id, src, dst, rule_name, action, attack_name                         |
| `custom`      | Custom Source          | Any JSON payload       | Maps common field names automatically (title, severity, source_ip, etc.) |

---

_This document is maintained by the SecureNexus engineering team. For questions or feedback, contact the platform administrators or open an issue in the repository._
