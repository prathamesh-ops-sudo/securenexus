# SecureNexus Platform — Complete Feature & Onboarding Guide

> **This is the single source of truth for how SecureNexus works, what every feature does, and exactly how to onboard assets into each one.**
> Last updated: March 2026

---

## Table of Contents

1. [Platform Overview](#1-platform-overview)
2. [Getting Started — First Login & Setup](#2-getting-started--first-login--setup)
3. [Environment Variables Reference](#3-environment-variables-reference)
4. [User Roles & Permissions](#4-user-roles--permissions)
5. [Asset Onboarding — The Core Flow](#5-asset-onboarding--the-core-flow)
6. [Connectors (SIEM/EDR/Cloud Integrations)](#6-connectors-siemedrccloud-integrations)
7. [Alert Management](#7-alert-management)
8. [Incident Management](#8-incident-management)
9. [AI Engine — How It Actually Works](#9-ai-engine--how-it-actually-works)
10. [SOC Copilot](#10-soc-copilot)
11. [Autonomous SOC & AI Detection Rules](#11-autonomous-soc--ai-detection-rules)
12. [Threat Hunting](#12-threat-hunting)
13. [UEBA (User & Entity Behavior Analytics)](#13-ueba-user--entity-behavior-analytics)
14. [Vulnerability Scanner](#14-vulnerability-scanner)
15. [CSPM (Cloud Security Posture Management)](#15-cspm-cloud-security-posture-management)
16. [Supply Chain Security (SBOM)](#16-supply-chain-security-sbom)
17. [Compliance & Governance](#17-compliance--governance)
18. [Identity Governance & PAM](#18-identity-governance--pam)
19. [Deception Technology (Canary Tokens & Honeypots)](#19-deception-technology-canary-tokens--honeypots)
20. [Threat Intelligence](#20-threat-intelligence)
21. [DNS Security](#21-dns-security)
22. [Email Security](#22-email-security)
23. [API Security](#23-api-security)
24. [Browser Defense](#24-browser-defense)
25. [OT/ICS Security](#25-otics-security)
26. [Mobile Security](#26-mobile-security)
27. [Physical Security](#27-physical-security)
28. [Ransomware Defense](#28-ransomware-defense)
29. [Playbooks (SOAR-Lite)](#29-playbooks-soar-lite)
30. [Integrations (Ticketing, Messaging, On-Call)](#30-integrations-ticketing-messaging-on-call)
31. [Reports & Dashboards](#31-reports--dashboards)
32. [Executive Risk Dashboard](#32-executive-risk-dashboard)
33. [MSSP Multi-Tenant Portal](#33-mssp-multi-tenant-portal)
34. [Billing, Plans & Usage](#34-billing-plans--usage)
35. [Trust Center & Posture](#35-trust-center--posture)
36. [Developer Portal & API Keys](#36-developer-portal--api-keys)
37. [Platform Administration](#37-platform-administration)
38. [Data Residency & Sovereign Keys](#38-data-residency--sovereign-keys)
39. [War Room](#39-war-room)
40. [Troubleshooting Common Issues](#40-troubleshooting-common-issues)

---

## 1. Platform Overview

SecureNexus is a **full-stack security operations platform** built on:

| Layer | Technology |
|-------|-----------|
| Backend | Node.js + Express (TypeScript) |
| Frontend | React 18 + Vite + Tailwind |
| Database | PostgreSQL (via Drizzle ORM) |
| AI Models | AWS Bedrock (Claude Sonnet 4 / Opus 4) or SageMaker |
| File Storage | AWS S3 |
| Auth | Session-based + Passport.js + OAuth (Google, GitHub) + SSO (SAML) |

### Architecture at a Glance

```
Browser (React SPA)
       ↕ REST + WebSocket
Express API Server
  ├── Route Modules (~100 route files)
  ├── AI Engine (Bedrock/SageMaker)
  ├── Connector Engine (24 plugins)
  ├── Correlation Engine
  ├── Policy Engine
  └── Notification Dispatcher
       ↕
PostgreSQL (Drizzle ORM)   ←→   AWS S3 (files, reports)
```

---

## 2. Getting Started — First Login & Setup

### Step 1 — Register / Sign In

Navigate to `/auth`. You can register via:
- **Email + Password** (standard)
- **Google OAuth** (requires `GOOGLE_CLIENT_ID` + `GOOGLE_CLIENT_SECRET`)
- **GitHub OAuth** (requires `GITHUB_CLIENT_ID` + `GITHUB_CLIENT_SECRET`)
- **SSO / SAML** (Enterprise — configured under Org Settings → SSO)

### Step 2 — Onboarding Wizard

After first login the **Onboarding Wizard** launches automatically (`/onboarding`). It guides you through 4 steps:

| Step | What Happens |
|------|-------------|
| **Organization Setup** | Name, industry, company size, timezone |
| **Integrations** | Connect your first SIEM/EDR/Cloud tool (see §6) |
| **Ingestion** | Send first alert via API or sync connector |
| **Endpoints/CSPM** | Add cloud accounts or endpoint assets |

You can check wizard progress at any time via `GET /api/wizard/status`.

### Step 3 — Invite Your Team

Go to **Team Management** (`/team-management`) → Invite by email. Choose a role:
- `owner` — full access
- `admin` — full access minus billing
- `analyst` — read + write on incidents/alerts, read-only on connectors
- `read_only` — read everywhere, no writes

---

## 3. Environment Variables Reference

These must be set before the server starts. Required ones will cause the server to exit if missing.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | **Yes** | — | PostgreSQL connection string (`postgres://user:pass@host:5432/db`) |
| `SESSION_SECRET` | **Yes** | — | Session encryption key. Must be ≥32 chars with high entropy in production |
| `S3_BUCKET_NAME` | **Yes** | — | AWS S3 bucket for file uploads and reports |
| `PORT` | No | `5000` | Server port |
| `NODE_ENV` | No | `development` | `development` / `staging` / `uat` / `production` |
| `FORCE_HTTPS` | No | `false` | Set `"true"` to enable Secure cookie flag |
| `AWS_REGION` | No | `us-east-1` | AWS region for Bedrock, S3, SES |
| `AWS_ACCESS_KEY_ID` | No | — | AWS credentials (if not using IAM role) |
| `AWS_SECRET_ACCESS_KEY` | No | — | AWS credentials (if not using IAM role) |
| **AI Variables** | | | |
| `AI_BACKEND` | No | `bedrock` | `bedrock` or `sagemaker` |
| `AI_MODEL_ID` | No | `anthropic.claude-sonnet-4-20250514-v1:0` | Default model for narrative/correlation |
| `AI_TRIAGE_MODEL_ID` | No | `anthropic.claude-sonnet-4-20250514-v1:0` | Fast model for alert triage |
| `AI_INVESTIGATION_MODEL_ID` | No | `anthropic.claude-opus-4-20250514-v1:0` | Deep investigation model (Opus) |
| `SAGEMAKER_ENDPOINT` | Conditional | — | Required only when `AI_BACKEND=sagemaker` |
| `SAGEMAKER_TRIAGE_ENDPOINT` | No | — | Separate triage endpoint for SageMaker |
| `AI_MAX_TOKENS` | No | `4096` | Max output tokens for main model |
| `AI_TRIAGE_MAX_TOKENS` | No | `2048` | Max output tokens for triage model |
| `AI_INVESTIGATION_MAX_TOKENS` | No | `8192` | Max output tokens for investigation model |
| `AI_TEMPERATURE` | No | `0.1` | Model temperature (0-2) |
| **OAuth** | | | |
| `GOOGLE_CLIENT_ID` | No | — | Google OAuth App client ID |
| `GOOGLE_CLIENT_SECRET` | No | — | Google OAuth App client secret |
| `GITHUB_CLIENT_ID` | No | — | GitHub OAuth App client ID |
| `GITHUB_CLIENT_SECRET` | No | — | GitHub OAuth App client secret |
| `COGNITO_USER_POOL_ID` | No | — | AWS Cognito user pool for SSO |
| `GITHUB_TOKEN` | No | — | GitHub PAT for CVE advisory queries |

---

## 4. User Roles & Permissions

SecureNexus uses a role-based access system scoped per-organization.

| Role | Incidents | Connectors | API Keys | Response Actions | Settings | Team |
|------|-----------|-----------|----------|-----------------|---------|------|
| `owner` | R/W/Admin | R/W/Admin | R/W/Admin | R/W/Admin | R/W/Admin | R/W/Admin |
| `admin` | R/W/Admin | R/W/Admin | R/W/Admin | R/W/Admin | R/W | R/W |
| `analyst` | R/W | R | R | R/W | R | R |
| `read_only` | R | R | — | R | R | R |

> **Tip:** Fine-grained permissions can be set per-team via Team Management.

---

## 5. Asset Onboarding — The Core Flow

"Assets" in SecureNexus means anything generating security data: cloud accounts, endpoints, network devices, applications, users. Here is the **master workflow** for getting any asset reporting into the platform:

```
Asset exists (server, cloud account, app, user, device)
        │
        ▼
OPTION A: Use a Connector (pull model — SecureNexus fetches alerts)
        │   → Go to Connectors page → Create Connector → provide credentials
        │   → Platform polls the source on a configurable interval
        │
OPTION B: Push via Ingestion API (push model — asset sends data to us)
        │   → Generate an API Key (Ingestion page or Settings → API Keys)
        │   → POST /api/ingest with Authorization: Bearer <key>
        │   → Data is normalized, deduplicated, correlated, stored
        │
OPTION C: Native Sensor / Collector Agent
        │   → Deploy the lightweight agent on the endpoint/server
        │   → Agent streams telemetry directly to the platform
        │
OPTION D: Register as CSPM Account (cloud posture)
            → Settings → CSPM → Add Account → Enter cloud credentials
            → Platform continuously audits your cloud config
```

Each path eventually creates **Alerts** in the system, which then flow through triage → correlation → incident creation → response.

---

## 6. Connectors (SIEM/EDR/Cloud Integrations)

**Page:** `/connectors`
**API base:** `/api/connectors`

### Supported Connector Types (24 total)

| Connector | Category | Auth Type |
|-----------|---------|-----------|
| CrowdStrike | EDR | API Key |
| SentinelOne | EDR | API Key |
| Microsoft Defender | EDR | OAuth2 / API Key |
| Carbon Black | EDR | API Key |
| Splunk | SIEM | API Key / Token |
| Elastic Security | SIEM | API Key |
| IBM QRadar | SIEM | API Key |
| Wazuh | SIEM | API Key |
| Rapid7 InsightIDR | SIEM | API Key |
| AWS GuardDuty | Cloud | AWS Credentials |
| Wiz | Cloud | OAuth2 |
| Palo Alto Firewall | Network | API Key |
| Fortinet FortiGate | Network | API Key |
| Cisco Umbrella | Network | API Key |
| Check Point | Network | Certificate |
| Zscaler ZIA | Network | API Key |
| Darktrace | AI/Network | API Key |
| Qualys VMDR | Vuln | API Key |
| Tenable Nessus | Vuln | API Key |
| Okta | Identity | API Key |
| Proofpoint | Email | API Key |
| Trend Micro Vision One | XDR | API Key |
| Suricata IDS | IDS | API Key |
| Snort IDS | IDS | API Key |

### How to Add a Connector

1. Navigate to **Connectors** in the sidebar.
2. Click **+ New Connector**.
3. Select the connector **type** from the dropdown.
4. Enter a **name** (e.g., "Production CrowdStrike").
5. Enter the **credentials** specific to that connector (API key, OAuth token, etc.).
6. Set the **polling interval** (default: 5 minutes).
7. Click **Save** → The platform validates the config against the connector's schema.
8. Click **Test** to verify connectivity.
9. Click **Sync Now** to pull the first batch of alerts.

### What Happens During a Sync

```
Connector Plugin (e.g. crowdstrike.ts)
    → plugin.fetch(config, since) — fetches raw events from vendor API
    → normalizer.normalizeAlert(raw) — converts to SecureNexus alert schema
    → Deduplication check (sourceEventId + source hash)
    → correlationEngine.correlateAlert(alert) — groups related alerts
    → entityResolver.resolveAndLinkEntities(alert) — links IPs, hosts, users
    → storage.createAlert(alert) — persists to DB
    → broadcastEvent("alert.created") — WebSocket push to connected UIs
```

### Connector API Reference

```
GET    /api/connectors              — List all connectors for your org
GET    /api/connectors/:id          — Get a single connector (secrets masked)
POST   /api/connectors              — Create a new connector
PATCH  /api/connectors/:id          — Update connector config/settings
DELETE /api/connectors/:id          — Delete connector
POST   /api/connectors/:id/sync     — Trigger manual sync
POST   /api/connectors/:id/test     — Test connector credentials
GET    /api/connectors/types        — List all supported connector types + metadata
GET    /api/connectors/dead-letters — View failed/dead-letter sync jobs
```

---

## 7. Alert Management

**Page:** `/alerts`
**API base:** `/api/alerts`

Alerts are the atomic unit of security data. Every event from every source becomes a normalized alert.

### Alert Lifecycle

```
new → triaged → correlated → investigating → resolved / dismissed / false_positive
```

### Alert Severities

`critical` → `high` → `medium` → `low` → `informational`

### Alert Categories

`malware`, `intrusion`, `phishing`, `data_exfiltration`, `privilege_escalation`, `lateral_movement`, `credential_access`, `reconnaissance`, `persistence`, `command_and_control`, `cloud_misconfiguration`, `policy_violation`, `other`

### Onboarding Alerts

**Via Connector** (automated — see §6)

**Via Ingestion API (manual push):**
```bash
# Generate an API key first (see §36)
curl -X POST https://your-domain.com/api/ingest \
  -H "Authorization: Bearer snx_YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "Custom",
    "severity": "high",
    "title": "Suspicious login from new IP",
    "description": "User admin logged in from 203.0.113.42 — first time seen",
    "sourceIp": "203.0.113.42",
    "userId": "admin@company.com",
    "hostname": "prod-server-01",
    "mitreTactic": "Initial Access",
    "mitreTechnique": "T1078"
  }'
```

**Via webhook (receive from any source):**
```bash
curl -X POST https://your-domain.com/api/webhooks/ingest \
  -H "X-Webhook-Secret: YOUR_SECRET" \
  -H "Content-Type: application/json" \
  -d '{ "alerts": [...] }'
```

### Key Alert API Endpoints

```
GET  /api/v1/alerts              — Paginated alert list with filters
GET  /api/alerts/:id             — Get single alert with entity links
POST /api/alerts                 — Manually create an alert
PATCH /api/alerts/:id            — Update status, assign, add notes
POST /api/alerts/:id/suppress    — Suppress alert with reason
GET  /api/alerts/:id/related     — Get related alerts (same entity)
```

### Alert Suppression Rules

To suppress noisy alert types: go to **Alerts** → **Suppression Rules** → Define matchers on `source`, `category`, `title`, `sourceIp`, etc. Supports `eq`, `neq`, `contains`, `regex`, `in` operators.

---

## 8. Incident Management

**Page:** `/incidents`
**API base:** `/api/incidents`

Incidents are groups of correlated alerts that represent a security event requiring investigation.

### Incident Lifecycle

```
open → investigating → contained → eradicated → recovered → resolved / closed
```

### How Incidents are Created

1. **Automatically:** When the AI Correlation Engine groups alerts into a cluster with sufficient confidence, it auto-creates an incident.
2. **Manually:** Click **+ New Incident** on the Incidents page and link relevant alerts.
3. **Via Playbook:** A playbook action can escalate a high-severity alert to an incident.

### Incident Response Actions

From any incident detail page you can trigger:
- `isolate_host` — isolate the affected endpoint via EDR connector
- `block_ip` — push block rule to firewall connector
- `quarantine_file` — quarantine file via EDR
- `disable_user` — disable user in identity provider
- `block_domain` — block domain in DNS/proxy connector
- `kill_process` — terminate process via EDR

> All actions are logged in the Audit Log and can be configured to require approval via RBAC.

---

## 9. AI Engine — How It Actually Works

This is the most complex feature. Read this carefully.

### Overview

SecureNexus AI runs on **AWS Bedrock** (default) or **AWS SageMaker** (if you set `AI_BACKEND=sagemaker`). The AI is not a single model call — it is a tiered system with three inference tiers.

### Inference Tiers

| Tier | Model | Use Case | Tokens |
|------|-------|---------|--------|
| `triage` | Claude Sonnet 4 (fast) | Quick per-alert classification | 2048 |
| `correlation`/`narrative` | Claude Sonnet 4 | Group analysis, incident summaries | 4096 |
| `investigation` | Claude Opus 4 | Deep multi-step forensic analysis | 8192 |

### What the AI Can Do

| Capability | Trigger | API Endpoint |
|------------|---------|-------------|
| **Alert Triage** | Auto or manual | `POST /api/ai/triage` |
| **Alert Correlation** | Auto or manual | `POST /api/ai/correlate` |
| **Incident Narrative** | Manual or playbook | `POST /api/ai/narrative` |
| **Deep Investigation** | Manual on incident | `POST /api/ai/investigate` |
| **Threat Hunting** | Manual (TH page) | `POST /api/ai/hunt` |
| **Behavior Analysis** | UEBA anomaly detected | `POST /api/ai/behavior` |
| **Attack Path Prediction** | Manual on incident | `POST /api/ai/predict-attack-paths` |
| **Detection Rule Generation** | Manual | `POST /api/ai/generate-rules` |
| **SOC Copilot Chat** | Via Copilot UI | `POST /api/soc-copilot/triages` |
| **Streaming Narrative** | Narrative page | `POST /api/ai/stream/narrative` |
| **Streaming Investigation** | Investigation page | `POST /api/ai/stream/investigate` |

### Why AI Might Not Work

Common reasons the AI returns errors or stubs:

1. **AWS credentials not configured.** The platform needs either:
   - `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY`, OR
   - An IAM role attached to the EC2/ECS task with Bedrock permissions.

2. **Bedrock model access not enabled.** In the AWS Console, go to Amazon Bedrock → Model Access → Enable **Claude Sonnet 4** and **Claude Opus 4** for your region.

3. **Wrong region.** Claude models on Bedrock are only available in specific regions (e.g., `us-east-1`, `us-west-2`). Set `AWS_REGION` accordingly.

4. **Budget cap reached.** If an org has a budget cap configured, AI calls will be blocked. Check **AI Engine** → **Budget Controls** page or call `GET /api/ai/usage`.

5. **Circuit breaker open.** If the model returns 5+ consecutive errors, the circuit breaker opens for 60 seconds. Check `GET /api/ai/health`.

6. **No data to analyze.** Most AI endpoints require alerts or incidents to exist first. Triage without alerts returns 400.

### How to Verify AI is Working

```bash
# Check AI health
curl -H "Cookie: your-session" https://your-domain.com/api/ai/health

# Response when working:
{
  "status": "ok",
  "modelId": "anthropic.claude-sonnet-4-20250514-v1:0",
  "backend": "bedrock",
  "latencyMs": 892,
  "circuitBreakers": {}
}
```

If `status` is `"error"`, check AWS credentials and Bedrock model access.

### AI Prompt Registry

The platform uses a **Prompt Registry** to manage all AI prompts centrally. Each prompt has:
- A unique `id` (e.g., `alert-triage-v2`)
- A versioned `systemPrompt`
- A `deprecated` flag

**Page:** `/ai-prompt-registry`
**API:** `GET /api/ai/prompts` — list all prompts
**API:** `GET /api/ai/prompts/:id/history` — see version history
Prompts are initialized from `server/ai/enhanced-prompts.ts` and default prompts in `server/ai/prompt-registry.ts`.

### RAG (Retrieval-Augmented Generation)

The platform builds a RAG context for investigations using `pgvector`. When you call the deep investigation endpoint, the AI enriches its analysis with:
- Threat intel context (IOCs matching alert entities)
- OSINT indicators
- Historical findings for the same entity

This is automatic — no extra setup needed beyond having `pgvector` enabled on your PostgreSQL instance.

### Active Learning (Few-Shot Augmentation)

The system learns from analyst feedback. When an analyst marks an AI triage as correct/incorrect, this gets stored and future prompts for the same tier are automatically augmented with those examples. Use the **AI Feedback** feature on any triage result.

### AI Budget Controls

**Page:** `/ai-budget-controls`

To prevent runaway costs, you can set per-org monthly budgets:

```bash
POST /api/ai/budget
{ "orgId": "org_xxx", "monthlyLimitUsd": 100.00 }
```

Once the budget is hit, AI calls return `429` with message `"AI budget exceeded for this organization"`.

### Onboarding Assets to AI Features

1. **Alerts must exist first.** AI triage/correlation needs at least one alert. Add via connector or API push.
2. **Incidents feed AI investigation.** Create an incident (manually or via correlation) then open it and click **Start Deep Investigation**.
3. **Entities improve accuracy.** The more endpoint/user/IP data you push, the more context the AI has.

---

## 10. SOC Copilot

**Page:** `/soc-copilot`
**API base:** `/api/soc-copilot`

The SOC Copilot is an AI-assisted analyst helper that provides:

- **Auto Triage** — generates a verdict (`true_positive`, `false_positive`, `needs_investigation`, `benign`) for each alert with confidence scoring
- **Attack Timeline** — reconstructs the attack timeline from correlated alerts
- **Hypotheses** — generates threat hunting hypotheses from observed behavior
- **Action Recommendations** — suggests response actions with blast-radius preview
- **Analyst Feedback Loop** — analysts approve/override AI decisions, improving future accuracy

### How to Use SOC Copilot

1. Navigate to **SOC Copilot** in the sidebar.
2. In the **Triages** tab, click **+ Generate Triage** → Select an alert → The AI generates a verdict.
3. Review the verdict, confidence score, and evidence. Click **Accept** or **Override**.
4. In the **Actions** tab, see pending response action recommendations. Click **Approve** to execute or **Reject**.
5. In the **Hypotheses** tab, review AI-generated threat hunting hypotheses. Update status as you investigate.

### Onboarding Assets to SOC Copilot

SOC Copilot automatically works on all alerts/incidents in your org. No separate onboarding needed. To get better results:
- Ensure connectors are active and pulling alerts
- Make sure analysts provide feedback (accept/override) to train the system

---

## 11. Autonomous SOC & AI Detection Rules

### Autonomous SOC

**Page:** `/autonomous-soc`
**API base:** `/api/autonomous-soc`

The Autonomous SOC feature handles the full alert → triage → response cycle without human intervention for low-risk actions. It uses a 4-level action classification:

| Action Class | Description | Human Approval |
|-------------|-------------|----------------|
| `READ` | Information gathering only | Not needed |
| `SUGGEST` | Suggestion displayed to analyst | Not needed |
| `EXECUTE_WITH_APPROVAL` | Execution pending analyst approval | Required |
| `AUTO_EXECUTE_LOW_RISK` | Automatically executed for low-risk actions | Not needed |

To enable: **Autonomous SOC** page → Configure thresholds → Set which action classes auto-execute.

### AI Detection Rules

**Page:** `/ai-detection-rules`
**API base:** `/api/ai-detection-rules`

AI-generated detection rules allow the system to write Sigma/custom rules based on observed attack patterns:

1. Go to **AI Detection Rules** → Click **Generate Rules**.
2. The AI analyzes recent alert patterns and generates Sigma-compatible detection rules.
3. Review the generated rules — approve or reject each.
4. Approved rules are compiled via the Sigma compiler and applied to incoming alert streams.

```bash
# Manually trigger rule generation
POST /api/ai/generate-rules
{ "incidentId": "inc_xxx" }  # or leave empty for general pattern analysis
```

---

## 12. Threat Hunting

**Page:** `/threat-hunting`
**API base:** `/api/threat-hunting`

### Features

- **Hunt Library** — Pre-built hunt queries for common attack patterns (APT, ransomware, lateral movement, etc.)
- **Custom Hunts** — Write your own Sigma, KQL, SPL, or Lucene queries
- **AI Hypotheses** — Let AI generate hunt hypotheses from current threat landscape
- **IOC Pivoting** — Given an IOC (IP, hash, domain), automatically pivot to find related entities
- **Hunt Scheduling** — Schedule recurring hunts (daily/weekly/biweekly/monthly)
- **Hunt Playbooks** — Attach response playbooks to hunt results

### How to Run a Hunt

1. Navigate to **Threat Hunting** → **Hunts** tab.
2. Click **+ New Hunt**.
3. Choose query type: `sigma`, `kql`, `spl`, `lucene`, `eql`, or `sql`.
4. Enter your query text. The platform validates and compiles it.
5. Click **Execute Hunt** — results appear in the **Results** tab.
6. Click on any result to pivot further or link to an incident.

### Onboarding Assets to Threat Hunting

- For hunts to find meaningful data, you need **sensor data** flowing in via connectors or native sensors.
- The hunt engine queries normalized alert data and entity telemetry.
- Add more connectors = more data for hunts to query.

### AI Hypothesis Generation

```bash
POST /api/threat-hunting/ai-hypotheses
{ "context": "We've seen multiple failed logins from Eastern European IPs" }
```

The AI returns a list of prioritized hunting hypotheses with recommended queries.

---

## 13. UEBA (User & Entity Behavior Analytics)

**Page:** `/ueba`
**API base:** `/api/ueba`

UEBA builds behavioral baselines for users and entities and detects anomalies.

### Anomaly Types Detected

| Anomaly | Score Weight | Description |
|---------|-------------|-------------|
| `off_hours_login` | 25 | Login outside normal working hours |
| `new_geo_location` | 30 | Login from a new country/city |
| `suspicious_process` | 35 | Unusual process execution |
| `traffic_volume_spike` | 20 | Abnormal data transfer volume |
| `new_source_ip` | 15 | Access from a new source IP |
| `brute_force_attempt` | 40 | Repeated authentication failures |
| `privilege_escalation` | 45 | Unexpected privilege gain |
| `data_exfiltration` | 50 | Large data movement to external targets |

### Risk Levels

- `critical` ≥80 risk score
- `high` ≥60
- `medium` ≥40
- `low` ≥20
- `none` <20

### Onboarding Assets to UEBA

1. **Users:** Push authentication events via connectors (Okta, Active Directory via Wazuh, Splunk, etc.)
2. **Endpoints:** Deploy native sensors or connect CrowdStrike/SentinelOne (endpoint telemetry)
3. **Networks:** Connect Darktrace, Zscaler, Palo Alto for network behavior

Once data flows, UEBA auto-builds baselines over 7-14 days before anomaly scoring becomes accurate.

```
GET  /api/ueba/entities          — Risk leaderboard (top risky entities)
GET  /api/ueba/anomalies         — All detected anomalies
GET  /api/ueba/baselines         — Entity behavior baselines
POST /api/ueba/baselines         — Manually create a baseline for an entity
```

---

## 14. Vulnerability Scanner

**Page:** `/vuln-scanner`
**API base:** `/api/vuln-scanner`

### What It Scans

The vulnerability scanner matches software packages against a built-in CVE database including famous vulnerabilities:
- Log4Shell (CVE-2021-44228)
- Heartbleed (CVE-2014-0160)
- Spring4Shell (CVE-2022-22965)
- Apache Struts RCE (CVE-2017-5638)
- And many more

Supports package managers: `npm`, `pip`, `gem`, `cargo`, `apt`, `rpm`, `nuget`, `maven`, `gradle`, `go`

### Onboarding Assets to Vulnerability Scanner

**Method 1 — SBOM Upload (recommended):**
```bash
POST /api/supply-chain/sbom
{
  "name": "my-app",
  "version": "1.0.0",
  "format": "cyclonedx",
  "sbomData": { ... CycloneDX JSON ... }
}
```

**Method 2 — Package manifest upload:**
```
POST /api/vuln-scanner/packages/upload
```
Upload your `package.json`, `requirements.txt`, `Gemfile.lock`, etc.

**Method 3 — Native Sensor (automatic):**
Deploy the native sensor on an endpoint → it automatically sends installed package manifests to the scanner.

### Viewing Results

Go to **Vuln Scanner** → **Findings** tab. Filter by severity, status, CVE ID, or package name. Click any finding to see remediation guidance.

---

## 15. CSPM (Cloud Security Posture Management)

**Page:** `/cspm`
**API base:** `/api/cspm`

CSPM continuously audits your cloud configurations against best practices.

### Onboarding a Cloud Account

**AWS:**
```bash
POST /api/cspm/accounts
{
  "name": "Production AWS",
  "provider": "aws",
  "accountId": "123456789012",
  "region": "us-east-1",
  "credentials": {
    "accessKeyId": "AKIA...",
    "secretAccessKey": "..."
  }
}
```

**GCP / Azure:** Same endpoint, set `provider` to `"gcp"` or `"azure"` with appropriate credential fields.

After adding an account, click **Run Scan** to get immediate results, or scans run automatically every 24 hours.

### What Gets Scanned

- S3 bucket public access
- Security group rules (overly permissive)
- IAM policies (excessive permissions)
- Encryption at rest
- MFA enforcement
- Logging and monitoring gaps
- Drift detection (compares current state to last-known-good baseline)

---

## 16. Supply Chain Security (SBOM)

**Page:** `/supply-chain`
**API base:** `/api/supply-chain`

### SBOM Formats Supported

- **CycloneDX** (JSON)
- **SPDX** (JSON)

### Onboarding an Application's Supply Chain

1. Generate your SBOM:
   ```bash
   # For Node.js
   npx @cyclonedx/cyclonedx-npm --output-file sbom.json
   # For Python
   pip install cyclonedx-bom && cyclonedx-py -o sbom.json
   ```

2. Upload to SecureNexus:
   ```bash
   POST /api/supply-chain/sbom
   {
     "name": "my-service",
     "version": "2.1.0",
     "format": "cyclonedx",
     "source": "ci_cd",
     "sbomData": <contents of sbom.json>
   }
   ```

3. The platform processes the SBOM, builds the dependency graph, and runs vulnerability matching.

4. IaC scanning (Terraform, CloudFormation):
   ```bash
   POST /api/supply-chain/iac/scan
   { "content": "<your IaC template>", "type": "terraform" }
   ```

5. Container image scanning:
   ```bash
   POST /api/supply-chain/container/scan
   { "image": "myrepo/myapp:1.0", "registry": "docker.io" }
   ```

---

## 17. Compliance & Governance

**Page:** `/compliance`
**API base:** `/api/compliance`

### Supported Frameworks

The platform provides control mapping and evidence management for:
- SOC 2 Type II
- ISO 27001
- NIST CSF / NIST 800-53
- PCI DSS
- HIPAA
- GDPR
- CIS Controls
- FedRAMP

### Onboarding to Compliance

1. **Set compliance policy:** Go to **Compliance** → **Policy Settings** → Select your frameworks.
2. **Map controls:** The platform auto-maps detected security events to framework controls.
3. **Upload evidence:** Go to **Evidence Locker** → Upload artifacts (screenshots, configs, logs) against specific controls.
4. **DSAR Management:** For GDPR, go to **Compliance** → **DSAR** → Manage data subject access requests.
5. **Gap Analysis:** Go to **Compliance Gap** (`/compliance-gap`) to see what controls need attention.

### Policy Packs

**Page:** `/policy-packs`

Pre-built policy packs for common regulatory regimes. Apply a policy pack to instantly configure detection rules and alert mappings aligned to that framework.

---

## 18. Identity Governance & PAM

### Identity Governance

**Page:** `/identity-governance`
**API base:** `/api/identity-governance`

Manages user access lifecycle, access reviews, and SoD (Separation of Duties) enforcement.

- **Access Reviews:** Periodic automated reviews of user entitlements
- **Role Mining:** Discovers and suggests role assignments based on peer groups
- **SoD Violations:** Flags conflicting permission combinations

### PAM (Privileged Access Management)

**Page:** Not a standalone page — integrated into Identity Governance.
**API base:** `/api/pam`

PAM controls access to privileged accounts and credentials.

### JIT (Just-in-Time) Secret Access

**Page:** `/jit-secret-access`
**API base:** `/api/jit-secret-access`

JIT enables temporary, time-boxed access to secrets and privileged credentials:

1. User requests access to a secret via the JIT page.
2. Request goes through approval workflow (configurable).
3. On approval, a time-limited credential is issued.
4. Access automatically revokes after the TTL expires.
5. All access is logged for audit.

### Onboarding to Identity Governance

- Connect your **Okta** or **Active Directory** (via Wazuh connector) to pull user entitlement data.
- Configure access review schedules in Identity Governance settings.
- Define high-privilege role sets that trigger JIT review.

---

## 19. Deception Technology (Canary Tokens & Honeypots)

**Page:** `/deception`
**API base:** `/api/deception`

### Canary Tokens

Fake credentials/files that generate alerts when accessed — catch attackers in your environment.

**Token Types:**
- `aws_key` — Fake AWS access key that fires if used
- `database_credential` — Fake DB credentials
- `api_key` — Fake API key
- `document` — File with embedded tracking pixel
- `email_pixel` — Email tracking pixel
- `dns_token` — DNS-based trigger
- `url_token` — HTTP-based tracking URL
- `kubeconfig` — Fake Kubernetes config
- `ssh_key` — Fake SSH private key
- `slack_webhook` — Fake Slack webhook URL

**Deploy a Canary Token:**
```bash
POST /api/deception/canary-tokens
{
  "name": "Fake AWS Key - S3 Bucket",
  "tokenType": "aws_key",
  "description": "Planted in shared drive to detect unauthorized access",
  "tags": ["s3", "finance-share"]
}
```

The response includes deployment instructions for your target location.

### Honeypot Assets

Fake services that lure attackers:

**Asset Types:** `honey_account`, `honeypot_endpoint`, `deception_fileshare`, `network_decoy`, `fake_rdp`, `fake_ssh`, `fake_admin_panel`, `fake_database`

```bash
POST /api/deception/honeypots
{
  "name": "Fake Admin Panel",
  "assetType": "fake_admin_panel",
  "ipAddress": "10.0.1.50",
  "hostname": "admin-panel-legacy.internal"
}
```

Any interaction with a honeypot automatically creates a high-severity alert.

### Deployment Targets

Canary tokens can be deployed to: `s3_bucket`, `github_repo`, `email`, `shared_drive`, `active_directory`, `kubernetes`, `ci_cd_pipeline`, `internal_wiki`

---

## 20. Threat Intelligence

**Page:** `/threat-intel`
**API base:** `/api/threat-intel`

### IOC Ingestion

**Page:** `/ioc-ingestion-matching`

Import Indicators of Compromise from any source:

```bash
POST /api/threat-intel/iocs/ingest
{
  "indicators": [
    { "type": "ip", "value": "203.0.113.42", "confidence": 90, "tags": ["c2"] },
    { "type": "domain", "value": "evil-domain.ru", "confidence": 85, "tags": ["phishing"] },
    { "type": "hash", "value": "e3b0c44298fc1c149...", "confidence": 95, "tags": ["malware"] }
  ],
  "source": "MISP Feed",
  "tlp": "amber"
}
```

IOCs are automatically matched against incoming alerts in real-time via the IOC Matcher engine.

### Threat Intel Feeds

**Page:** `/threat-intel-feeds`

Pre-configured feeds:
- OSINT feeds (AlienVault OTX, Abuse.ch, etc.)
- Community Intel (shared intelligence within the SecureNexus community)
- Dark Web Monitoring (see §below)
- Commercial feeds (configurable)

To add a custom feed: **Threat Intel Feeds** → **+ Add Feed** → Enter feed URL and format (STIX/TAXII, CSV, JSON).

### Dark Web Monitoring

**Page:** `/dark-web-monitoring`
**API base:** `/api/dark-web`

Monitor paste sites, dark web forums, and breach databases for your organization's data:

```bash
POST /api/dark-web/monitors
{
  "keywords": ["company.com", "admin@company.com"],
  "monitorType": "email_domain",
  "alertThreshold": "medium"
}
```

### MITRE ATT&CK Mapping

**Page:** `/mitre-attack`

Every alert with a `mitreTechnique` or `mitreTactic` is automatically mapped to the MITRE ATT&CK matrix. The page shows your organization's coverage gaps.

---

## 21. DNS Security

**Page:** `/dns-security`
**API base:** `/api/dns-security`

DNS Security monitors and blocks malicious domains at the DNS resolution layer.

### Onboarding Assets

1. Configure your DNS resolver to forward queries to the SecureNexus DNS sniffer, OR
2. Connect Cisco Umbrella or Zscaler ZIA via their connectors (automatic DNS logging).

### Features
- DNS sinkholing for known-bad domains
- DGA (Domain Generation Algorithm) detection
- DNS tunneling detection
- Suspicious TLD monitoring

---

## 22. Email Security

**Page:** `/email-security`
**API base:** `/api/email-security`

### Onboarding Assets

Connect **Proofpoint** via connector (see §6) for automatic email threat ingestion. Or push email security events via the API:

```bash
POST /api/email-security/events
{
  "sender": "attacker@evil.com",
  "recipient": "ceo@company.com",
  "subject": "Urgent: Wire Transfer Required",
  "threatType": "phishing",
  "disposition": "quarantined"
}
```

### Features
- Phishing detection and quarantine tracking
- Business Email Compromise (BEC) analysis
- Email header analysis
- Sender reputation scoring
- Attachment sandboxing results ingestion

---

## 23. API Security

**Page:** `/api-security`
**API base:** `/api/api-security`

Monitors and protects APIs from abuse and attacks.

### Onboarding Assets

Import your OpenAPI/Swagger specifications:

```bash
POST /api/api-security/specs
{
  "name": "Production API",
  "spec": { ... OpenAPI 3.0 JSON ... },
  "baseUrl": "https://api.company.com"
}
```

The platform analyzes the spec, identifies risky endpoints, and monitors traffic against expected patterns.

---

## 24. Browser Defense

**Page:** `/browser-defense`
**API base:** `/api/browser-defense`

Protects against browser-based attacks: XSS, malicious extensions, browser exploits.

To enable: deploy the SecureNexus browser extension (Enterprise tier) or push browser security events from your EDR connectors.

---

## 25. OT/ICS Security

**Page:** `/ot-security`
**API base:** `/api/ot-security`

For operational technology environments. Supports parsing OT protocol traffic (Modbus, DNP3, EtherNet/IP, S7, IEC 61850).

### Onboarding OT Assets

```bash
POST /api/ot-security/assets
{
  "name": "PLC-01",
  "type": "plc",
  "ipAddress": "192.168.100.10",
  "protocol": "modbus",
  "vendor": "Siemens",
  "location": "Factory Floor A"
}
```

Push protocol events via the ingestion API using the OT-specific format.

---

## 26. Mobile Security

**Page:** `/mobile-security`
**API base:** `/api/mobile-security`

Mobile threat defense and device compliance monitoring.

### Onboarding Mobile Assets

Push MDM events (from Jamf, Intune, VMware Workspace ONE):
```bash
POST /api/mobile-security/events
{
  "deviceId": "device-uuid",
  "platform": "ios",
  "complianceStatus": "non_compliant",
  "violations": ["jailbroken", "outdated_os"],
  "userId": "user@company.com"
}
```

---

## 27. Physical Security

**Page:** `/physical-security`
**API base:** `/api/physical-security`

Correlates physical access events with digital security events.

### Onboarding Assets

Push badge access and camera events:
```bash
POST /api/physical-security/events
{
  "type": "badge_access",
  "userId": "emp123",
  "location": "Server Room",
  "result": "denied",
  "timestamp": "2026-03-16T14:30:00Z"
}
```

---

## 28. Ransomware Defense

**Page:** `/ransomware-defense`
**API base:** `/api/ransomware-defense`

Dedicated ransomware detection, containment, and recovery capabilities.

### Features
- Ransomware indicator monitoring (honeypot files, encryption rate detection)
- Real-time backup status integration
- Automated isolation playbooks for infected hosts
- Ransom note pattern detection

Onboarding: Ensure EDR connectors (CrowdStrike, SentinelOne, Defender) are active — they provide the telemetry needed for ransomware detection.

---

## 29. Playbooks (SOAR-Lite)

**Page:** `/playbooks`
**API base:** `/api/playbooks`

Playbooks automate response workflows triggered by security events.

### Playbook Structure

```json
{
  "name": "Isolate Infected Host",
  "trigger": "alert_critical",
  "conditions": [
    { "field": "category", "op": "eq", "value": "malware" }
  ],
  "actions": [
    { "type": "isolate_host", "params": { "target": "{{alert.hostname}}" } },
    { "type": "create_incident", "params": { "severity": "critical" } },
    { "type": "notify_slack", "params": { "channel": "#security-alerts" } }
  ]
}
```

### Triggers

| Trigger | Fires When |
|---------|-----------|
| `alert_created` | Any new alert arrives |
| `alert_critical` | Critical severity alert created |
| `incident_created` | New incident opened |
| `incident_escalated` | Incident severity upgraded |
| `manual` | Analyst clicks Run on the playbook |

### Creating a Playbook

1. Go to **Playbooks** → **+ New Playbook**.
2. Choose a trigger.
3. Add conditions (optional) to filter when the playbook fires.
4. Add actions in sequence.
5. Set status to `active` to enable it.

### Playbook Templates

Pre-built templates are available at `/playbook-templates` for common scenarios: phishing response, malware containment, account compromise, etc.

---

## 30. Integrations (Ticketing, Messaging, On-Call)

**Page:** `/integrations`
**API base:** `/api/integrations`

### Supported Integration Types

| Type | Sends To |
|------|---------|
| `jira` | Creates tickets in Jira |
| `servicenow` | Creates incidents in ServiceNow |
| `slack` | Sends messages to Slack channels |
| `teams` | Sends messages to MS Teams channels |
| `email` | Sends email notifications |
| `pagerduty` | Creates PagerDuty incidents |
| `webhook` | Calls any HTTP webhook |

### Adding a Slack Integration

```bash
POST /api/integrations
{
  "name": "Security Alerts Slack",
  "type": "slack",
  "config": {
    "webhookUrl": "https://hooks.slack.com/services/T.../B.../xxx",
    "channel": "#security-alerts",
    "defaultSeverity": "high"
  }
}
```

### Adding a Jira Integration

```bash
POST /api/integrations
{
  "name": "Security Jira",
  "type": "jira",
  "config": {
    "baseUrl": "https://yourcompany.atlassian.net",
    "apiToken": "your-api-token",
    "userEmail": "security@company.com",
    "projectKey": "SEC",
    "issueType": "Bug"
  }
}
```

---

## 31. Reports & Dashboards

**Pages:** `/reports`, `/advanced-reporting`, `/dashboard`

### Built-in Reports

- Security Posture Summary
- Alert Volume Trends
- Incident Response Metrics (MTTD, MTTR)
- Compliance Status Report
- Top Threat Actors / Techniques
- Vulnerability Exposure Report
- Executive Risk Summary

### Generating a Report

1. Go to **Reports** → **+ New Report**.
2. Select report type and date range.
3. Click **Generate** — PDF is created and stored in S3.
4. Download or share via secure link.

### Report Scheduling

**Page:** `/report-scheduling`

Schedule automated reports:
```bash
POST /api/report-scheduling/schedules
{
  "reportType": "security_posture",
  "schedule": "0 8 * * 1",  // Every Monday at 8am (cron)
  "recipients": ["ciso@company.com"],
  "format": "pdf"
}
```

---

## 32. Executive Risk Dashboard

**Page:** `/executive-risk`
**API base:** `/api/executive-risk`

Board-level risk view with:
- Overall risk score (0-100)
- Top 5 risks by business impact
- Trend analysis (improving/worsening)
- Compliance posture summary
- Recommended actions

No specific onboarding needed — this aggregates data from all other modules automatically.

---

## 33. MSSP Multi-Tenant Portal

**Pages:** `/mssp-dashboard`, `/mssp-partner-portal`
**API base:** `/api/mssp`

For Managed Security Service Providers managing multiple client organizations.

### Setup

1. Your organization must be created with `orgType: "mssp_parent"`.
2. Create child organizations: `POST /api/mssp/child-orgs` with `{ "name": "Client A", "parentOrgId": "your-org-id" }`.
3. Switch between client contexts from the MSSP Dashboard.

Each child org gets full isolation — separate data, separate API keys, separate connectors.

---

## 34. Billing, Plans & Usage

**Page:** `/billing`, `/usage-billing`
**API base:** `/api/billing`, `/api/usage`

### Plans

| Plan | Price | Users | Data Retention | Key Limits |
|------|-------|-------|---------------|-----------|
| Free | $0 | 5 | 7 days | Basic alerting, community support |
| Pro | $49/mo | 50 | 90 days | Advanced analytics, custom integrations |
| Enterprise | $199/mo | Unlimited | 1 year | SSO/SCIM, custom SLAs, dedicated support |

### Checking Usage

```bash
GET /api/usage/summary        — Current period usage
GET /api/usage/metering       — Detailed metric breakdown
```

Limits tracked: `alerts_ingested`, `connectors`, `api_keys`, `playbooks`, `ai_analyses`

---

## 35. Trust Center & Posture

**Page:** `/trust-center`, `/posture-trust-center`
**API base:** `/api/trust-center`, `/api/posture-trust`

The Trust Center provides a public-facing or internal view of your organization's security posture for customers and auditors. Configure what to publish, add certifications (SOC 2 report, ISO certificate), and track your overall security score.

---

## 36. Developer Portal & API Keys

**Page:** `/developer-portal`
**API base:** `/api/dev-portal`

### Creating an API Key

1. Go to **Settings** → **API Keys** or **Developer Portal**.
2. Click **+ Generate API Key**.
3. Enter a name and select scopes:
   - `ingest:write` — push alerts/events
   - `alerts:read` — read alerts
   - `alerts:write` — update alerts
   - `incidents:read` — read incidents
   - `incidents:write` — update incidents
4. Copy the full key — it is **shown only once**.
5. Use in requests: `Authorization: Bearer snx_XXXXXXXXXXXX`

### Key Rotation Policy

API keys should be rotated every 90 days (platform default). Expiring keys show warnings 14 days before expiry.

---

## 37. Platform Administration

**Page:** `/platform-admin`
**API base:** `/api/platform-admin`

Super-admin only. Accessible to users with the `superAdmin` flag on their account.

Features:
- View and manage all organizations
- Impersonate any user for debugging
- Global system health
- Feature flag management
- Force sync any connector globally

---

## 38. Data Residency & Sovereign Keys

**Page:** `/data-residency`
**API base:** `/api/data-residency`

Enterprise feature for orgs with data sovereignty requirements.

- Configure which AWS region stores your data (`dataResidency` on the org)
- Configure customer-managed encryption keys (CMK) in `sovereignKeyConfig`
- Set cross-border data flow controls in `crossBorderFlowControls`

---

## 39. War Room

**Page:** `/war-room`
**API base:** `/api/war-room`

A real-time collaborative workspace for major incident response. When a critical incident is declared, analysts can join the War Room to:

- Share findings in real-time
- Run runbooks collaboratively
- Track timeline of response actions
- Coordinate with external parties

Activate a War Room: From any incident detail page → **Escalate to War Room**.

---

## 40. Troubleshooting Common Issues

### AI returns empty or stub responses

1. Check `GET /api/ai/health` — if status is not `"ok"`, AWS credentials or Bedrock access is the issue.
2. Verify Bedrock model access in AWS Console → Amazon Bedrock → Model Access.
3. Check if the org has hit its AI budget cap: `GET /api/ai/usage`.
4. Ensure alerts/incidents exist — most AI endpoints need data to analyze.

### Connectors show "error" status

1. Open the connector → click **Test** — read the error message carefully.
2. Verify API key/credentials haven't expired or been rotated in the source system.
3. Check if the source system is reachable from the server (network/firewall).
4. Check **Dead Letters** tab at `/api/connectors/dead-letters` for failed sync jobs.

### Alerts not appearing after connector sync

1. Check the connector's **Last Synced** timestamp — if it's old, the sync isn't running.
2. Check the connector's `pollingIntervalMin` — default is 5 min.
3. Run a manual sync: **Connectors** → Select connector → **Sync Now**.
4. Check that the source system has events in the time range being queried.

### UEBA not detecting anomalies

UEBA needs 7-14 days of baseline data before anomaly detection becomes accurate. Ensure behavior data is flowing via connectors (Okta, EDR agents, SIEM).

### Reports fail to generate

S3 is required for report PDF generation. Verify `S3_BUCKET_NAME` is set and the AWS credentials have `s3:PutObject` permission on that bucket.

### SSO login fails

Check SSO configuration under **Org Settings** → **SSO**. Verify the SAML metadata URL or certificate is current. Check the Cognito User Pool ID if using `COGNITO_USER_POOL_ID`.

---

*For bugs and feature requests, create an issue in the project repository.*
