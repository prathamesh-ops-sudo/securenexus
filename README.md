# SecureNexus

**AI-Powered Security Orchestration & Intelligence Platform**

SecureNexus is a full-stack SaaS platform that unifies alerts from multiple cybersecurity tools (EDR, SIEM, IDS/IPS, cloud security), correlates them using AI, and produces attacker-centric incident narratives for security operations teams.

---

## Key Features

### AI-Driven Correlation Engine
- Powered by **Mistral Large 2 Instruct** on AWS Bedrock
- Automatic alert correlation with confidence scoring
- AI-generated incident narratives and triage recommendations
- Framework-aware analysis: MITRE ATT&CK, Kill Chain, Diamond Model, NIST IR

### Dual Alert Ingestion
- **Push-based API**: RESTful endpoints with X-API-Key authentication (SHA-256 hashed) for real-time alert ingestion from any source
- **Pull-based Connectors**: Scheduled polling engine that actively fetches from 8 security tool APIs:
  - CrowdStrike Falcon
  - Splunk Enterprise Security
  - Wiz Cloud Security
  - Wazuh
  - Palo Alto Networks Cortex XDR
  - AWS GuardDuty
  - Microsoft Defender for Endpoint
  - SentinelOne

### Alert Normalization
- 6 source-specific transformers that normalize raw alerts into a unified schema
- Automatic MITRE ATT&CK tactic/technique mapping
- Deduplication via unique index on (orgId, source, sourceEventId)

### Enhanced SOC Dashboard
- Real-time security operations overview with 6 stat cards
- Interactive charts: severity distribution, alerts by source, 7-day trend
- MITRE ATT&CK tactics widget with progress bars
- Threat category breakdown, connector health status, ingestion rate monitoring

### Incident Management
- Full incident lifecycle tracking (open through resolved/closed)
- Comments, tags, affected assets, IOCs
- AI-generated summaries and mitigation steps
- Escalation tracking and MTTR metrics

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React, TypeScript, Vite, TailwindCSS, shadcn/ui |
| Backend | Express.js, TypeScript |
| Database | PostgreSQL with Drizzle ORM |
| Authentication | OpenID Connect (Replit Auth) |
| AI Engine | AWS Bedrock Converse API (Mistral Large 2 Instruct) |
| Charts | Recharts |
| Routing | wouter |
| Data Fetching | TanStack Query |

---

## Getting Started

### Prerequisites
- Node.js 20+
- PostgreSQL database
- AWS credentials (for Bedrock AI features)

### Installation

```bash
npm install
```

### Database Setup

```bash
npm run db:push
```

### Run Development Server

```bash
npm run dev
```

The application will be available at `http://localhost:5000`.

---

## API Overview

### Alert Ingestion (Push)
```
POST /api/ingest/alert        - Single alert ingestion
POST /api/ingest/alerts/bulk  - Bulk alert ingestion (up to 100)
```
All ingestion endpoints require an `X-API-Key` header.

### Core Resources
```
GET    /api/alerts             - List alerts
GET    /api/alerts/:id         - Get alert details
PATCH  /api/alerts/:id         - Update alert
GET    /api/incidents          - List incidents
GET    /api/incidents/:id      - Get incident details
POST   /api/incidents          - Create incident
GET    /api/dashboard/stats    - Dashboard statistics
GET    /api/dashboard/analytics - Analytics data (charts, trends)
```

### Connectors
```
GET    /api/connectors         - List connectors
POST   /api/connectors         - Create connector
POST   /api/connectors/:id/test  - Test connector
POST   /api/connectors/:id/sync  - Trigger sync
```

---

## Development Phases

| Phase | Status | Description |
|-------|--------|-------------|
| 0 | Complete | Foundation - Auth, DB, UI shell, dashboard, basic CRUD |
| 1 | Complete | Data Models & Alert Schema refinements |
| 2 | Complete | Alert Ingestion System with API key auth |
| 3 | Complete | Normalization Engine (6 source transformers) |
| 4 | Complete | Enhanced SOC Dashboard with Recharts analytics |
| 5 | Complete | AI Correlation Engine (AWS Bedrock) |
| 6-16 | Planned | Incident Management, MITRE ATT&CK, Threat Intel, RBAC, SOAR, Billing |

---

## Architecture

```
                    +------------------+
                    |   React Frontend |
                    |  (Vite + shadcn) |
                    +--------+---------+
                             |
                    +--------+---------+
                    |  Express Backend  |
                    |   (TypeScript)    |
                    +--+-----+------+--+
                       |     |      |
              +--------+  +--+--+  +--------+
              |           |     |           |
     +--------+--+  +-----+--+ +--+--------+--+
     | PostgreSQL |  |  AWS   | | Connector    |
     | (Drizzle)  |  | Bedrock| | Engine (8    |
     +------------+  | (AI)   | | sources)     |
                     +--------+ +--------------+
```

---

## License

Proprietary - All rights reserved.

---

## Repository

[https://github.com/prathamesh-ops-sudo/ATS-AI-SEC](https://github.com/prathamesh-ops-sudo/ATS-AI-SEC)
