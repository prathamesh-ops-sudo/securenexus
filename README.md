# SecureNexus — Agentic SOC Platform

**AI-Powered Security Operations Center | Autonomous Threat Detection, Correlation & Incident Response**

SecureNexus is an **Agentic SOC** (Security Operations Center) platform that uses **AI SOC Analyst** agents to autonomously detect, investigate, and respond to security threats. Built by **Arica Technologies** (India), it unifies alerts from 24+ cybersecurity tools (EDR, SIEM, IDS/IPS, cloud security), correlates them using AI, and produces attacker-centric incident narratives — reducing Tier-1 analyst workload by 80%+.

**Key capabilities:** Agentic SOC | AI SOC Analyst | SOAR Automation | MITRE ATT&CK Mapping | Multi-Tenant RBAC | Automated Compliance (SOC 2, ISO 27001, NIST CSF) | MSSP Multi-Tenancy | Indian Data Residency | Enterprise SSO/SAML | Usage Metering & Plan Enforcement

[![Live Platform](https://img.shields.io/badge/Live-nexus.aricatech.xyz-06b6d4?style=flat-square)](https://nexus.aricatech.xyz)
[![Built in India](https://img.shields.io/badge/Built%20in-India%20%F0%9F%87%AE%F0%9F%87%B3-ff9933?style=flat-square)](https://aricatech.xyz)

---

## Why SecureNexus?

| Challenge       | Traditional SIEM           | SecureNexus Agentic SOC                               |
| --------------- | -------------------------- | ----------------------------------------------------- |
| Alert triage    | Manual, 45+ min per alert  | Autonomous AI triage in under 5 min                   |
| False positives | 70%+ noise                 | 70% fewer false positives via behavioral correlation  |
| Deployment      | Weeks of configuration     | 30 minutes, read-only API connectors                  |
| Correlation     | Rule-based, static         | AI-powered entity + temporal + kill-chain correlation |
| Compliance      | Manual evidence collection | Automated SOC 2, ISO 27001, NIST CSF reports          |
| Multi-tenancy   | Add-on, complex            | Native MSSP parent-child with org isolation           |
| Cost            | $50K-$500K/year            | Free tier available, Pro from $49/mo                  |

---

## Key Features

### AI SOC Analyst & Correlation Engine

- Powered by **AWS Bedrock** (Claude, Mistral Large 2, Llama) with model gateway and circuit breaker
- Dual correlation: AI-powered semantic correlation + entity-based graph correlation
- Automatic alert triage with confidence scoring and reasoning traces
- AI-generated incident narratives, MITRE ATT&CK mapping, and mitigation recommendations
- Prompt registry with version control and A/B testing
- AI budget controls and token usage monitoring

### Alert Ingestion & Normalization

- **Push-based API**: RESTful endpoints with X-API-Key authentication (SHA-256 hashed)
- **Pull-based Connectors**: Scheduled polling from 8+ security tool APIs:
  - CrowdStrike Falcon, Splunk Enterprise Security, Wiz Cloud Security, Wazuh
  - Palo Alto Networks Cortex XDR, AWS GuardDuty, Microsoft Defender, SentinelOne
- 6 source-specific transformers normalizing alerts into a unified schema
- Deduplication via unique index on (orgId, source, sourceEventId)
- Connector health monitoring and sync throughput optimization

### SOAR Automation & Playbooks

- Playbook-driven incident response with one-click actions
- Playbook governance: version control, approval workflows, audit trail
- Dry-run simulation mode for testing response actions
- Policy tuning and engine controls dashboard

### Threat Intelligence

- Real-time IOC ingestion from STIX/TAXII feeds
- OSINT feed configuration with health indicators and manual refresh
- Entity graph analysis with relationship mapping
- Threat intel confidence boosting for correlation

### Incident Response Lifecycle

- Full IR lifecycle: detection, triage, investigation, containment, eradication, recovery, lessons learned
- AI-generated summaries, timelines, and affected asset tracking
- Escalation workflows with MTTR/MTTD metrics
- Hash chain integrity for tamper-proof audit trails

### Enterprise SOC Dashboard

- Real-time security operations overview with customizable widgets
- Interactive charts: severity distribution, alerts by source, 7-day trend, ingestion rate
- MITRE ATT&CK tactics heatmap with drill-down
- Threat category breakdown, connector health, SLA queue monitoring
- Split-view alert investigation with resizable panels

### Compliance & Reporting

- Automated evidence collection for SOC 2 Type II, ISO 27001, NIST CSF, GDPR
- Scheduled compliance reports with PDF/CSV export
- Control mapping with coverage scoring
- Audit log with CSV/JSON export, date range filtering, and IP display

### Enterprise Multi-Tenancy

- Organization management with settings, branding, and domain auto-join
- RBAC with role-based navigation and permission enforcement
- SSO/SAML integration with OIDC support
- MSSP parent-child organization hierarchy
- Usage metering with plan-based enforcement (alerts/day, connectors, AI executions)
- Stripe billing integration with subscription lifecycle management

### Security Hardening

- CSRF protection with double-submit cookie pattern
- Input validation on all endpoints (Zod schemas)
- SSRF protection with DNS rebinding prevention
- Rate limiting, secure headers (HSTS, CSP, X-Frame-Options)
- Secrets redaction in logs and API responses
- Supply chain security with dependency auditing

### Observability & Operations

- Distributed tracing with correlation IDs across request chains
- Structured logging with centralized redaction
- Metrics rollup dashboard with historical browser
- Outbox event replay and monitoring
- API versioning with lifecycle dashboard and deprecation tracking
- Database query performance monitoring with budget controls

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
GET    /api/alerts             - List alerts (paginated, filterable, sortable)
GET    /api/alerts/:id         - Get alert details
PATCH  /api/alerts/:id         - Update alert
GET    /api/incidents          - List incidents
GET    /api/incidents/:id      - Get incident details
POST   /api/incidents          - Create incident
GET    /api/dashboard/stats    - Dashboard statistics
GET    /api/dashboard/analytics - Analytics data (charts, trends)
```

### AI & Correlation

```
POST /api/ai/correlate         - AI-powered alert correlation
POST /api/ai/triage            - AI alert triage with reasoning
POST /api/correlation/scan     - Entity-based correlation scan
GET  /api/correlation/clusters - List correlation clusters
```

### Connectors

```
GET    /api/connectors         - List connectors
POST   /api/connectors         - Create connector
POST   /api/connectors/:id/test  - Test connector
POST   /api/connectors/:id/sync  - Trigger sync
```

### Compliance & Reporting

```
GET  /api/compliance/reports   - List compliance reports
POST /api/compliance/reports   - Generate compliance report
GET  /api/export/alerts        - Export alerts (CSV)
GET  /api/audit-log            - Audit log with filtering
```

---

## Architecture

### Application Architecture

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
     | (Drizzle)  |  | Bedrock| | Engine (8+   |
     +------------+  | (AI)   | | sources)     |
                     +--------+ +--------------+
```

### CI/CD Pipeline

```text
Pull Request -> Build Check + Lint + TypeCheck + Prettier + ESLint + E2E Tests
Merge to main -> Build & Push image to ECR
  -> Deploy to staging namespace (EKS)
  -> Deploy to UAT namespace (EKS)
  -> Deploy to production namespace (EKS + Argo Rollouts canary 20%/50%/80%/100%)

Security: GitGuardian secret scanning, CodeQL static analysis, Devin Review
Observability: Prometheus + Grafana (monitoring namespace)
```

### Infrastructure

```
AWS Account (us-east-1)
|
+-- Amazon EKS Cluster: "securenexus" (K8s 1.31)
|   +-- Namespace: staging      (1 replica)
|   +-- Namespace: uat          (1 replica)
|   +-- Namespace: production   (2 replicas, Argo Rollouts canary)
|   +-- Namespace: argo-rollouts (controller)
|   +-- Namespace: monitoring   (Prometheus + Grafana)
|
+-- Amazon ECR: securenexus (Docker image registry)
+-- Amazon RDS: PostgreSQL (database)
+-- Amazon S3: securenexus-platform (file storage)
+-- Amazon SES: Transactional email (invitations, billing, alerts)
+-- Amazon Cognito: Authentication (Google + GitHub OAuth)
+-- AWS Secrets Manager: Credential storage
+-- Amazon ELB: Load balancers (per namespace)
```

---

## Tech Stack

| Layer          | Technology                                                                             |
| -------------- | -------------------------------------------------------------------------------------- |
| Frontend       | React 18, TypeScript, Vite, TailwindCSS, shadcn/ui, Radix UI, Recharts, TanStack Query |
| Backend        | Express.js, TypeScript, Drizzle ORM, Zod validation                                    |
| Database       | PostgreSQL (AWS RDS) with partitioning, indexes, query budgets                         |
| AI/ML          | AWS Bedrock (Claude, Mistral Large 2, Llama), model gateway with circuit breaker       |
| Auth           | AWS Cognito (Google + GitHub OAuth), session-based with CSRF                           |
| Email          | AWS SES (transactional notifications)                                                  |
| Billing        | Stripe (subscription management, usage metering)                                       |
| Infrastructure | AWS EKS (Kubernetes), Docker, Argo Rollouts, Helm                                      |
| CI/CD          | GitHub Actions, ECR, staged deployment (staging, UAT, canary production)               |
| Monitoring     | Prometheus, Grafana, structured logging, distributed tracing                           |
| Security       | MITRE ATT&CK v15, NIST SP 800-61r2, Cyber Kill Chain, Diamond Model, OCSF              |
| SEO            | Schema.org JSON-LD, Open Graph, speakable markup, llms.txt                             |

---

## Content & Resources

- **Product Overview**: [nexus.aricatech.xyz/product](https://nexus.aricatech.xyz/product)
- **What is an Agentic SOC?**: [nexus.aricatech.xyz/product/agentic-soc](https://nexus.aricatech.xyz/product/agentic-soc)
- **AI SOC Analyst**: [nexus.aricatech.xyz/product/ai-soc-analyst](https://nexus.aricatech.xyz/product/ai-soc-analyst)
- **Platform Comparison**: [nexus.aricatech.xyz/product/comparison](https://nexus.aricatech.xyz/product/comparison)
- **Solutions for India**: [nexus.aricatech.xyz/solutions/india](https://nexus.aricatech.xyz/solutions/india)
- **MSSP Multi-Tenant SOC**: [nexus.aricatech.xyz/solutions/mssp](https://nexus.aricatech.xyz/solutions/mssp)
- **Compliance Automation**: [nexus.aricatech.xyz/solutions/compliance](https://nexus.aricatech.xyz/solutions/compliance)
- **About Arica Technologies**: [nexus.aricatech.xyz/about](https://nexus.aricatech.xyz/about)

---

## License

Proprietary - All rights reserved. Built by [Arica Technologies](https://aricatech.xyz), India.
