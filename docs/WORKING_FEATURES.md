# SecureNexus — Working Features Audit

**Audit Date:** March 2026
**Auditor:** Automated codebase analysis
**Method:** Backend route analysis (DB operations, storage layer calls, external service integrations), frontend page analysis, schema verification

---

## Audit Methodology

Features are classified as **WORKING** when they meet ALL of the following criteria:

- Backend routes perform real database operations (via `db.*` or `storage.*` calls)
- No `Math.random()` used to generate fake/simulated data
- Data is persisted to PostgreSQL and retrievable across sessions
- Frontend pages render real data from API responses

**WORKING does NOT mean production-battle-tested.** It means the code path is real (DB-backed CRUD), not simulated. None of these features have been validated with real customer data at enterprise scale.

---

## Summary

| Category                                                   | Count          |
| ---------------------------------------------------------- | -------------- |
| Fully Working (DB-backed, no fake data)                    | 48 route files |
| Partially Working (DB-backed + some simulated metrics)     | 16 route files |
| Fake Data Only (Math.random, no DB)                        | 8 route files  |
| Stubs (no DB, no random — static responses or passthrough) | 27 route files |
| **Total route files**                                      | **99**         |

---

## Fully Working Features (DB-Backed, No Fake Data)

These features have real database operations, persist data, and return real stored data.

### 1. Core Security Operations

| Feature                 | Route File          | DB/Storage Ops   | Description                                                                                                    |
| ----------------------- | ------------------- | ---------------- | -------------------------------------------------------------------------------------------------------------- |
| **SOC Dashboard**       | `dashboard.ts`      | 5 storage calls  | Real-time security score, alert counts, severity distribution, connector health — all from DB aggregation      |
| **Alert Management**    | `alerts.ts`         | 27 storage calls | Full CRUD: list, filter, bulk update, suppress, tag, archive, entity extraction, related alerts. All DB-backed |
| **Incident Management** | `incidents.ts`      | 97 storage calls | Full lifecycle: create, assign, escalate, resolve, timeline, evidence, post-incident review. Heavy DB usage    |
| **Investigations**      | `investigations.ts` | 49 storage calls | Investigation runs, steps, AI-assisted analysis. All persisted                                                 |
| **Connectors**          | `connectors.ts`     | 66 storage calls | CRUD for data source connectors, health monitoring, sync status, dead letter queue                             |
| **Data Ingestion**      | `ingestion.ts`      | 31 storage calls | Event ingestion pipeline, API key management, deduplication, stats tracking                                    |
| **Entities**            | `entities.ts`       | 6 storage calls  | Entity graph — IPs, domains, hashes, users extracted and correlated                                            |

### 2. AI & Detection

| Feature                    | Route File           | DB/Storage Ops    | Description                                                                    |
| -------------------------- | -------------------- | ----------------- | ------------------------------------------------------------------------------ |
| **AI Engine Controls**     | `engine-controls.ts` | 16 storage calls  | Circuit breaker, model selection, budget limits, prompt registry management    |
| **Community Threat Intel** | `community-intel.ts` | 11 DB ops         | Anonymous IOC sharing, industry feeds, campaign correlation. DB-backed         |
| **Autonomous SOC**         | `autonomous-soc.ts`  | 1 DB op + storage | Tier-based alert triage configuration. Relies on AI engine for actual analysis |

### 3. Cloud & Posture

| Feature                         | Route File                     | DB/Storage Ops | Description                                                                |
| ------------------------------- | ------------------------------ | -------------- | -------------------------------------------------------------------------- |
| **API Security**                | `api-security.ts`              | 13 DB ops      | API inventory, schema validation, abuse detection, sensitive data scanning |
| **CSPM** (via cloud-connectors) | `aws.ts`, `azure.ts`, `gcp.ts` | SDK calls      | Real AWS/Azure/GCP SDK integration for cloud security scanning             |
| **Posture & Trust Center**      | `posture-trust.ts`             | 12 DB ops      | Security posture scoring, peer benchmarking, public trust pages            |
| **Attack Path Analysis**        | `attack-path-advanced.ts`      | 1 DB op        | Attack path visualization from CSPM data                                   |

### 4. Identity & Access

| Feature                 | Route File               | DB/Storage Ops   | Description                                            |
| ----------------------- | ------------------------ | ---------------- | ------------------------------------------------------ |
| **Identity Governance** | `identity-governance.ts` | 5 DB ops         | Access reviews, user risk scoring, SCIM provisioning   |
| **PAM**                 | `pam.ts`                 | 2 DB ops         | Privileged access management, session recording config |
| **MFA**                 | `mfa.ts`                 | 7 DB ops         | TOTP setup, verification, backup codes                 |
| **SSO/SAML**            | `sso.ts`                 | 20 storage calls | SAML configuration, IDP management                     |

### 5. Compliance & Governance

| Feature               | Route File             | DB/Storage Ops   | Description                                                                                             |
| --------------------- | ---------------------- | ---------------- | ------------------------------------------------------------------------------------------------------- |
| **Compliance**        | `compliance.ts`        | 86 storage calls | 15+ framework mappings (ISO 27001, SOC 2, NIST, RBI, SEBI, etc.), control tracking, evidence collection |
| **Report Governance** | `report-governance.ts` | 33 storage calls | Report templates, scheduling, approval workflows                                                        |
| **Reports**           | `reports.ts`           | 28 storage calls | PDF generation, compliance reports, executive summaries                                                 |
| **Data Residency**    | `data-residency.ts`    | 4 real ops       | Region selection, BYOK key management, cross-border flow controls                                       |

### 6. Threat Management

| Feature                  | Route File          | DB/Storage Ops          | Description                                                                        |
| ------------------------ | ------------------- | ----------------------- | ---------------------------------------------------------------------------------- |
| **Threat Intelligence**  | `threat-intel.ts`   | 45 storage calls        | IOC ingestion, feed management, threat actor tracking, indicator enrichment        |
| **TPRM**                 | `tprm.ts`           | 13 DB ops               | Vendor inventory, questionnaire automation, continuous monitoring, breach alerting |
| **Deception Technology** | `deception.ts`      | 5 DB ops                | Canary tokens, honeypots, network decoys, deployment wizard                        |
| **Email Security**       | `email-security.ts` | 5 DB ops                | BEC detection, thread injection analysis, retroactive IOC scanning                 |
| **UEBA**                 | `ueba.ts`           | 9 DB ops                | User behavioral analytics, anomaly detection, risk scoring                         |
| **Dark Web Monitoring**  | `dark-web.ts`       | Uses storage via routes | Credential exposure, breach integration, brand monitoring                          |

### 7. Specialized Security

| Feature                 | Route File               | DB/Storage Ops | Description                                                           |
| ----------------------- | ------------------------ | -------------- | --------------------------------------------------------------------- |
| **OT/ICS Security**     | `ot-security.ts`         | 5 DB ops       | Passive asset discovery, protocol parsers, Purdue model visualization |
| **Mobile Security**     | `mobile-security.ts`     | 3 DB ops       | MDM integration, device posture checks, ZTNA policies                 |
| **Physical Security**   | `physical-security.ts`   | 1 DB op        | Physical-cyber convergence, badge events, visitor management          |
| **Security Awareness**  | `security-awareness.ts`  | 6 DB ops       | Training modules, assignments, completion tracking                    |
| **Privacy Engineering** | `privacy-engineering.ts` | 3 DB ops       | Data discovery, classification, PIAs, consent management              |
| **Quantum Readiness**   | `quantum-readiness.ts`   | 2 DB ops       | Cryptographic inventory, vulnerability scoring, PQC migration tasks   |
| **Developer Security**  | `developer-security.ts`  | 10 DB ops      | SAST scanning config, secret detection, CI gate management            |

### 8. Platform & Admin

| Feature             | Route File                   | DB/Storage Ops   | Description                                                             |
| ------------------- | ---------------------------- | ---------------- | ----------------------------------------------------------------------- |
| **Platform Admin**  | `platform-admin.ts`          | 54 real ops      | Super admin panel, org management, user management, tenant provisioning |
| **Organizations**   | `orgs.ts`                    | 59 storage calls | Org CRUD, member management, invitations, settings                      |
| **Onboarding**      | `onboarding.ts`              | 21 real ops      | Multi-step wizard, org setup, connector configuration                   |
| **Billing**         | `billing.ts`                 | 10 storage calls | Stripe integration, plan management, usage tracking                     |
| **Team Management** | (via `orgs.ts`)              | Included above   | Role-based access, member invitations, role assignment                  |
| **War Room**        | `war-room.ts`                | 89 real ops      | Collaborative investigation rooms, timeline, evidence, chat             |
| **MSSP Portal**     | `mssp-portal.ts` + `mssp.ts` | 42 real ops      | White-label management, client tenant management, SLA dashboards        |
| **Enterprise Org**  | `enterprise-org.ts`          | 31 storage calls | Multi-org management, hierarchy, consolidated views                     |

### 9. Infrastructure

| Feature                | Route File            | DB/Storage Ops   | Description                                 |
| ---------------------- | --------------------- | ---------------- | ------------------------------------------- |
| **Log Sources**        | `log-sources.ts`      | 3 DB ops         | Log source configuration, deployment guides |
| **Tenant Isolation**   | `tenant-isolation.ts` | 3 real ops       | Multi-tenant data isolation verification    |
| **Domain Auto-Join**   | `domain-autojoin.ts`  | 15 storage calls | Email domain-based org auto-assignment      |
| **API Versioning**     | `api-versioning.ts`   | 5 storage calls  | API version management                      |
| **Dev Portal**         | `dev-portal.ts`       | 10 DB ops        | Developer documentation, API key management |
| **Predictive Defense** | `predictive.ts`       | 11 storage calls | Risk forecasting, anomaly trend analysis    |
| **Commercial**         | `commercial.ts`       | 30 storage calls | Plan tiers, feature gating, usage limits    |

---

## External Service Integrations (Verified Real)

| Service                 | Files                                                                | Status                                                                            |
| ----------------------- | -------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| **Anthropic/Claude AI** | `server/ai/model-gateway.ts`, `server/ai/rule-generator.ts` + 5 more | Real SDK integration via AWS Bedrock. Fallback to heuristics when API unavailable |
| **Stripe Billing**      | `server/stripe-service.ts`, `server/routes/billing.ts` + 6 more      | Real Stripe SDK for subscriptions, invoices, webhooks                             |
| **AWS SDK**             | `server/cloud-connectors/aws.ts`, `server/cspm-scanner.ts` + 16 more | Real AWS SDK for S3, SES, GuardDuty, IAM, CloudTrail, EC2, RDS scanning           |
| **Google OAuth**        | `server/auth/session.ts`                                             | Real Passport.js Google OAuth integration                                         |
| **PostgreSQL**          | `server/db.ts` + entire storage layer                                | Real Drizzle ORM with 54 tables in schema                                         |

---

## Connector Implementations (25 Security Tools)

All connectors have real `fetch()` calls to external APIs. They will work IF valid API credentials are provided.

| Connector          | Lines | Status                         |
| ------------------ | ----- | ------------------------------ |
| CrowdStrike        | 119L  | Real fetch, needs API key      |
| Splunk             | 101L  | Real fetch, needs API key      |
| Elastic            | 107L  | Real fetch, needs API key      |
| Wiz                | 103L  | Real fetch, needs API key      |
| Zscaler            | 110L  | Real fetch, needs API key      |
| SentinelOne        | 87L   | Real fetch, needs API key      |
| Microsoft Defender | 90L   | Real fetch, needs API key      |
| Palo Alto          | 89L   | Real fetch, needs API key      |
| Okta               | 83L   | Real fetch, needs API key      |
| AWS GuardDuty      | 120L  | Real AWS SDK                   |
| Carbon Black       | 90L   | Real fetch, needs API key      |
| Check Point        | 136L  | Real fetch, needs API key      |
| Darktrace          | 84L   | Real fetch, needs API key      |
| FortiGate          | 89L   | Real fetch, needs API key      |
| Proofpoint         | 81L   | Real fetch, needs API key      |
| QRadar             | 74L   | Real fetch, needs API key      |
| Qualys             | 88L   | Real fetch, needs API key      |
| Rapid7             | 81L   | Real fetch, needs API key      |
| Snort              | 95L   | Real fetch, needs API key      |
| Tenable            | 83L   | Real fetch, needs API key      |
| Trend Micro        | 84L   | Real fetch, needs API key      |
| Cisco Umbrella     | 84L   | Real fetch, needs API key      |
| Wazuh              | 95L   | Real fetch, needs API key      |
| Custom Plugin      | 128L  | Configurable webhook connector |

**Note:** These connectors have the fetch/API call code written, but none have been tested against live instances. The response parsing and normalization logic may need adjustments when processing real vendor API responses.

---

## Cloud Security Connectors (Real SDK)

| Connector            | Lines | SDK Calls    | Status                                                         |
| -------------------- | ----- | ------------ | -------------------------------------------------------------- |
| AWS                  | 763L  | 12 SDK calls | Real @aws-sdk usage — EC2, IAM, S3, RDS, CloudTrail, GuardDuty |
| Azure                | 444L  | 29 SDK refs  | Real Azure SDK — Resource Graph, Defender, AAD, Key Vault      |
| GCP                  | 511L  | 8 SDK calls  | Real GCP SDK — Compute, IAM, Storage, Cloud SQL                |
| Attack Path Analyzer | 399L  | 11 SDK calls | Cross-cloud attack path analysis                               |
| Drift Detector       | 225L  | 2 SDK calls  | Configuration drift detection                                  |
| DSPM Scanner         | 394L  | 2 SDK calls  | Data security posture scanning                                 |
| Remediation Engine   | 396L  | 9 SDK calls  | Auto-remediation for cloud misconfigs                          |

---

## Storage Layer (Real DB Operations)

The storage layer (`server/storage/`) provides 407+ DB operations across 22 files:

| Storage File          | DB Ops | Manages                                                       |
| --------------------- | ------ | ------------------------------------------------------------- |
| `misc.ts`             | 40     | Tags, suppression rules, playbook templates, report schedules |
| `compliance.ts`       | 33     | Compliance frameworks, controls, evidence, assessments        |
| `organizations.ts`    | 33     | Orgs, members, invitations, settings, API keys                |
| `incidents.ts`        | 25     | Incidents, timeline, evidence, assignments                    |
| `jobs.ts`             | 25     | Background job queue, scheduling, retries                     |
| `alerts.ts`           | 24     | Alerts, bulk operations, archival, entity linking             |
| `playbooks.ts`        | 23     | Playbooks, steps, execution history, approvals                |
| `ioc.ts`              | 23     | IOC management, matching, threat feeds                        |
| `response-actions.ts` | 19     | Response action execution, rollback tracking                  |
| `ai.ts`               | 19     | AI inference history, prompt versions, model configs          |
| `cspm.ts`             | 19     | Cloud security findings, scans, accounts, remediations        |
| `connectors.ts`       | 16     | Connector configs, health, sync status, DLQ                   |
| `billing.ts`          | 15     | Stripe subscriptions, invoices, usage metering                |
| `reports.ts`          | 14     | Report templates, runs, PDF generation tracking               |
| `evidence.ts`         | 11     | Evidence chain of custody, forensic artifacts                 |
| `auth.ts`             | 10     | User auth, sessions, MFA, password resets                     |
| `war-room.ts`         | 10     | War room sessions, messages, evidence attachments             |
| `notifications.ts`    | 8      | Notification delivery, preferences, channels                  |
| `audit.ts`            | 5      | Audit log entries                                             |
| `predictive.ts`       | 17     | Risk forecasts, anomaly trends, quality snapshots             |

---

## Database Schema (54 Tables)

The schema defines 54 tables in `shared/schema.ts` (12,858 lines). Key tables:

**Core:** `organizations`, `tags`
**Security Ops:** `endpoint_assets`, `endpoint_telemetry`, `investigation_runs`, `investigation_steps`
**AI/ML:** `ai_deployment_configs`, `forecast_quality_snapshots`, `predictive_anomalies`, `risk_forecasts`
**CSPM:** `cspm_accounts`, `cspm_findings`, `cspm_scans`, `cspm_remediations`, `cspm_attack_paths`, `cspm_drift_baselines`, `cspm_drift_events`, `cspm_dspm_findings`
**Compliance:** `control_effectiveness`, `detection_gaps`
**Deception:** `chaos_schedules`, `chaos_simulations`, `purple_team_exercises`
**Threat Intel:** `dark_web_exposures`, `dark_web_monitoring_config`, `dark_web_scan_history`, `breach_monitoring_targets`
**Physical:** `physical_assets`, `physical_incidents`, `physical_security_config`, `visitors`, `badge_events`
**Awareness:** `phishing_campaigns`, `phishing_results`, `phishing_templates`, `security_awareness_config`, `training_assignments`, `training_modules`
**Quantum:** `crypto_inventory`, `quantum_migration_tasks`, `quantum_risk_scores`, `quantum_scan_history`
**Reports:** `report_runs`, `report_schedules`, `report_templates`
**Response:** `auto_response_policies`, `response_action_rollbacks`
**Other:** `anomaly_subscriptions`, `attack_surface_assets`, `connector_provider_state`, `employee_risk_scores`, `hardening_recommendations`, `posture_scores`, `workspace_templates`

**Note:** Many core tables (alerts, incidents, users, playbooks, etc.) are defined via the storage layer's runtime SQL and are not in the Drizzle schema file. The storage layer uses raw SQL for ~100+ additional tables managed by `server/storage/index.ts`.

---

_End of Working Features Audit_
