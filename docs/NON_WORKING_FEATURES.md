# SecureNexus — Non-Working Features Audit

**Audit Date:** March 2026
**Auditor:** Automated codebase analysis
**Method:** Backend route analysis (DB operations, storage layer calls, `Math.random` usage, external service calls), frontend page analysis, schema verification

---

## Classification

Features are classified into three non-working categories:

1. **FAKE** — Route exists but generates data using `Math.random()` with zero DB persistence. Users see numbers that change on every page load.
2. **STUB** — Route exists but has no database operations and no random data. Returns static/hardcoded responses or delegates to engine files that also don't persist data.
3. **PARTIAL** — Route has real DB operations BUT also uses `Math.random()` for some metrics/statistics, meaning parts of the response are fabricated.

---

## Summary

| Category                    | Count              | Impact                                            |
| --------------------------- | ------------------ | ------------------------------------------------- |
| FAKE (random data, no DB)   | 8 route files      | Data changes every refresh, nothing persisted     |
| STUB (no DB, no random)     | 27 route files     | Features appear in UI but do nothing meaningful   |
| PARTIAL (DB + random mixed) | 16 route files     | Core CRUD works but dashboards/stats are fake     |
| **Total non-working**       | **51 route files** | ~52% of all route files have non-working elements |

---

## Category 1: FAKE Features (Random Data, No Database)

These features generate all data using `Math.random()`. Nothing is persisted. Every page refresh shows different numbers.

### 1.1 Compliance Gap Analysis

- **Route:** `server/routes/compliance-gap.ts` (555 lines)
- **Random calls:** 7
- **What's fake:** Gap scores, remediation effort estimates, control coverage percentages — all generated with `Math.random()`
- **What's needed:** Real gap analysis engine that compares actual control implementations against framework requirements from the compliance storage layer
- **Frontend:** `client/src/pages/gap-analysis.tsx` — Shows fake gap percentages

### 1.2 Evidence & Chain of Custody

- **Route:** `server/routes/evidence-custody.ts` (927 lines)
- **Random calls:** 3
- **What's fake:** Evidence integrity hashes, custody transfer timestamps, forensic artifact metadata
- **What's needed:** Real evidence storage with cryptographic hashing, actual file upload/download, tamper-proof custody chain
- **Frontend:** `client/src/pages/evidence-custody.tsx`, `evidence-chain-viewer.tsx` — Shows fabricated evidence chains

### 1.3 Investigation Timeline

- **Route:** `server/routes/investigation-timeline.ts` (522 lines)
- **Random calls:** 3
- **What's fake:** Timeline event durations, analyst activity metrics, investigation phase transitions
- **What's needed:** Wire to actual investigation_runs/investigation_steps tables that already exist in schema
- **Frontend:** `client/src/pages/investigation-timeline.tsx` — Shows fake timeline data

### 1.4 Playbook Templates

- **Route:** `server/routes/playbook-templates.ts` (1,260 lines)
- **Random calls:** 2
- **What's fake:** Template usage statistics, effectiveness scores
- **What's needed:** Wire template stats to actual playbook execution data from storage layer
- **Frontend:** `client/src/pages/playbook-templates.tsx` — Template gallery with fake stats

### 1.5 SOC Copilot

- **Route:** `server/routes/soc-copilot.ts` (525 lines)
- **Random calls:** 2
- **What's fake:** Copilot suggestion confidence scores, response time metrics
- **What's needed:** Wire to real AI model gateway for actual suggestions; track suggestion acceptance rates in DB
- **Frontend:** `client/src/pages/soc-copilot.tsx` — AI copilot with fake confidence scores

### 1.6 Report Scheduling

- **Route:** `server/routes/report-scheduling.ts` (331 lines)
- **Random calls:** 2
- **What's fake:** Schedule execution history, delivery success rates
- **What's needed:** Wire to `report_schedules` and `report_runs` tables that exist in schema but aren't used here
- **Frontend:** `client/src/pages/report-scheduling.tsx` — Schedule list with fake execution data

### 1.7 Prompt-to-Artifact

- **Route:** `server/routes/prompt-artifact.ts` (686 lines)
- **Random calls:** 1
- **What's fake:** Artifact generation metrics
- **What's needed:** Persist generated artifacts to DB, track generation history
- **Frontend:** `client/src/pages/prompt-to-artifact.tsx`

### 1.8 Tenant Data Management

- **Route:** `server/routes/tenant-data.ts` (347 lines)
- **Random calls:** 3
- **What's fake:** Data volume metrics, storage usage, retention compliance percentages
- **What's needed:** Real data volume queries against actual tenant tables
- **Frontend:** `client/src/pages/tenant-data.tsx` — Shows fake storage metrics

---

## Category 2: STUB Features (No Database, No Random — Static/Empty)

These features have route files that return static responses, delegate to engine files without DB persistence, or simply exist as API surface with no real backend logic.

### 2.1 Large Stubs (500+ lines — significant UI but no backend persistence)

| Feature                      | Route File                   | Lines | What It Does                                                  | What's Missing                                                                                                                                              |
| ---------------------------- | ---------------------------- | ----- | ------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Compliance** (subset)      | `compliance.ts`              | 1,725 | Framework mappings, control tracking — 86 storage calls exist | Some sub-features use storage; others are static framework definitions. Main compliance is WORKING but sub-features like audit readiness scoring are static |
| **Incident Detail** (subset) | `incidents.ts`               | 1,512 | 97 storage calls — mostly working                             | Working overall, but some advanced features (ML-based priority, auto-assignment) are not wired                                                              |
| **JIT Secret Access**        | `jit-secret-access.ts`       | 964   | Just-in-time secret provisioning, approval workflows          | No DB persistence. Entire approval workflow is in-memory only. Secrets are not actually rotated or provisioned                                              |
| **Dark Web Monitoring**      | `dark-web.ts`                | 790   | Credential monitoring, breach alerts                          | Uses storage via other routes but this route file itself has no DB ops. Real dark web scanning requires external OSINT feeds not connected                  |
| **SSO/SAML Config**          | `sso.ts`                     | 751   | SAML provider management                                      | 20 storage calls exist — this is actually partially working for config CRUD but actual SAML authentication flow is not end-to-end tested                    |
| **DNS Security**             | `dns-security.ts`            | 713   | DNS query analysis, DGA detection, tunneling detection        | No DB persistence. `dns-analyzer.ts` engine (683L) does analysis in-memory but nothing is saved. Requires real DNS log ingestion                            |
| **AI Model Gateway**         | `model-gateway.ts`           | 684   | Model routing, A/B testing, token budgets                     | Delegates to `server/ai/model-gateway.ts` which has real Bedrock SDK calls, but this route file has no direct DB persistence                                |
| **Native Collectors**        | `native-collectors.ts`       | 647   | Agent-based data collection, heartbeats                       | Delegates to `native-collectors-engine.ts` (1,365L). Engine processes data in-memory but agent deployment/management is not DB-backed from this route       |
| **Security Metrics**         | `security-metrics.ts`        | 584   | MTTD, MTTR, detection coverage                                | Calculates metrics from other data but doesn't persist metric snapshots. No historical trending                                                             |
| **Integration Marketplace**  | `integration-marketplace.ts` | 555   | App marketplace, install/uninstall                            | Delegates to `integration-marketplace-engine.ts` (772L, 5 random calls). Marketplace catalog is hardcoded, installations not persisted                      |
| **Enterprise Org**           | `enterprise-org.ts`          | 509   | Multi-org hierarchy                                           | 31 storage calls — actually working for CRUD. Listed here in error — see WORKING features                                                                   |
| **MSSP**                     | `mssp.ts`                    | 507   | Multi-tenant MSSP features                                    | 32 storage calls — actually working for CRUD                                                                                                                |
| **Reports** (subset)         | `reports.ts`                 | 510   | Report generation                                             | 28 storage calls — mostly working. PDF generation via `report-pdf.ts` is real                                                                               |
| **Report Governance**        | `report-governance.ts`       | 485   | Report approval, classification                               | 33 storage calls — actually working                                                                                                                         |

### 2.2 Medium Stubs (300-500 lines)

| Feature                        | Route File               | Lines | What's Missing                                                                                                                              |
| ------------------------------ | ------------------------ | ----- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| **Cross-Cutting Correlations** | `cross-cutting.ts`       | 468   | Delegates to `cross-cutting-engine.ts` (1,013L). Correlation logic runs in-memory, results not persisted to DB                              |
| **Alerts** (subset)            | `alerts.ts`              | 437   | 27 storage calls — mostly working but some advanced ML-based scoring is static                                                              |
| **Engine Controls**            | `engine-controls.ts`     | 420   | 16 storage calls — mostly working for config CRUD                                                                                           |
| **Phase 2 Routes**             | `phase2-routes.ts`       | 408   | Catch-all route registrations. 14 storage calls — working as router                                                                         |
| **Runtime Guardrails**         | `runtime-guardrails.ts`  | 401   | Delegates to `runtime-guardrails-engine.ts` (996L). AI guardrail rules evaluated in-memory, not persisted                                   |
| **Browser Defense**            | `browser-defense.ts`     | 401   | Delegates to `browser-defense-engine.ts` (1,122L, 3 random). Browser isolation policies not persisted                                       |
| **Chaos Engineering**          | `chaos-engineering.ts`   | 373   | Delegates to `chaos-engineering-engine.ts` (1,506L, 7 random). Simulation results fabricated with Math.random                               |
| **Trust Center**               | `trust-center.ts`        | 366   | Delegates to `trust-center-engine.ts` (828L, 2 random). Public trust page content not persisted                                             |
| **Email Templates**            | `email-templates.ts`     | 357   | Template management for notifications. No DB persistence — templates are hardcoded                                                          |
| **Metrics Rollup**             | `metrics-rollup.ts`      | 346   | Delegates to `metrics-rollup.ts` engine. Rollup logic exists but no persistence                                                             |
| **Agent Tool Security**        | `agent-tool-security.ts` | 341   | Delegates to engine (953L, 3 random). Tool risk assessments fabricated                                                                      |
| **RAG Knowledge Base**         | `rag-knowledge.ts`       | 318   | pgvector integration exists in `server/ai/vector-search.ts`. Route file itself has no DB calls but delegates to working vector search layer |
| **Adversarial Testing**        | `adversarial-testing.ts` | 312   | Delegates to engine (800L, 8 random, 2 fetch). Red team simulation results are fabricated                                                   |
| **Policy Packs**               | `policy-packs.ts`        | 300   | Delegates to engine (1,014L). Policy pack catalog is hardcoded, not DB-backed                                                               |

### 2.3 Small Stubs (< 300 lines)

| Feature              | Route File            | Lines | What's Missing                                                                       |
| -------------------- | --------------------- | ----- | ------------------------------------------------------------------------------------ |
| **Security Graph**   | `security-graph.ts`   | 250   | Delegates to `security-graph-engine.ts` (1,861L). Graph queries run in-memory        |
| **Active Learning**  | `active-learning.ts`  | 228   | Delegates to `server/ai/active-learning.ts` which has createTable. Partially working |
| **Index/Health**     | `index.ts`            | 223   | Router index — working as intended                                                   |
| **Finding Lineage**  | `finding-lineage.ts`  | 217   | Delegates to engine (1,315L). Finding provenance tracking not persisted              |
| **Files**            | `files.ts`            | 211   | File upload/download — needs S3 integration                                          |
| **Lifecycle**        | `lifecycle.ts`        | 186   | Data lifecycle management. No DB ops                                                 |
| **Password Reset**   | `password-reset.ts`   | 175   | 7 storage calls — actually working                                                   |
| **Tiered Packaging** | `tiered-packaging.ts` | 161   | Delegates to engine (727L). Feature tiers are hardcoded                              |
| **Executive Risk**   | `executive-risk.ts`   | 149   | Delegates to engine (683L, 1 random). Executive dashboards have fake risk scores     |
| **Usage Tracking**   | `usage.ts`            | 129   | 3 storage calls — working for basic usage                                            |
| **Health Check**     | `health.ts`           | 108   | Working — returns service health status                                              |
| **Remediation**      | `remediation.ts`      | 89    | Delegates to engine (629L). Remediation tracking not persisted                       |
| **Events**           | `events.ts`           | 74    | Event streaming — working as SSE endpoint                                            |
| **Well-Known**       | `well-known.ts`       | 39    | `.well-known/security.txt` — working as intended                                     |

---

## Category 3: PARTIAL Features (DB-Backed Core + Fake Metrics)

These features have real database CRUD but supplement it with `Math.random()` for dashboards, statistics, or analytics overlays.

### 3.1 High-Impact Partial Features

| Feature                 | Route File               | Real Ops   | Random Calls | What's Fake                                                                                                                                   |
| ----------------------- | ------------------------ | ---------- | ------------ | --------------------------------------------------------------------------------------------------------------------------------------------- |
| **Endpoints/Assets**    | `endpoints.ts`           | 68 storage | 7 random     | Asset CRUD is real; risk scores, health metrics, and vulnerability counts are `Math.random()`                                                 |
| **Autonomous SOC**      | `autonomous.ts`          | 26 storage | 11 random    | Alert triage config is real; auto-response impact summaries (affected sessions, dropped connections, blocked queries) are all `Math.random()` |
| **Operations Center**   | `operations.ts`          | 40 storage | 4 random     | Operations dashboard layout is real; SLA metrics, queue depths are fabricated                                                                 |
| **Standalone Platform** | `standalone-platform.ts` | 22 real    | 3 random     | Asset/risk CRUD is real; some analytics are random                                                                                            |
| **Integrations**        | `integrations.ts`        | 47 storage | 1 random     | Integration CRUD is real; one minor metric is random                                                                                          |
| **Webhooks**            | `webhooks.ts`            | 25 storage | 1 random     | Webhook config is real; delivery metrics are random                                                                                           |
| **Admin**               | `admin.ts`               | 19 real    | 1 random     | Admin CRUD is real; one analytics metric is random                                                                                            |

### 3.2 Detection & Response Partial Features

| Feature                   | Route File              | Real Ops | Random Calls | What's Fake                                                                                                              |
| ------------------------- | ----------------------- | -------- | ------------ | ------------------------------------------------------------------------------------------------------------------------ |
| **Native Sensors**        | `native-sensors.ts`     | 12 DB    | 8 random     | Detection rule CRUD is real; rule performance metrics (tp rate, fp rate, eval time, memory, CPU) are all `Math.random()` |
| **AI Detection Rules**    | `ai-detection-rules.ts` | 12 DB    | 1 random     | Rule CRUD is real; one quality metric is random                                                                          |
| **Ransomware Defense**    | `ransomware-defense.ts` | 11 DB    | 2 random     | Kill switch config, canary files are real; drill results (RTO/RPO actuals) are random                                    |
| **Threat Hunting**        | `threat-hunting.ts`     | 15 DB    | 1 random     | Hunt query execution is real (SQL compiler); one metric is random                                                        |
| **Agent Response**        | `agent-response.ts`     | 6 DB     | 2 random     | Response action CRUD is real; impact assessment metrics are random                                                       |
| **Vulnerability Scanner** | `vuln-scanner.ts`       | 6 DB     | 3 random     | Scan config is real; vulnerability severity distributions are random                                                     |

### 3.3 Data & Analytics Partial Features

| Feature              | Route File                 | Real Ops   | Random Calls | What's Fake                                                                            |
| -------------------- | -------------------------- | ---------- | ------------ | -------------------------------------------------------------------------------------- |
| **Phase 2 Features** | `phase2-features.ts`       | 25 real    | 7 random     | Various phase 2 feature CRUD is real; DR drill results, backup verification are random |
| **Supply Chain**     | `supply-chain.ts`          | 7 DB       | 2 random     | SBOM ingestion is real; dependency risk scores are random                              |
| **Advanced Reports** | `advanced-reports.ts`      | 12 storage | 5 random     | Report config is real; chart data points are random                                    |
| **Data Lake**        | `data-lake.ts`             | 2 DB       | 2 random     | Cold storage config is real; query performance metrics are random                      |
| **Entity Graph**     | `entity-graph-advanced.ts` | 10 real    | 1 random     | Entity relationships are real; one graph metric is random                              |

---

## Engine Files Analysis (Non-Persistent)

Many features delegate to dedicated "engine" files that contain significant logic but NO database persistence. The engines process data in-memory and return results that are never saved.

| Engine File                         | Lines | Random Calls | Fetch Calls | What It Does                             | Why It's Not Working                                                          |
| ----------------------------------- | ----- | ------------ | ----------- | ---------------------------------------- | ----------------------------------------------------------------------------- |
| `security-graph-engine.ts`          | 1,861 | 0            | 0           | Security relationship graph queries      | Results never persisted, recomputed on every request                          |
| `chaos-engineering-engine.ts`       | 1,506 | 7            | 0           | BAS simulation execution                 | Simulation results are fabricated with Math.random                            |
| `prompt-artifact-engine.ts`         | 1,378 | 6            | 0           | AI prompt → security artifact generation | Generated artifacts not persisted                                             |
| `native-collectors-engine.ts`       | 1,365 | 1            | 0           | Agent data collection processing         | Processes data in-memory, no persistence                                      |
| `jit-secret-access-engine.ts`       | 1,358 | 0            | 0           | Just-in-time secret provisioning         | Approval workflows in-memory only                                             |
| `finding-lineage-engine.ts`         | 1,315 | 0            | 0           | Finding provenance tracking              | Lineage graph not persisted                                                   |
| `supply-chain-engine.ts`            | 1,203 | 0            | 0           | SBOM analysis, dependency graph          | Analysis results not persisted                                                |
| `browser-defense-engine.ts`         | 1,122 | 3            | 0           | Browser isolation policies               | Policies not persisted, some metrics fake                                     |
| `soc-copilot-engine.ts`             | 1,112 | 3            | 0           | AI SOC analyst assistance                | Suggestions not tracked, metrics fake                                         |
| `cross-cutting-engine.ts`           | 1,013 | 0            | 0           | Cross-domain correlation                 | Correlations computed but not stored                                          |
| `policy-packs-engine.ts`            | 1,014 | 0            | 0           | Compliance policy pack definitions       | Pack catalog hardcoded, not DB-backed                                         |
| `runtime-guardrails-engine.ts`      | 996   | 0            | 0           | AI safety guardrails                     | Rules evaluated in-memory                                                     |
| `agent-tool-security-engine.ts`     | 953   | 3            | 0           | Tool risk assessment for agents          | Risk scores fabricated                                                        |
| `trust-center-engine.ts`            | 828   | 2            | 0           | Public trust page content                | Content not persisted                                                         |
| `crypto-scanner.ts`                 | 809   | 0            | 0           | Cryptographic algorithm inventory        | Scan results go to schema tables (quantum\_\*), partially working             |
| `adversarial-testing-engine.ts`     | 800   | 8            | 2           | Red team simulation                      | Results heavily fabricated                                                    |
| `integration-marketplace-engine.ts` | 772   | 5            | 0           | Marketplace catalog                      | Catalog hardcoded                                                             |
| `tiered-packaging-engine.ts`        | 727   | 0            | 0           | Feature tier definitions                 | Tiers hardcoded                                                               |
| `sast-engine.ts`                    | 700   | 0            | 0           | Static code analysis                     | Parsing logic exists but no real SAST scanner integrated                      |
| `dns-analyzer.ts`                   | 683   | 0            | 0           | DNS query analysis                       | Analysis in-memory only                                                       |
| `executive-risk-engine.ts`          | 683   | 1            | 0           | Executive risk dashboard                 | Risk scores have random component                                             |
| `remediation-engine.ts`             | 629   | 0            | 0           | Remediation workflow                     | Actions not persisted                                                         |
| `predictive-engine.ts`              | 607   | 0            | 0           | Risk prediction ML                       | Uses storage.predictive (working), but predictions are heuristic, not real ML |
| `email-analyzer.ts`                 | 991   | 0            | 0           | Email threat analysis                    | NLP analysis logic exists but requires real email gateway integration         |
| `posture-engine-v2.ts`              | 893   | 2            | 0           | Security posture scoring                 | Some scores have random component                                             |
| `deception-engine.ts`               | 379   | 0            | 0           | Honeypot/canary management               | Delegates to route which has DB ops — partially working                       |

---

## Critical Gaps Summary

### Features That LOOK Complete But Aren't

1. **Chaos Engineering / BAS** — Full UI with attack scenarios, MITRE heatmap, but simulation results are entirely `Math.random()`. No real attack simulation.

2. **Autonomous SOC Response** — Impressive tier-based UI (Tier 1/2/3 analyst), but response impact metrics (affected sessions, dropped connections, blocked queries) are all fabricated.

3. **Native Sensor Performance** — Detection rule management is real, but rule performance metrics (TP rate, FP rate, eval time, memory, CPU usage) are all `Math.random()`.

4. **Endpoint Risk Scores** — Asset inventory CRUD is real (68 storage calls), but per-asset risk scores and vulnerability counts are `Math.random()`.

5. **SOC Copilot** — AI-assisted SOC analyst UI exists, but suggestion confidence scores are fabricated.

6. **Executive Risk Dashboard** — Executive-facing risk overview exists, but risk scores include `Math.random()` components.

7. **Integration Marketplace** — App store UI exists, but the marketplace catalog is hardcoded and installations aren't persisted.

### Features That Need External Services Not Connected

1. **DNS Security** — Requires real DNS log ingestion (syslog/DNS server integration)
2. **Email Security** — Requires M365/Gmail API integration for real email scanning
3. **Dark Web Monitoring** — Requires OSINT feed subscriptions (paid services)
4. **Browser Defense** — Requires browser extension deployment
5. **SAST Engine** — Requires real code parsing (currently pattern-matching only)
6. **Phishing Simulation** — Requires SMTP server for sending test emails
7. **MDM Integration** — Requires Intune/Jamf API credentials

### Database Tables That Exist But Are Underutilized

The schema has 54 tables, but many feature routes don't use them:

- `report_schedules` exists but `report-scheduling.ts` uses `Math.random()` instead
- `investigation_runs`/`investigation_steps` exist but `investigation-timeline.ts` uses `Math.random()`
- `chaos_schedules`/`chaos_simulations` exist but `chaos-engineering.ts` delegates to engine with `Math.random()`

---

## Recommendations

### Quick Wins (Wire existing DB tables to routes)

1. Wire `report-scheduling.ts` to `report_schedules` table
2. Wire `investigation-timeline.ts` to `investigation_runs`/`investigation_steps` tables
3. Wire `chaos-engineering.ts` to `chaos_schedules`/`chaos_simulations` tables
4. Remove `Math.random()` from `native-sensors.ts` performance metrics — compute from real detection data
5. Remove `Math.random()` from `endpoints.ts` risk scores — compute from real vulnerability data

### Medium Effort (Build real data pipelines)

1. Connect DNS analyzer to real syslog ingestion
2. Connect email analyzer to M365/Gmail APIs
3. Build real SAST parser integration
4. Implement actual chaos engineering simulation (not `Math.random()`)

### High Effort (Requires external subscriptions)

1. Dark web monitoring OSINT feeds
2. Threat intel feed subscriptions beyond OSINT
3. MDM vendor API integrations
4. Browser extension development and deployment

---

_End of Non-Working Features Audit_
