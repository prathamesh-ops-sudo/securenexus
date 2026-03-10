# SecureNexus: Complete 5-Phase Ship Plan
## From Current State to Production-Ready Enterprise SaaS

**Date**: February 2026
**Version**: 1.0 FINAL
**Scope**: Every single item that needs to be implemented, fixed, connected, or verified to ship SecureNexus as a real commercial SaaS product.

---

## Table of Contents

1. [Current State Assessment](#1-current-state-assessment)
2. [Complete Codebase Inventory](#2-complete-codebase-inventory)
3. [Phase 1: Infrastructure & Foundation](#3-phase-1-infrastructure--foundation)
4. [Phase 2: Core SOC Platform](#4-phase-2-core-soc-platform)
5. [Phase 3: AI Intelligence & Automation](#5-phase-3-ai-intelligence--automation)
6. [Phase 4: Enterprise & Commercial](#6-phase-4-enterprise--commercial)
7. [Phase 5: Production Hardening & Launch](#7-phase-5-production-hardening--launch)
8. [Complete API Endpoint Registry](#8-complete-api-endpoint-registry)
9. [Complete Database Schema Registry](#9-complete-database-schema-registry)
10. [Complete Frontend Page Registry](#10-complete-frontend-page-registry)
11. [Third-Party Integration Requirements](#11-third-party-integration-requirements)
12. [Security Audit Findings](#12-security-audit-findings)
13. [Testing Strategy](#13-testing-strategy)
14. [Risk Register](#14-risk-register)

---

## 1. Current State Assessment

### 1.1 Ship-Readiness Score: 15/100

| Category | Score | Max | Status |
|----------|-------|-----|--------|
| Infrastructure & Deployment | 0 | 15 | BLOCKED - Services cannot start |
| Authentication & Security | 4 | 15 | CRITICAL - Auth code exists but untested |
| Core SOC Features | 6 | 15 | PARTIAL - Schema + routes exist, no working data flow |
| AI & Automation | 2 | 10 | SCAFFOLDED - Depends on unavailable AWS Bedrock |
| UI/UX & Frontend | 5 | 15 | UNTESTED - 49 pages built, zero verified |
| Billing & Monetization | 0 | 10 | SCAFFOLDED - Stripe service exists, not integrated |
| Enterprise Features | 3 | 10 | PARTIAL - RBAC schema defined, not enforced |
| Testing & QA | 0 | 10 | NONE - Zero passing tests |

### 1.2 The Critical Blocker

**The application cannot run.** The deployment environment expects:
- Python/FastAPI backend at `/app/backend/` (uvicorn on port 8001)
- React frontend at `/app/frontend/` (yarn start on port 3000)
- MongoDB database

But the codebase is:
- TypeScript/Express backend at `/app/server/` (55,048 lines)
- React/TypeScript/Vite frontend at `/app/client/` (53,871 lines)
- PostgreSQL with Drizzle ORM

**Both services show FATAL in supervisor. Nothing loads.**

### 1.3 What Does Exist (Reusable as Specifications)

Despite the infrastructure mismatch, the TypeScript codebase is an incredibly detailed specification:
- **4,818 lines of schema** defining 126 database tables with exact field names, types, constraints, indexes, and relations
- **365 unique API endpoints** across 41 route files with full request/response handling logic
- **49 frontend pages** with complete UI components, state management, and API calls
- **25 security connector plugins** with data normalization logic
- **1,533 lines of AI prompts** for cybersecurity analysis
- **47 shadcn/ui components** pre-configured
- **6 custom hooks** for auth, event streaming, org context, role-based landing
- **13 custom components** (sidebar, command palette, guided workflow, etc.)
- **RBAC permission matrix** for 4 roles across 6 scopes

---

## 2. Complete Codebase Inventory

### 2.1 Backend Files (157 files, 55,048 lines)

#### Route Modules (41 files, 20,170 lines)
| # | File | Lines | Category | Key Endpoints |
|---|------|-------|----------|--------------|
| 1 | compliance.ts | 1,473 | Compliance | GET/PUT /api/compliance/policy, GET /api/compliance/center, POST/GET /api/compliance/dsar, GET /api/compliance/report/:type, POST /api/compliance/audit/verify, GET /api/compliance/audit/export |
| 2 | incidents.ts | 1,287 | Core | GET/POST /api/incidents (with pagination, filtering by status/severity/assignee), GET/PATCH /api/incidents/:id, POST /api/incidents/:id/comments, GET /api/incidents/:id/timeline, POST /api/incidents/:id/escalate, POST /api/incidents/:id/contain, POST /api/incidents/:id/resolve |
| 3 | operations.ts | 1,259 | Operations | GET /api/operations/overview, GET /api/operations/shift-handoff, GET /api/operations/metrics, POST /api/operations/runbooks/:id/execute, GET /api/operations/response-actions, GET /api/operations/sla-status, POST /api/operations/war-room |
| 4 | playbooks.ts | 1,197 | Automation | GET/POST /api/playbooks, GET/PUT/DELETE /api/playbooks/:id, POST /api/playbooks/:id/execute, POST /api/playbooks/:id/dry-run, GET /api/playbooks/:id/executions, POST /api/playbooks/:id/versions, GET /api/playbooks/:id/blast-radius, POST /api/playbooks/:id/simulate, GET /api/playbooks/:id/rollback-plans |
| 5 | platform-admin.ts | 1,018 | Admin | GET /api/admin/organizations, GET /api/admin/users, POST /api/admin/impersonate/:userId, GET /api/admin/audit-logs, GET /api/admin/system-health, POST /api/admin/feature-flags, GET /api/admin/usage-overview, POST /api/admin/org/:id/suspend, POST /api/admin/org/:id/restore |
| 6 | orgs.ts | 819 | Organization | GET/PUT /api/orgs/current, GET /api/orgs/members, POST /api/orgs/invite, DELETE /api/orgs/members/:id, PUT /api/orgs/members/:id/role, GET /api/orgs/teams, POST /api/orgs/teams, PUT /api/orgs/teams/:id, GET /api/orgs/roles, POST /api/orgs/roles |
| 7 | predictive.ts | 790 | Defense | GET /api/predictive/anomalies, GET /api/predictive/forecasts, GET /api/predictive/attack-surface, GET /api/predictive/recommendations, POST /api/predictive/anomaly-subscriptions, GET /api/predictive/forecast-quality, POST /api/predictive/generate |
| 8 | sso.ts | 783 | Auth | GET /api/sso/check/:slug, GET /api/sso/:slug/login, POST /api/sso/:slug/acs (SAML callback), GET /api/sso/:slug/callback (OIDC callback), PUT /api/sso/config, GET /api/sso/config |
| 9 | dev-portal.ts | 709 | Developer | GET /api/dev-portal/docs, GET /api/dev-portal/api-keys, POST /api/dev-portal/api-keys, DELETE /api/dev-portal/api-keys/:id, GET /api/dev-portal/usage, GET /api/dev-portal/sdk-examples, GET /api/dev-portal/webhooks |
| 10 | ai.ts | 681 | AI | POST /api/ai/triage (alert classification), POST /api/ai/correlate/apply (alert correlation), POST /api/ai/narrative (incident narrative gen), GET /api/ai/health, GET /api/ai/budget/usage, POST /api/ai/feedback, GET /api/ai/prompts, PUT /api/ai/prompts/:id, GET /api/ai/config, PUT /api/ai/config, GET /api/ai/inference-metrics, POST /api/ai/cache/clear |
| 11 | connectors.ts | 607 | Infrastructure | GET/POST /api/connectors, GET/PUT/DELETE /api/connectors/:id, POST /api/connectors/:id/sync, POST /api/connectors/:id/test, GET /api/connectors/:id/health, GET /api/connectors/:id/jobs, GET /api/connectors/:id/metrics, GET /api/connectors/types, GET /api/connectors/dead-letters, GET /api/connectors/:id/secret-rotations |
| 12 | threat-intel.ts | 589 | Intelligence | GET/POST /api/ioc-feeds, GET/PUT/DELETE /api/ioc-feeds/:id, POST /api/ioc-feeds/:id/fetch, GET /api/ioc-entries, GET /api/ioc-watchlists, POST /api/ioc-watchlists, GET /api/ioc-match-rules, POST /api/ioc-match-rules, GET /api/ioc-matches, GET /api/threat-intel-configs, PUT /api/threat-intel-configs/:provider, POST /api/threat-intel-configs/:provider/test |
| 13 | admin.ts | 579 | Admin | Routes overlap with platform-admin.ts - org management, user management, system health |
| 14 | investigations.ts | 570 | AI | POST /api/autonomous/investigations (trigger investigation), GET /api/autonomous/investigations, GET /api/autonomous/investigations/:id, POST /api/autonomous/evaluate/:incidentId |
| 15 | autonomous.ts | 549 | Response | GET/POST /api/autonomous/policies, GET/PUT/DELETE /api/autonomous/policies/:id, POST /api/autonomous/policies/seed-defaults, GET /api/autonomous/rollbacks, POST /api/autonomous/rollbacks/:id/execute |
| 16 | enterprise-org.ts | 526 | Enterprise | Security policies, domain verification, SSO config, SCIM config for enterprise orgs |
| 17 | ingestion.ts | 518 | Core | POST /api/v1/alerts (ingest alerts via API key), POST /api/connectors/test (test connector), GET /api/v1/ingestion/logs |
| 18 | onboarding.ts | 516 | Onboarding | GET /api/wizard/status, POST /api/wizard/create-org, POST /api/wizard/select-plan, POST /api/wizard/invite-team, POST /api/wizard/connect-integration, POST /api/wizard/complete-tour, POST /api/wizard/skip-step, POST /api/wizard/complete, GET /api/wizard/options, GET /api/v1/onboarding/status |
| 19 | report-governance.ts | 481 | Reporting | GET/POST /api/report-templates (versioned templates), GET /api/report-schedules, POST /api/report-schedules, GET /api/report-runs, GET /api/v1/report-templates/:id/versions |
| 20 | integrations.ts | 467 | Infrastructure | GET/POST /api/integrations (Jira, ServiceNow, Slack, etc.), PUT/DELETE /api/integrations/:id, POST /api/integrations/:id/test, GET/POST /api/notification-channels, GET/POST /api/ticket-sync, POST /api/ticket-sync/:id/sync |
| 21 | mssp.ts | 384 | MSSP | GET /api/mssp/children, POST /api/mssp/children, GET /api/mssp/access-grants, POST /api/mssp/access-grants, DELETE /api/mssp/access-grants/:id, GET /api/mssp/aggregate-stats |
| 22 | alerts.ts | 369 | Core | GET/POST /api/alerts, GET/PATCH /api/alerts/:id, POST /api/alerts/:id/suppress, POST /api/alerts/:id/unsuppress, GET /api/alerts/:id/entities, GET /api/alerts/:id/related, PUT /api/alerts/:id/confidence, POST /api/alerts/:id/tags, POST /api/alerts/archive, POST /api/alerts/archive/restore |
| 23 | api-versioning.ts | 362 | Infrastructure | Versioned API endpoints (v1), migration guide, version policy |
| 24 | stunning-dashboard.ts | 335 | Dashboard | GET /api/dashboard/stunning (enhanced dashboard data), GET /api/dashboard/metrics, GET /api/dashboard/trends |
| 25 | commercial.ts | 338 | Commercial | Workspace templates, plan enforcement endpoints |
| 26 | tenant-isolation.ts | 324 | Enterprise | GET /api/tenant-isolation/config, POST /api/tenant-isolation/provision-schema, GET /api/tenant-isolation/report, POST /api/tenant-isolation/register-instance, GET /api/tenant-isolation/noisy-neighbor, POST /api/tenant-isolation/dedicated-instance |
| 27 | entities.ts | 280 | Core | GET /api/entities, GET /api/entities/:id, GET /api/entities/:id/alerts, GET /api/entities/:id/graph, GET /api/attack-paths, GET /api/campaigns |
| 28 | billing.ts | 275 | Billing | GET /api/billing/plans, POST /api/billing/checkout, GET /api/billing/subscription, POST /api/billing/webhook |
| 29 | endpoints.ts | 252 | Telemetry | GET /api/endpoints, GET /api/endpoints/:id, GET /api/endpoints/:id/telemetry, POST /api/endpoints, PATCH /api/endpoints/:id |
| 30 | domain-autojoin.ts | 255 | Enterprise | Domain verification and auto-join configuration |
| 31 | reports.ts | 246 | Reporting | GET /api/reports/preview/:reportType, POST /api/reports/generate |
| 32 | webhooks.ts | 236 | Infrastructure | GET/POST /api/v1/webhooks, GET/PUT/DELETE /api/v1/webhooks/:id, GET /api/v1/webhooks/:id/logs |
| 33 | lifecycle.ts | 170 | Core | Incident lifecycle management (evidence chain, response approvals, post-incident reviews) |
| 34 | password-reset.ts | 157 | Auth | POST /api/auth/forgot-password, POST /api/auth/reset-password/validate, POST /api/auth/reset-password |
| 35 | usage.ts | 126 | Billing | GET /api/usage-metering, GET /api/usage-metering/history |
| 36 | dashboard.ts | 100 | Dashboard | GET /api/dashboard/main (core dashboard analytics) |
| 37 | files.ts | 62 | Infrastructure | POST /api/files/upload, GET /api/files/:key |
| 38 | events.ts | 58 | Real-time | GET /api/events (SSE stream for real-time updates) |
| 39 | health.ts | 29 | Infrastructure | GET /api/health |
| 40 | index.ts | 86 | Router | Master route registration |
| 41 | Various sub-routes | ~500 | Mixed | Suppression rules, SLA policies, tags, comments, correlation clusters, feature flags, SLO targets, DR runbooks, runbook templates, etc. |

#### Core Services (70+ files, 26,637 lines)
| # | File | Lines | Purpose | Status |
|---|------|-------|---------|--------|
| 1 | storage.ts | 5,424 | Monolithic data access layer (ALL database operations) | Needs decomposition |
| 2 | openapi.ts | 2,254 | OpenAPI/Swagger spec generation | Scaffolded |
| 3 | ai.ts | 899 | AWS Bedrock AI integration (alert triage, narratives, correlation) | Needs migration to Emergent LLM |
| 4 | normalizer.ts | 843 | Alert normalization from 6 source types (CrowdStrike, Splunk, Wazuh, AWS GuardDuty, Palo Alto, Generic) | Valuable logic to port |
| 5 | data-lifecycle.ts | 716 | Data retention, archival, legal holds, PII masking | Complex, needs porting |
| 6 | graph-correlation.ts | 584 | Graph-based alert correlation (shared entities, temporal proximity, TTP similarity) | Core differentiator |
| 7 | cspm-scanner.ts | 543 | Cloud Security Posture Management scanning | Complex |
| 8 | predictive-engine.ts | 540 | Anomaly detection, risk forecasting, hardening recommendations | Core differentiator |
| 9 | tenant-throttle.ts | 526 | Per-tenant rate limiting with sliding windows | Enterprise feature |
| 10 | entity-resolver.ts | 512 | Entity extraction and resolution from alerts | Core feature |
| 11 | job-queue.ts | 498 | Background job processing with retries | Infrastructure |
| 12 | stripe-service.ts | 466 | Stripe billing integration (checkout, webhooks, subscription management) | Needs Stripe key |
| 13 | event-catalog.ts | 458 | Event type registry with schema validation | Infrastructure |
| 14 | connector-engine.ts | 416 | Connector sync orchestration with retry/checkpoint/dead-letter | Core feature |
| 15 | ioc-ingestion.ts | 395 | IOC (Indicators of Compromise) feed ingestion | Intelligence feature |
| 16 | threat-enrichment.ts | 391 | Threat data enrichment from OSINT feeds | Intelligence feature |
| 17 | canary-analysis.ts | 389 | Canary deployment analysis | Enterprise feature |
| 18 | report-engine.ts | 382 | Report generation (SOC KPI, incidents, compliance, executive summary) | Enterprise feature |
| 19 | dr-drill-scheduler.ts | 371 | Disaster Recovery drill scheduling and execution | Enterprise feature |
| 20 | partition-strategy.ts | 368 | Database partitioning strategy | Infrastructure |
| 21 | tenant-isolation.ts | 363 | Per-tenant data isolation | Enterprise feature |
| 22 | correlation-engine.ts | 322 | Alert correlation (rule-based + AI-powered) | Core differentiator |
| 23 | slo-alerting.ts | 323 | SLA/SLO monitoring and breach detection | Core feature |
| 24 | ocsf.ts | 319 | Open Cybersecurity Schema Framework normalization | Standard compliance |
| 25 | secret-rotation.ts | 315 | Connector secret rotation management | Enterprise feature |
| 26 | outbound-security.ts | 307 | Outbound request security (SSRF protection, URL validation) | Security feature |
| 27 | notification-dispatcher.ts | 295 | Multi-channel notification delivery (email, Slack, webhook, PagerDuty) | Core feature |
| 28 | metrics-rollup.ts | 292 | Hourly/daily metrics aggregation | Infrastructure |
| 29 | event-bus.ts | 287 | Internal event bus for decoupled communication | Infrastructure |
| 30 | seed.ts | 286 | Database seeding (3 incidents, 12 alerts, 10 tags) | Development |
| 31 | tracing.ts | 281 | Request tracing and correlation IDs | Infrastructure |
| 32 | email-templates.ts | 279 | Email templates for notifications and invitations | Feature |
| 33 | osint-feeds.ts | 276 | Open-source intelligence feed management | Intelligence |
| 34 | investigation-agent.ts | 269 | AI-powered multi-step investigation agent | Core differentiator |
| 35 | request-validator.ts | 267 | Request payload validation middleware | Infrastructure |
| 36 | connector-config-validator.ts | 235 | Connector configuration validation | Infrastructure |
| 37 | action-dispatcher.ts | 235 | Response action execution dispatcher | Core feature |
| 38 | integration-tests.ts | 231 | Integration test definitions | Testing |
| 39 | logger.ts | 228 | Structured logging | Infrastructure |
| 40 | ioc-matcher.ts | 227 | IOC matching against alerts and entities | Intelligence |
| 41 | scaling-state.ts | 225 | Horizontal scaling state management | Enterprise |
| 42 | db-performance.ts | 225 | Database performance monitoring | Infrastructure |
| 43 | endpoint-telemetry.ts | 213 | Endpoint telemetry collection | Feature |
| 44 | security-middleware.ts | 210 | Security headers, CORS, CSRF, helmet | Infrastructure |
| 45 | query-cache.ts | 206 | Query result caching (LRU with TTL) | Infrastructure |
| 46 | config.ts | 200 | Application configuration with Zod validation | Infrastructure |
| 47 | api-response.ts | 197 | Standardized API response envelope | Infrastructure |
| 48 | outbox-processor.ts | 190 | Outbox pattern for reliable event delivery | Infrastructure |
| 49 | report-scheduler.ts | 176 | Scheduled report generation | Feature |
| 50 | sli-middleware.ts | 173 | Service Level Indicator collection middleware | Infrastructure |
| 51 | retention-scheduler.ts | 164 | Data retention policy enforcement | Compliance |
| 52 | rbac.ts | 153 | Role-based access control enforcement | Core feature |
| 53 | policy-engine.ts | 143 | Cloud policy evaluation engine | CSPM feature |
| 54 | posture-engine.ts | 132 | Security posture score computation | Feature |
| 55 | pii-engine.ts | 131 | PII detection and masking | Compliance |
| 56 | timezone-utils.ts | 125 | Timezone handling utilities | Utility |
| 57 | request-lifecycle.ts | 125 | Request lifecycle hooks | Infrastructure |
| 58 | envelope-middleware.ts | 117 | Response envelope middleware | Infrastructure |
| 59 | feature-flags.ts | 109 | Feature flag evaluation | Infrastructure |
| 60 | pagination-contract.ts | 97 | Pagination contract validation | Infrastructure |
| 61 | rollback-engine.ts | 83 | Response action rollback execution | Feature |
| 62 | email-service.ts | 68 | Email delivery service | Feature |
| 63 | s3.ts | 64 | AWS S3 file storage | Feature |
| 64 | aws-credentials.ts | 60 | AWS credential management | Infrastructure |

#### AI Subsystem (4 files, 1,533 lines)
| File | Lines | Purpose |
|------|-------|---------|
| ai/enhanced-prompts.ts | 635 | 15+ cybersecurity-specific prompt templates |
| ai/prompt-registry.ts | 388 | Prompt versioning, A/B testing, performance tracking |
| ai/model-gateway.ts | 341 | AI model routing (Bedrock/SageMaker/Azure OpenAI) |
| ai/budget.ts | 169 | AI usage budget tracking and enforcement |

#### Connector Plugins (25 files, 2,267 lines)
| Plugin | Lines | Source Type |
|--------|-------|------------|
| crowdstrike.ts | 161 | EDR |
| splunk.ts | 163 | SIEM |
| wiz.ts | 100 | Cloud Security |
| wazuh.ts | 101 | SIEM |
| paloalto.ts | 103 | Firewall/NGFW |
| aws-guardduty.ts | 122 | Cloud Security |
| microsoft-defender.ts | 79 | EDR |
| sentinelone.ts | 91 | EDR |
| elastic.ts | 87 | SIEM |
| ibm-qradar.ts | 73 | SIEM |
| fortinet-fortigate.ts | 109 | Firewall |
| carbonblack.ts | 90 | EDR |
| qualys.ts | 84 | Vulnerability Scanner |
| tenable.ts | 85 | Vulnerability Scanner |
| cisco-umbrella.ts | 79 | DNS Security |
| darktrace.ts | 91 | NDR |
| rapid7.ts | 86 | SIEM/VA |
| trendmicro.ts | 85 | AV/EDR |
| okta.ts | 89 | Identity |
| proofpoint.ts | 85 | Email Security |
| snort.ts | 70 | IDS/IPS |
| zscaler.ts | 109 | SASE |
| checkpoint.ts | 79 | Firewall |
| generic.ts | 49 | Generic/Custom |
| base-plugin.ts | 52 | Plugin base class |

#### Middleware (5 files, 1,041 lines)
| File | Lines | Purpose |
|------|-------|---------|
| plan-enforcement-enhanced.ts | 381 | Feature gating per plan tier with limit checks |
| error-handler-enhanced.ts | 311 | Structured error handling with Sentry-ready format |
| plan-enforcement.ts | 190 | Basic plan tier enforcement |
| org-rate-limit.ts | 124 | Per-org request rate limiting |
| super-admin.ts | 35 | Super-admin role verification |

### 2.2 Frontend Files (49 pages + 60 components, 60,746 lines)

#### Pages by Category
| # | Page | Lines | Category | Key Features |
|---|------|-------|----------|-------------|
| 1 | incident-detail.tsx | 3,365 | Core | Full investigation view with timeline, evidence, comments, AI analysis, response actions, evidence chain, MITRE mapping |
| 2 | compliance.tsx | 3,171 | Compliance | Multi-framework compliance dashboard, DSAR management, audit export, data retention config, PII settings |
| 3 | playbooks.tsx | 2,502 | Automation | Playbook builder, execution history, version management, simulation, blast radius preview |
| 4 | threat-intel.tsx | 2,122 | Intelligence | IOC feeds, watchlists, match rules, enrichment, threat landscape |
| 5 | alerts.tsx | 1,876 | Core | Alert list with advanced filtering, bulk actions, suppression, tag management, saved views |
| 6 | integrations.tsx | 1,770 | Infrastructure | Integration management for Jira/ServiceNow/Slack/Teams/Email/PagerDuty/Webhook |
| 7 | team-management.tsx | 1,670 | Enterprise | Team CRUD, member management, role assignment, invitation management |
| 8 | connectors.tsx | 1,541 | Infrastructure | Connector configuration wizard, health monitoring, sync management, job history |
| 9 | ai-engine.tsx | 1,431 | AI | AI configuration, prompt management, budget tracking, feedback review, model selection |
| 10 | org-settings.tsx | 1,425 | Enterprise | Organization settings, branding, security policies, domain verification |
| 11 | reports.tsx | 1,341 | Reporting | Report template management, scheduling, run history, export |
| 12 | operations.tsx | 1,348 | Operations | SOC operations center, shift handoff, war room, SLA dashboard |
| 13 | incidents.tsx | 1,276 | Core | Incident list with filtering, bulk operations, SLA status indicators |
| 14 | dashboard.tsx | 1,325 | Core | Main dashboard with alert volume charts, severity distribution, MTTR, SLA compliance |
| 15 | cspm.tsx | 1,263 | Cloud Security | Cloud accounts, scan results, findings, policy checks, compliance mapping |
| 16 | dev-portal.tsx | 1,277 | Developer | API documentation, key management, usage metrics, SDK examples, webhook testing |
| 17 | landing.tsx | 1,031 | Marketing | Public landing page with features, pricing preview, CTAs |
| 18 | platform-admin.tsx | 977 | Admin | Super-admin dashboard for org/user management, system health, feature flags |
| 19 | autonomous-response.tsx | 901 | Response | Autonomous response policy management, execution history, rollback |
| 20 | entity-graph.tsx | 880 | Investigation | Entity relationship visualization with D3/force graph |
| 21 | predictive-defense.tsx | 855 | Defense | Anomaly detection dashboard, risk forecasts, attack surface analysis |
| 22 | alert-detail.tsx | 848 | Core | Alert deep-dive with raw data, entity extraction, confidence scoring, related alerts |
| 23 | onboarding-wizard.tsx | 801 | Onboarding | Step-by-step org setup wizard (create org, plan, team, connector, tour) |
| 24 | settings.tsx | 788 | Settings | User profile, preferences, theme, notification settings |
| 25 | billing.tsx | 784 | Billing | Subscription management, plan comparison, payment methods |
| 26 | endpoint-telemetry.tsx | 768 | Telemetry | Endpoint asset inventory, telemetry metrics, risk scoring |
| 27 | mssp-dashboard.tsx | 634 | MSSP | Multi-tenant dashboard for MSSP parent organizations |
| 28 | attack-graph.tsx | 649 | Investigation | Attack path visualization with graph rendering |
| 29 | security-posture.tsx | 608 | Security | Overall security posture score with breakdown by category |
| 30 | kill-chain.tsx | 569 | Investigation | Kill chain analysis with stage-by-stage breakdown |
| 31 | analytics.tsx | 543 | Analytics | Historical analytics with trend charts, source analysis, category breakdown |
| 32 | ingestion.tsx | 553 | Infrastructure | Ingestion pipeline monitoring, log viewer, error tracking |
| 33 | usage-billing.tsx | 532 | Billing | Usage-based billing with metric breakdowns |
| 34 | dashboard-stunning.tsx | 504 | Dashboard | Enhanced "visually stunning" dashboard variant |
| 35 | audit-log.tsx | 499 | Compliance | Activity audit trail with filtering, tamper-evidence verification |
| 36 | mitre-attack.tsx | 379 | Investigation | MITRE ATT&CK framework matrix visualization |
| 37 | agentic-soc.tsx | 299 | Marketing | Agentic SOC capabilities marketing page |
| 38 | ai-soc-analyst.tsx | 294 | Marketing | AI SOC Analyst marketing page |
| 39 | reset-password.tsx | 268 | Auth | Password reset with token validation |
| 40 | product-overview.tsx | 260 | Marketing | Product overview and features page |
| 41 | about.tsx | 257 | Marketing | About/company page |
| 42 | solutions-india.tsx | 250 | Marketing | India-specific compliance solutions |
| 43 | solutions-compliance.tsx | 240 | Marketing | Compliance solutions marketing |
| 44 | solutions-mssp.tsx | 239 | Marketing | MSSP solutions marketing |
| 45 | onboarding.tsx | 221 | Onboarding | Onboarding entry/router |
| 46 | accept-invitation.tsx | 185 | Auth | Team invitation acceptance |
| 47 | forgot-password.tsx | 147 | Auth | Password reset request |
| 48 | auth-page.tsx | ~200 | Auth | Login/Register dual-panel page |
| 49 | not-found.tsx | 21 | Utility | 404 page |

#### Custom Components (13 files, 2,125 lines)
| Component | Lines | Purpose |
|-----------|-------|---------|
| app-sidebar.tsx | 422 | Main navigation sidebar with collapsible groups |
| command-palette.tsx | 375 | Cmd+K command palette for quick actions |
| guided-workflow.tsx | 214 | Step-by-step workflow wizard component |
| global-quick-create.tsx | 203 | Quick-create dropdown for new items |
| live-activity-feed.tsx | 149 | Real-time activity feed via SSE |
| onboarding-checklist.tsx | 171 | Inline onboarding progress checklist |
| page-skeleton.tsx | 155 | Loading skeleton for pages |
| empty-state.tsx | 156 | Empty state illustrations |
| security-badges.tsx | 81 | Security certification badges |
| plan-limit-banner.tsx | 66 | Plan limit warning banner |
| impersonation-banner.tsx | 75 | Admin impersonation indicator |
| theme-provider.tsx | 39 | Dark/light theme context |
| theme-toggle.tsx | 18 | Theme toggle button |

#### Hooks (6 files, 571 lines)
| Hook | Lines | Purpose |
|------|-------|---------|
| use-auth.ts | 104 | Authentication state (login, register, logout, current user) |
| use-event-stream.ts | 127 | SSE event stream subscription |
| use-org-context.ts | 101 | Current organization context and role |
| use-toast.ts | 191 | Toast notification management |
| use-role-landing.ts | 36 | Role-based default landing page |
| use-page-title.ts | 12 | Dynamic page title |

### 2.3 Database Schema (126 tables across 4,818 lines)

**Core Domain (12 tables):**
organizations, alerts, incidents, incident_comments, tags, alert_tags, incident_tags, audit_logs, audit_verification_runs, api_keys, ingestion_logs, connectors

**Entity & Intelligence (12 tables):**
entities, entity_aliases, alert_entities, correlation_clusters, attack_paths, campaigns, ioc_feeds, ioc_entries, ioc_watchlists, ioc_watchlist_entries, ioc_match_rules, ioc_matches

**AI & Analysis (3 tables):**
ai_feedback, ai_deployment_configs, investigation_runs, investigation_steps

**Automation & Response (12 tables):**
playbooks, playbook_executions, playbook_approvals, playbook_versions, playbook_simulations, blast_radius_previews, playbook_rollback_plans, response_actions, response_action_rollbacks, auto_response_policies, response_action_approvals, approval_decision_records

**Predictive Defense (5 tables):**
predictive_anomalies, attack_surface_assets, risk_forecasts, anomaly_subscriptions, forecast_quality_snapshots, hardening_recommendations

**Incident Lifecycle (5 tables):**
evidence_chain_entries, incident_response_approvals, post_incident_reviews, pir_action_items, evidence_items, investigation_hypotheses, investigation_tasks

**Compliance (9 tables):**
compliance_policies, dsar_requests, compliance_controls, compliance_control_mappings, evidence_locker_items, evidence_attachments, compliance_control_helpers, policy_checks, policy_results

**RBAC & Organization (10 tables):**
organization_memberships, org_invitations, org_roles, org_role_permissions, org_teams, org_team_memberships, saved_views, org_security_policies, org_domain_verifications, org_sso_configs, org_scim_configs

**Infrastructure & Operations (18 tables):**
connector_job_runs, connector_health_checks, suppression_rules, alert_dedup_clusters, incident_sla_policies, connector_secret_rotations, notification_channels, integration_configs, threat_intel_configs, outbound_webhooks, outbound_webhook_logs, idempotency_keys, job_queue, dashboard_metrics_cache, alert_daily_stats, alerts_archive, table_partitions, feature_flags

**Reporting (4 tables):**
report_templates, report_schedules, report_runs, report_template_versions

**SLI/SLO & DR (5 tables):**
sli_metrics, sli_metrics_hourly, sli_metrics_daily, slo_targets, dr_runbooks, dr_drill_results

**CSPM & Endpoints (5 tables):**
cspm_accounts, cspm_scans, cspm_findings, endpoint_assets, endpoint_telemetry, endpoint_telemetry_archive, posture_scores

**Commercial & Billing (7 tables):**
plans, subscriptions, invoices, org_plan_limits, usage_meter_snapshots, usage_records, onboarding_progress, wizard_progress, workspace_templates

**Event System (2 tables):**
outbox_events, ticket_sync_jobs

**Legal & Archival (4 tables):**
legal_holds, password_reset_tokens, ingestion_logs_archive, connector_job_runs_archive

**MSSP (1 table):**
mssp_access_grants

**Runbooks (2 tables):**
runbook_templates, runbook_steps

---

## 3. Phase 1: Infrastructure & Foundation

**Goal**: Get the application running with authentication, navigation, and core CRUD operations.
**Timeline Estimate**: 1-2 weeks

### 3.1 Create Backend Infrastructure
| # | Task | Description | Files to Create | Priority |
|---|------|-------------|----------------|----------|
| 1.1 | Create `/app/backend/` directory | Python FastAPI application structure | server.py, requirements.txt, .env | P0 |
| 1.2 | MongoDB connection | Connect to MongoDB using motor/pymongo via MONGO_URL env var | db.py | P0 |
| 1.3 | Collection schema setup | Create MongoDB collections mirroring the core PostgreSQL tables | models.py | P0 |
| 1.4 | Health check endpoint | GET /api/health returning status | routes/health.py | P0 |
| 1.5 | Standardized API response | Envelope format matching TypeScript api-response.ts pattern | utils/response.py | P0 |
| 1.6 | Error handling middleware | Global exception handler matching error-handler-enhanced.ts | middleware/error_handler.py | P0 |
| 1.7 | CORS configuration | Allow frontend origin | middleware/cors.py | P0 |

### 3.2 Create Frontend Infrastructure
| # | Task | Description | Files to Create | Priority |
|---|------|-------------|----------------|----------|
| 1.8 | Create `/app/frontend/` directory | React + Vite + TailwindCSS + shadcn/ui | package.json, vite.config.ts, tailwind.config.ts | P0 |
| 1.9 | Component library setup | Port 47 shadcn/ui components from /app/client | components/ui/*.tsx | P0 |
| 1.10 | Routing setup | React Router or wouter with all 49 page routes | App.tsx | P0 |
| 1.11 | API client setup | Fetch wrapper using REACT_APP_BACKEND_URL | lib/queryClient.ts | P0 |
| 1.12 | Theme system | Dark/light mode with CSS variables | components/theme-provider.tsx | P1 |

### 3.3 Authentication System
| # | Task | Description | Endpoints | Priority |
|---|------|-------------|-----------|----------|
| 1.13 | User registration | Email + password with bcrypt hashing | POST /api/register | P0 |
| 1.14 | User login | Session-based or JWT auth | POST /api/login | P0 |
| 1.15 | User logout | Clear session/token | POST /api/logout | P0 |
| 1.16 | Current user endpoint | Return authenticated user data | GET /api/auth/user | P0 |
| 1.17 | Auth middleware | Protect routes requiring authentication | middleware/auth.py | P0 |
| 1.18 | Auth page UI | Login/Register dual-panel page | pages/auth-page.tsx | P0 |
| 1.19 | Work email validation | Block free email providers (gmail, yahoo, etc.) during registration | auth validation | P1 |
| 1.20 | Password complexity | Min 8 chars, uppercase, number, special char | auth validation | P1 |

### 3.4 Core Navigation & Layout
| # | Task | Description | Components | Priority |
|---|------|-------------|------------|----------|
| 1.21 | App sidebar | Collapsible navigation with all page groups (matching app-sidebar.tsx) | app-sidebar.tsx | P0 |
| 1.22 | Page skeleton | Loading state component | page-skeleton.tsx | P0 |
| 1.23 | Empty state | No-data placeholder | empty-state.tsx | P1 |
| 1.24 | 404 page | Not found handler | not-found.tsx | P1 |

### 3.5 Dashboard (Core)
| # | Task | Description | Endpoints | Priority |
|---|------|-------------|-----------|----------|
| 1.25 | Dashboard API | Return aggregated metrics (alert count by severity, incident count by status, MTTR, recent activity) | GET /api/dashboard/main | P0 |
| 1.26 | Dashboard UI | Charts and metrics matching dashboard.tsx (alert volume, severity distribution, recent incidents, SOC KPIs) | pages/dashboard.tsx | P0 |
| 1.27 | Seed data | Populate demo data (12 alerts, 3 incidents, 10 tags, etc.) matching seed.ts | seed.py | P0 |

### 3.6 Alerts CRUD
| # | Task | Description | Endpoints | Priority |
|---|------|-------------|-----------|----------|
| 1.28 | List alerts | Paginated with filters (status, severity, source, category, date range) | GET /api/alerts | P0 |
| 1.29 | Get alert detail | Full alert data with entities | GET /api/alerts/:id | P0 |
| 1.30 | Update alert | Status change, notes, assignment | PATCH /api/alerts/:id | P0 |
| 1.31 | Alert list UI | Table with filters, bulk select, status badges | pages/alerts.tsx | P0 |
| 1.32 | Alert detail UI | Deep-dive view with raw data, entities, related alerts | pages/alert-detail.tsx | P0 |
| 1.33 | Alert tagging | Add/remove tags | POST /api/alerts/:id/tags | P1 |
| 1.34 | Alert suppression | Suppress/unsuppress alerts | POST /api/alerts/:id/suppress | P1 |

### 3.7 Incidents CRUD
| # | Task | Description | Endpoints | Priority |
|---|------|-------------|-----------|----------|
| 1.35 | List incidents | Paginated with filters | GET /api/incidents | P0 |
| 1.36 | Create incident | Manual incident creation | POST /api/incidents | P0 |
| 1.37 | Get incident detail | Full data with alerts, comments, timeline | GET /api/incidents/:id | P0 |
| 1.38 | Update incident | Status, severity, assignment | PATCH /api/incidents/:id | P0 |
| 1.39 | Incident comments | Add/list comments | POST /api/incidents/:id/comments | P0 |
| 1.40 | Incidents list UI | Table with SLA indicators | pages/incidents.tsx | P0 |
| 1.41 | Incident detail UI | Investigation view with tabs (overview, alerts, timeline, evidence, AI analysis) | pages/incident-detail.tsx | P0 |

### Phase 1 Acceptance Criteria
- [ ] Both frontend and backend services start successfully
- [ ] Health check returns 200
- [ ] User can register and login
- [ ] Dashboard shows seeded data with charts
- [ ] Alert list loads with pagination and filtering
- [ ] Alert detail page shows full alert data
- [ ] Incident list loads with pagination
- [ ] Incident detail shows linked alerts and comments
- [ ] Navigation sidebar works for all core pages
- [ ] Dark/light theme toggle works

---

## 4. Phase 2: Core SOC Platform

**Goal**: A security analyst can use the platform for daily SOC operations.
**Timeline Estimate**: 2-4 weeks

### 4.1 Alert Ingestion Pipeline
| # | Task | Description | Priority |
|---|------|-------------|----------|
| 2.1 | API key management backend | Create/revoke API keys with hash storage | P0 |
| 2.2 | Alert ingestion endpoint | POST /api/v1/alerts accepting normalized alert data, with API key auth | P0 |
| 2.3 | Alert normalization | Port normalizer.ts logic for CrowdStrike, Splunk, Wazuh, GuardDuty, Palo Alto, Generic formats | P0 |
| 2.4 | Ingestion logging | Track ingestion metrics (received, created, deduped, failed) | P0 |
| 2.5 | Alert deduplication | Match on (org, source, sourceEventId) to prevent duplicates | P1 |
| 2.6 | Ingestion UI | Pipeline monitoring page matching ingestion.tsx | P1 |

### 4.2 Connector Management
| # | Task | Description | Priority |
|---|------|-------------|----------|
| 2.7 | Connector CRUD | Create/read/update/delete connector configurations | P0 |
| 2.8 | Connector types registry | List all 25 supported connector types with config schemas | P0 |
| 2.9 | Connector health check | Validate connector credentials and connectivity | P1 |
| 2.10 | Connector sync | Trigger manual sync with simulated data flow | P1 |
| 2.11 | Connector UI | Configuration wizard matching connectors.tsx | P0 |
| 2.12 | Connector job history | Track sync runs with status, alerts created, errors | P1 |

### 4.3 Entity Resolution
| # | Task | Description | Priority |
|---|------|-------------|----------|
| 2.13 | Entity extraction | Extract IPs, domains, users, hosts, hashes, URLs from alerts during ingestion | P0 |
| 2.14 | Entity deduplication | Merge duplicate entities with alias tracking | P1 |
| 2.15 | Entity-alert linking | Track which entities appear in which alerts | P0 |
| 2.16 | Entity API | GET /api/entities with type filtering, GET /api/entities/:id/alerts | P0 |
| 2.17 | Entity graph UI | Force-directed graph matching entity-graph.tsx | P1 |

### 4.4 Alert Correlation
| # | Task | Description | Priority |
|---|------|-------------|----------|
| 2.18 | Rule-based correlation | Correlate alerts sharing entities, temporal proximity, or TTP patterns | P0 |
| 2.19 | Correlation clusters | Group correlated alerts into clusters | P0 |
| 2.20 | Auto-incident creation | Create incidents from high-confidence correlation clusters | P1 |
| 2.21 | Correlation API | GET /api/correlation/clusters | P0 |

### 4.5 Incident Lifecycle
| # | Task | Description | Priority |
|---|------|-------------|----------|
| 2.22 | Incident escalation | POST /api/incidents/:id/escalate with audit trail | P0 |
| 2.23 | Incident containment | POST /api/incidents/:id/contain with timestamp | P0 |
| 2.24 | Incident resolution | POST /api/incidents/:id/resolve with MTTR calculation | P0 |
| 2.25 | Evidence chain | Immutable hash-chain evidence log per incident | P1 |
| 2.26 | Incident timeline | Chronological event history | P0 |
| 2.27 | SLA tracking | Per-severity SLA policies with breach detection | P1 |
| 2.28 | SLA policies API | CRUD for SLA policy definitions | P1 |

### 4.6 RBAC & Access Control
| # | Task | Description | Priority |
|---|------|-------------|----------|
| 2.29 | Role-based middleware | Enforce permissions on every route based on user role (owner/admin/analyst/read_only) | P0 |
| 2.30 | Organization context | Scope all queries to current user's organization | P0 |
| 2.31 | Permission checks | Validate scope+action permissions before operations | P0 |
| 2.32 | Custom roles | Create org-specific roles with custom permission sets | P2 |

### 4.7 Audit Logging
| # | Task | Description | Priority |
|---|------|-------------|----------|
| 2.33 | Audit log capture | Log all write operations (create, update, delete) with actor, resource, details | P0 |
| 2.34 | Audit log API | GET /api/audit-logs with filtering | P0 |
| 2.35 | Audit log UI | Audit trail page matching audit-log.tsx | P0 |
| 2.36 | Tamper-evidence | Hash chain verification for audit log integrity | P2 |

### 4.8 Tags & Suppression
| # | Task | Description | Priority |
|---|------|-------------|----------|
| 2.37 | Tag CRUD | Create/list/delete tags | P1 |
| 2.38 | Suppression rules | Create rules to auto-suppress matching alerts | P1 |
| 2.39 | Suppression rules API | GET/POST /api/suppression-rules | P1 |

### Phase 2 Acceptance Criteria
- [ ] Alerts can be ingested via API key
- [ ] Connectors can be configured and tested
- [ ] Entities are extracted from alerts automatically
- [ ] Correlated alerts are grouped into clusters
- [ ] Incidents can be escalated, contained, and resolved
- [ ] SLA timers track breach status
- [ ] RBAC enforces permissions on all routes
- [ ] Audit logs capture all write operations
- [ ] Tags and suppression rules work

---

## 5. Phase 3: AI Intelligence & Automation

**Goal**: AI-powered analysis and automated response that differentiates the product.
**Timeline Estimate**: 2-3 weeks

### 5.1 AI Integration (Emergent LLM Key)
| # | Task | Description | Priority |
|---|------|-------------|----------|
| 3.1 | AI service setup | Integrate Emergent LLM key for OpenAI/Claude/Gemini | P0 |
| 3.2 | Alert triage | AI classification of alert severity and category | P0 |
| 3.3 | Incident narrative | AI-generated incident summary and narrative | P0 |
| 3.4 | Correlation analysis | AI-assisted alert correlation reasoning | P1 |
| 3.5 | AI configuration UI | AI engine settings page matching ai-engine.tsx | P0 |
| 3.6 | AI budget tracking | Track token usage against budget limits | P1 |
| 3.7 | AI feedback loop | Analyst ratings and corrections for AI outputs | P1 |

### 5.2 Investigation Agent
| # | Task | Description | Priority |
|---|------|-------------|----------|
| 3.8 | Multi-step investigation | Automated investigation: gather alerts -> enrich entities -> correlate evidence -> MITRE mapping -> AI analysis -> recommendation | P1 |
| 3.9 | Investigation runs API | POST /api/autonomous/investigations, GET status/results | P1 |
| 3.10 | Investigation UI | Investigation results display in incident-detail.tsx | P1 |

### 5.3 Threat Intelligence
| # | Task | Description | Priority |
|---|------|-------------|----------|
| 3.11 | IOC feed management | CRUD for IOC feed sources (MISP, STIX, TAXII, OTX, VirusTotal, CSV, Custom) | P1 |
| 3.12 | IOC ingestion | Fetch and parse IOC entries from configured feeds | P1 |
| 3.13 | IOC matching | Match IOC entries against alerts and entities | P1 |
| 3.14 | Watchlists | Custom IOC watchlist management | P2 |
| 3.15 | Threat intel UI | Full threat intelligence page matching threat-intel.tsx | P1 |
| 3.16 | MITRE ATT&CK mapping | Map alerts/incidents to MITRE techniques | P1 |
| 3.17 | MITRE ATT&CK UI | Interactive ATT&CK matrix matching mitre-attack.tsx | P1 |

### 5.4 SOAR Playbooks
| # | Task | Description | Priority |
|---|------|-------------|----------|
| 3.18 | Playbook CRUD | Create/edit/delete automation playbooks | P1 |
| 3.19 | Playbook execution | Execute playbook actions (simulated mode) | P1 |
| 3.20 | Playbook dry-run | Preview execution without side effects | P1 |
| 3.21 | Execution history | Track playbook runs with results | P1 |
| 3.22 | Playbook UI | Builder and history matching playbooks.tsx | P1 |
| 3.23 | Playbook versioning | Track playbook changes with version history | P2 |
| 3.24 | Blast radius preview | Estimate impact before execution | P2 |

### 5.5 Autonomous Response
| # | Task | Description | Priority |
|---|------|-------------|----------|
| 3.25 | Response policies | Define auto-response policies with conditions and actions | P1 |
| 3.26 | Policy evaluation | Evaluate policies against incidents to recommend actions | P1 |
| 3.27 | Response actions | Execute simulated response actions (isolate host, block IP, etc.) | P1 |
| 3.28 | Approval workflow | Require approval for high-risk actions | P2 |
| 3.29 | Rollback mechanism | Reverse executed response actions | P2 |
| 3.30 | Autonomous response UI | Policy management matching autonomous-response.tsx | P1 |

### 5.6 Predictive Defense
| # | Task | Description | Priority |
|---|------|-------------|----------|
| 3.31 | Anomaly detection | Detect volume spikes, new vectors, timing anomalies | P1 |
| 3.32 | Risk forecasting | Predict likelihood of attack types | P1 |
| 3.33 | Attack surface analysis | Track exposed assets and risk scores | P2 |
| 3.34 | Hardening recommendations | Generate security improvement suggestions | P2 |
| 3.35 | Predictive defense UI | Dashboard matching predictive-defense.tsx | P1 |

### 5.7 Visualization
| # | Task | Description | Priority |
|---|------|-------------|----------|
| 3.36 | Attack graph | Visualize attack paths through the network | P2 |
| 3.37 | Kill chain | Map incidents to cyber kill chain stages | P2 |
| 3.38 | Attack graph UI | Interactive graph matching attack-graph.tsx | P2 |
| 3.39 | Kill chain UI | Kill chain visualization matching kill-chain.tsx | P2 |

### Phase 3 Acceptance Criteria
- [ ] AI triages alerts with severity/category classification
- [ ] AI generates incident narratives
- [ ] Investigation agent runs multi-step analysis
- [ ] IOC feeds can be configured and fetched
- [ ] IOC entries match against alerts
- [ ] MITRE ATT&CK techniques are mapped to incidents
- [ ] Playbooks can be created, tested, and executed
- [ ] Autonomous response policies evaluate incidents
- [ ] Anomaly detection identifies volume spikes
- [ ] Attack path visualization renders

---

## 6. Phase 4: Enterprise & Commercial

**Goal**: Enterprise customers can evaluate, purchase, and operate the platform.
**Timeline Estimate**: 2-3 weeks

### 6.1 Stripe Billing
| # | Task | Description | Priority |
|---|------|-------------|----------|
| 4.1 | Plan definitions | Free, Starter, Professional, Enterprise tiers with feature limits | P0 |
| 4.2 | Stripe checkout | Create checkout session for plan selection | P0 |
| 4.3 | Stripe webhooks | Handle subscription lifecycle events | P0 |
| 4.4 | Subscription management | View/change/cancel subscription | P0 |
| 4.5 | Plan enforcement | Gate features based on current plan tier | P0 |
| 4.6 | Billing UI | Subscription page matching billing.tsx | P0 |
| 4.7 | Usage tracking | Track events ingested, connectors, AI tokens, API calls | P1 |
| 4.8 | Usage billing UI | Usage dashboard matching usage-billing.tsx | P1 |

### 6.2 Team & Organization Management
| # | Task | Description | Priority |
|---|------|-------------|----------|
| 4.9 | Team CRUD | Create/edit/delete teams within organization | P0 |
| 4.10 | Team members | Add/remove members, assign roles | P0 |
| 4.11 | Invitations | Send email invitations with token-based acceptance | P0 |
| 4.12 | Team management UI | Full page matching team-management.tsx | P0 |
| 4.13 | Org settings UI | Organization settings matching org-settings.tsx | P0 |

### 6.3 SSO & Authentication Enhancement
| # | Task | Description | Priority |
|---|------|-------------|----------|
| 4.14 | Google OAuth | Social login via Emergent-managed Google Auth | P0 |
| 4.15 | Password reset | Forgot password -> email token -> reset flow | P0 |
| 4.16 | Account lockout | Lock account after 5 failed login attempts | P1 |
| 4.17 | Rate limiting on auth | 5 requests per minute per IP on login/register | P1 |
| 4.18 | Session management | Configurable session timeout | P1 |

### 6.4 Notification System
| # | Task | Description | Priority |
|---|------|-------------|----------|
| 4.19 | Notification channels | Configure email/webhook/Slack/Teams delivery | P1 |
| 4.20 | Notification dispatch | Send notifications on incident creation, SLA breach, etc. | P1 |
| 4.21 | Email templates | Port email-templates.ts designs | P1 |
| 4.22 | Integration UI | Integrations page matching integrations.tsx | P1 |

### 6.5 Compliance Management
| # | Task | Description | Priority |
|---|------|-------------|----------|
| 4.23 | Compliance frameworks | GDPR, HIPAA, SOX, PCI-DSS, ISO 27001, NIST support | P1 |
| 4.24 | Compliance policies | Data retention settings, PII masking, DSAR SLA | P1 |
| 4.25 | DSAR management | Data Subject Access Request workflow | P2 |
| 4.26 | Compliance controls | Control mapping with evidence management | P2 |
| 4.27 | Compliance UI | Full page matching compliance.tsx | P1 |

### 6.6 Reporting
| # | Task | Description | Priority |
|---|------|-------------|----------|
| 4.28 | Report templates | SOC KPI, Incidents, Compliance, Executive Summary templates | P1 |
| 4.29 | Report generation | Generate PDF/CSV reports | P1 |
| 4.30 | Report scheduling | Schedule recurring reports | P2 |
| 4.31 | Reports UI | Report management matching reports.tsx | P1 |

### 6.7 Onboarding
| # | Task | Description | Priority |
|---|------|-------------|----------|
| 4.32 | Onboarding wizard | Step-by-step: create org, choose plan, invite team, connect integration, dashboard tour | P1 |
| 4.33 | Workspace templates | Pre-configured setups for different use cases | P2 |
| 4.34 | Onboarding wizard UI | Matching onboarding-wizard.tsx | P1 |

### 6.8 Analytics & Security Posture
| # | Task | Description | Priority |
|---|------|-------------|----------|
| 4.35 | Analytics page | Historical trend analysis | P1 |
| 4.36 | Security posture score | Composite score from CSPM, endpoints, incidents, compliance | P2 |
| 4.37 | Analytics UI | Matching analytics.tsx | P1 |
| 4.38 | Security posture UI | Matching security-posture.tsx | P2 |

### Phase 4 Acceptance Criteria
- [ ] Users can subscribe to a plan via Stripe
- [ ] Feature limits are enforced per plan
- [ ] Teams can be created with member management
- [ ] Invitations are sent and accepted
- [ ] Google OAuth login works
- [ ] Password reset flow works
- [ ] Notifications fire on key events
- [ ] Compliance dashboard shows framework status
- [ ] Reports can be generated and downloaded
- [ ] Onboarding wizard guides new users

---

## 7. Phase 5: Production Hardening & Launch

**Goal**: Production-ready SaaS with security, performance, and operational excellence.
**Timeline Estimate**: 2-3 weeks

### 7.1 Security Hardening
| # | Task | Description | Priority |
|---|------|-------------|----------|
| 5.1 | Input validation | Validate all API inputs with Pydantic models | P0 |
| 5.2 | SQL/NoSQL injection prevention | Parameterized queries everywhere | P0 |
| 5.3 | XSS prevention | Sanitize all user-generated content | P0 |
| 5.4 | CSRF protection | CSRF tokens on all state-changing requests | P0 |
| 5.5 | Security headers | Helmet equivalent (CSP, HSTS, X-Frame-Options, etc.) | P0 |
| 5.6 | Rate limiting | Global and per-endpoint rate limits | P0 |
| 5.7 | API key security | Hashed storage, prefix display, rotation support | P1 |
| 5.8 | PII masking | Mask sensitive data in exports and logs | P1 |
| 5.9 | SSRF protection | Validate outbound URLs (matching outbound-security.ts) | P1 |
| 5.10 | Dependency audit | Check for known vulnerabilities in all dependencies | P1 |

### 7.2 Performance
| # | Task | Description | Priority |
|---|------|-------------|----------|
| 5.11 | Database indexing | Ensure all query patterns have proper MongoDB indexes | P0 |
| 5.12 | Query caching | Implement LRU cache for frequent queries (matching query-cache.ts) | P1 |
| 5.13 | Pagination optimization | Cursor-based pagination for large collections | P1 |
| 5.14 | Dashboard metric caching | Pre-compute dashboard stats (matching dashboard_metrics_cache) | P1 |
| 5.15 | Bundle optimization | Frontend code splitting, lazy loading | P1 |

### 7.3 Testing
| # | Task | Description | Priority |
|---|------|-------------|----------|
| 5.16 | Backend unit tests | Test all route handlers and services | P0 |
| 5.17 | Backend integration tests | Test full API flows (auth, CRUD, correlation) | P0 |
| 5.18 | Frontend E2E tests | Test auth flow, dashboard, alert management, incident workflow | P0 |
| 5.19 | API contract tests | Validate request/response schemas | P1 |
| 5.20 | Load testing | Verify performance under concurrent load | P2 |

### 7.4 Marketing & Public Pages
| # | Task | Description | Priority |
|---|------|-------------|----------|
| 5.21 | Landing page | Public marketing page with features, pricing, CTAs | P1 |
| 5.22 | Product overview | Feature showcase page | P2 |
| 5.23 | Solution pages | Compliance, MSSP, India-specific pages | P2 |
| 5.24 | About page | Company/team information | P2 |
| 5.25 | Pricing page | Public plan comparison with CTA | P1 |

### 7.5 Developer Portal
| # | Task | Description | Priority |
|---|------|-------------|----------|
| 5.26 | API documentation | OpenAPI/Swagger documentation | P1 |
| 5.27 | Developer portal UI | API key management, usage metrics, SDK examples | P1 |
| 5.28 | Webhook management | Outbound webhook configuration with event filtering | P2 |

### 7.6 Platform Administration
| # | Task | Description | Priority |
|---|------|-------------|----------|
| 5.29 | Platform admin dashboard | Org/user overview, system health | P1 |
| 5.30 | User impersonation | Admin can impersonate users for support | P2 |
| 5.31 | Feature flags | Toggle features per org/role | P2 |

### 7.7 Advanced Enterprise
| # | Task | Description | Priority |
|---|------|-------------|----------|
| 5.32 | CSPM integration | Cloud security posture scanning UI | P2 |
| 5.33 | Endpoint telemetry | Endpoint asset inventory and monitoring | P2 |
| 5.34 | SOC operations center | Shift handoff, war room, SLA dashboard | P2 |
| 5.35 | MSSP multi-tenant | Parent-child org hierarchy with access grants | P3 |
| 5.36 | Data lifecycle management | Retention policies, archival, legal holds | P2 |

### 7.8 Real-time Features
| # | Task | Description | Priority |
|---|------|-------------|----------|
| 5.37 | SSE event stream | Real-time updates for alerts, incidents, investigations | P1 |
| 5.38 | Live activity feed | Real-time SOC activity feed component | P1 |
| 5.39 | Command palette | Cmd+K quick actions | P2 |

### Phase 5 Acceptance Criteria
- [ ] All OWASP Top 10 vulnerabilities addressed
- [ ] All core flows have E2E tests
- [ ] Page load time < 2 seconds
- [ ] API response time < 500ms (p95)
- [ ] Landing page is public and SEO-ready
- [ ] API documentation is accessible
- [ ] Platform admin can manage orgs
- [ ] Real-time updates work via SSE

---

## 8. Complete API Endpoint Registry

### Authentication (6 endpoints)
```
POST   /api/register
POST   /api/login
POST   /api/logout
GET    /api/auth/user
GET    /api/auth/me
POST   /api/auth/ensure-org
POST   /api/auth/forgot-password
POST   /api/auth/reset-password/validate
POST   /api/auth/reset-password
```

### Alerts (14 endpoints)
```
GET    /api/alerts                     (list with pagination + filters)
POST   /api/alerts                     (create)
GET    /api/alerts/:id                 (detail)
PATCH  /api/alerts/:id                 (update)
POST   /api/alerts/:id/suppress        (suppress)
POST   /api/alerts/:id/unsuppress      (unsuppress)
GET    /api/alerts/:id/entities        (linked entities)
GET    /api/alerts/:id/related         (related alerts)
PUT    /api/alerts/:id/confidence      (update confidence)
POST   /api/alerts/:id/tags            (manage tags)
POST   /api/alerts/archive             (archive old alerts)
POST   /api/alerts/archive/restore     (restore archived)
POST   /api/v1/alerts                  (ingest via API key)
```

### Incidents (15+ endpoints)
```
GET    /api/incidents                  (list)
POST   /api/incidents                  (create)
GET    /api/incidents/:id              (detail)
PATCH  /api/incidents/:id              (update)
POST   /api/incidents/:id/comments     (add comment)
PATCH  /api/comments/:id               (edit comment)
POST   /api/incidents/:id/escalate
POST   /api/incidents/:id/contain
POST   /api/incidents/:id/resolve
GET    /api/incidents/:id/timeline
```

### Dashboard (6 endpoints)
```
GET    /api/dashboard/main
GET    /api/dashboard/stunning
GET    /api/dashboard/metrics
GET    /api/dashboard/trends
```

### Connectors (15+ endpoints)
```
GET    /api/connectors
POST   /api/connectors
GET    /api/connectors/:id
PUT    /api/connectors/:id
DELETE /api/connectors/:id
POST   /api/connectors/:id/sync
POST   /api/connectors/:id/test
GET    /api/connectors/:id/health
GET    /api/connectors/:id/health-check
GET    /api/connectors/:id/jobs
GET    /api/connectors/:id/metrics
GET    /api/connectors/:id/secret-rotations
GET    /api/connectors/types
POST   /api/connectors/test
GET    /api/connectors/dead-letters
```

### AI (12+ endpoints)
```
POST   /api/ai/triage
POST   /api/ai/correlate/apply
POST   /api/ai/narrative
GET    /api/ai/health
GET    /api/ai/budget/usage
POST   /api/ai/feedback
GET    /api/ai/feedback/:resourceType/:resourceId
GET    /api/ai/prompts
PUT    /api/ai/prompts/:id
GET    /api/ai/prompts/:id/history
GET    /api/ai/prompts/:id/audit
GET    /api/ai/config
PUT    /api/ai/config
GET    /api/ai/inference-metrics
POST   /api/ai/cache/clear
POST   /api/ai/playbook-authoring/propose
GET    /api/ai-deployment/config
PUT    /api/ai-deployment/config
```

### (365 total endpoints - remaining listed in categories above in Section 2.1)

---

## 9. Complete Database Schema Registry

(Full 126-table inventory already documented in Section 2.3 above)

---

## 10. Complete Frontend Page Registry

(Full 49-page inventory already documented in Section 2.2 above)

---

## 11. Third-Party Integration Requirements

| # | Integration | Purpose | Phase | Required Key |
|---|-------------|---------|-------|-------------|
| 1 | Emergent LLM Key (OpenAI/Claude/Gemini) | AI triage, narratives, investigation, correlation | Phase 3 | Emergent Universal Key |
| 2 | MongoDB | Primary database | Phase 1 | MONGO_URL (env) |
| 3 | Stripe | Billing & subscriptions | Phase 4 | Test key in pod |
| 4 | Emergent Google Auth | Social login | Phase 4 | Emergent managed |

---

## 12. Security Audit Findings

### Critical
| # | Finding | Risk | Phase |
|---|---------|------|-------|
| S1 | No email validation - anyone can register with any email | Abuse/spam accounts | Phase 1 |
| S2 | Default user role is not restricted | Privilege escalation risk | Phase 1 |
| S3 | No password complexity enforcement | Weak credentials | Phase 1 |
| S4 | No rate limiting on auth endpoints | Brute force attacks | Phase 4 |
| S5 | No account lockout after failed attempts | Brute force attacks | Phase 4 |

### High
| # | Finding | Risk | Phase |
|---|---------|------|-------|
| S6 | No MFA support | Account compromise risk | Phase 5 |
| S7 | RBAC defined but not enforced on routes | Unauthorized access | Phase 2 |
| S8 | API keys stored (need to verify hashing) | Key compromise | Phase 2 |
| S9 | No SSRF protection on outbound requests | Server-side request forgery | Phase 5 |
| S10 | No input validation on many endpoints | Injection attacks | Phase 5 |

### Medium
| # | Finding | Risk | Phase |
|---|---------|------|-------|
| S11 | Audit logs not tamper-evident | Forensic integrity | Phase 2 |
| S12 | No PII masking in data exports | Data privacy violation | Phase 5 |
| S13 | No session timeout configuration | Session hijacking | Phase 4 |
| S14 | No IP allowlist for admin access | Unauthorized admin access | Phase 5 |
| S15 | Connector secrets not encrypted at rest | Secret exposure | Phase 5 |

---

## 13. Testing Strategy

### Phase 1: Foundation Testing
- Backend: pytest unit tests for auth, CRUD, middleware
- Frontend: Playwright E2E for auth flow, dashboard, alert/incident navigation
- API: curl-based smoke tests for all endpoints

### Phase 2: Core SOC Testing
- Integration tests: alert ingestion -> entity extraction -> correlation -> incident creation
- RBAC tests: verify permission enforcement for each role
- Audit log tests: verify all operations are captured

### Phase 3: AI & Automation Testing
- AI integration tests: verify LLM calls return valid classifications
- Playbook tests: dry-run execution with expected outcomes
- IOC matching tests: verify IOCs match against test alerts

### Phase 4: Enterprise Testing
- Billing tests: Stripe checkout, webhook handling, plan enforcement
- SSO tests: Google OAuth flow
- Notification tests: email/webhook delivery

### Phase 5: Security & Load Testing
- OWASP ZAP automated scan
- Load testing: 100 concurrent users
- Penetration testing: manual injection testing

---

## 14. Risk Register

| # | Risk | Probability | Impact | Mitigation |
|---|------|------------|--------|------------|
| R1 | Infrastructure rebuild takes too long | Medium | Critical | Focus on 15 core pages first, defer marketing/admin |
| R2 | AI integration quality varies | Medium | High | Use multiple models, implement feedback loop |
| R3 | MongoDB doesn't handle relations well | Medium | Medium | Use embedded documents + $lookup for joins |
| R4 | 49 pages can't all be rebuilt quickly | High | Medium | Prioritize by user value: dashboard > alerts > incidents > rest |
| R5 | Stripe integration complexity | Low | Medium | Use test mode, follow integration playbook |
| R6 | Schema migration loses data fidelity | Medium | High | Comprehensive field mapping, validation tests |
| R7 | Security vulnerabilities introduced | Medium | Critical | Follow OWASP, use testing agent |
| R8 | Performance under load | Medium | High | Index early, cache dashboard, paginate everything |

---

## Summary: Total Work Items

| Phase | Items | P0 | P1 | P2 | P3 |
|-------|-------|----|----|----|----|
| Phase 1: Foundation | 41 | 27 | 14 | 0 | 0 |
| Phase 2: Core SOC | 39 | 18 | 17 | 4 | 0 |
| Phase 3: AI & Automation | 39 | 2 | 27 | 10 | 0 |
| Phase 4: Enterprise | 38 | 8 | 18 | 10 | 2 |
| Phase 5: Hardening | 39 | 8 | 14 | 14 | 3 |
| **TOTAL** | **196** | **63** | **90** | **38** | **5** |

---

*This document serves as the definitive reference for shipping SecureNexus as a production SaaS product. Every item listed here must be implemented, verified, and tested before the platform can be confidently shipped to paying customers.*
