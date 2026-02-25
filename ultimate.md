# SecureNexus: Ultimate Improvement / Upgrade / Enhancement Opportunities (Exhaustive)

This document is a comprehensive, codebase-driven catalog of improvement opportunities across SecureNexus. It is intentionally written as plain descriptive language (no code snippets, no schema definitions) and is meant to be a persistent backlog for product, engineering, security, and infrastructure work.

For every item below, the structure is:
- Current problem (what exists today / what is missing)
- Why it matters (risk, cost, user impact, scalability)
- What to do (exactly what should be implemented or changed)

Scope assumptions (based on current repo + infra conventions):
- Backend: Node.js + Express, Drizzle ORM, PostgreSQL on RDS
- Frontend: React + Vite + Tailwind + Radix
- Deploy: EKS (staging/uat/production), Argo Rollouts, GitHub Actions, AWS Secrets Manager, S3
- Platform: Multi-tenant org model + RBAC + connectors + ingestion + correlation + AI-assisted workflows

---

## 0) Cross-cutting "platform hygiene" (applies to everything)

### 0.1 Single source of truth for configuration
- Current problem: Configuration is spread across environment variables, GitHub Actions, k8s manifests, and runtime defaults in code (examples: S3 bucket fallback in server/s3.ts; session secret fallback in server/replit_integrations/auth/replitAuth.ts; region fixed in a few places).
- Why it matters: Drift between environments causes production-only failures, security footguns (unsafe defaults), and makes onboarding new engineers/clients slower.
- What to do:
  - Create a centralized configuration module that validates all required runtime settings at startup (per environment).
  - Eliminate insecure or environment-specific fallbacks (especially secrets).
  - Clearly separate "required" vs "optional" configuration and document each setting’s purpose, allowed values, and owner.

### 0.2 Standardize response envelopes and error formats
- Current problem: The codebase has a mixture of legacy endpoints returning arrays and newer v1 endpoints returning enveloped responses; error bodies vary across routes.
- Why it matters: Inconsistent API behavior increases frontend complexity, breaks typed clients, and complicates customer integration.
- What to do:
  - Define one canonical API envelope and apply it consistently across all API versions.
  - Standardize error codes, messages, and error metadata (validation errors, auth errors, rate limits, upstream provider errors).
  - Provide explicit deprecation policy for legacy endpoints.

### 0.3 Remove implicit "default org" behavior everywhere
- Current problem: Several subsystems fall back to orgId = "default" (examples: job-queue cache_refresh handler, outbox processor, etc.) instead of forcing explicit tenant context.
- Why it matters: Default fallbacks are a recurring cross-tenant data leak risk and create hard-to-debug multi-tenant incidents.
- What to do:
  - Make orgId mandatory for every org-scoped operation and remove defaulting.
  - Where truly global operations exist, represent them explicitly (orgId null) and handle them separately.

### 0.4 Replace console logging with structured, correlated logging
- Current problem: Console logging is used broadly and often logs raw JSON payloads (server/index.ts request logging captures and truncates response bodies; many subsystems log errors with minimal context).
- Why it matters: Debugging production incidents requires correlation (requestId, orgId, userId, route, trace id). Logging sensitive data creates compliance and data leakage risk.
- What to do:
  - Implement structured logging with correlation IDs (requestId and jobId/outboxEventId) and consistent fields.
  - Add centralized log redaction (secrets, auth tokens, credentials, cookies, PII).
  - Emit logs in JSON format and standardize log levels.

### 0.5 “Never silently swallow errors” policy
- Current problem: Some flows catch and ignore errors (for example, org membership auto-provision helpers log to console but do not propagate; connector parsers and external fetches sometimes ignore parse errors).
- Why it matters: Silent failures cause “it looks healthy but doesn’t work” behavior and degrade trust.
- What to do:
  - Replace silent catches with explicit error classification and surfaced UI feedback.
  - Ensure every failure results in at least one of: user-visible error, retry path, audit log entry, or alert.

---

## 1) Performance

### 1.1 Database query performance and load shaping
- Current problem: Many endpoints can become high-cardinality over time (alerts, incidents, entities, logs). Even with pagination added in places, the system lacks consistent query plans and guardrails.
- Why it matters: As customers ingest more telemetry, the same queries will become the dominant cost driver (RDS CPU/IO, slow UI, timeouts).
- What to do:
  - Add explicit performance budgets per endpoint (p95 latency targets per environment).
  - Add query plan review for top N endpoints (alerts listing, incident listing, entity graph, connectors sync history, audit logs).
  - Ensure every high-cardinality endpoint enforces pagination with max limits, default sorting, and indexed filters.

### 1.2 Index strategy and query patterns
- Current problem: Indexing exists for many common lookups, but long-term scaling requires systematic index governance across the most written tables and time-series-ish tables.
- Why it matters: Without the right composite indexes, RDS will degrade gradually and unpredictably.
- What to do:
  - Maintain an “index contract” per high-write table: required composite indexes, rationale, and removal plan.
  - Add continuous monitoring of slow queries and index hit rates.

### 1.3 Caching strategy maturity
- Current problem: There is an in-memory query cache module (server/query-cache.ts) and some cached metrics, but cache invalidation, tenancy scoping, stampede protection, and persistence are not fully systematized.
- Why it matters: In-memory caches do not scale horizontally; stale caches can cause incorrect analyst decisions.
- What to do:
  - Decide and document cache tiers: per-instance memory cache vs shared cache (Redis or managed alternative).
  - Implement cache stampede protection (single-flight for common expensive queries).
  - Enforce tenant-aware cache keys and invalidation patterns.
  - Add metrics: hit rate by key prefix, evictions, stale reads.

### 1.4 Connector sync throughput and latency
- Current problem: Connector engine performs many upstream calls serially; it also performs normalization and storage writes without batching strategy guarantees across all connectors.
- Why it matters: Connector sync is the biggest external-latency component; it can also overload upstream APIs and your own DB.
- What to do:
  - Implement per-connector concurrency controls, per-provider backoff, and adaptive scheduling.
  - Batch inserts/updates where possible; avoid per-alert DB calls.
  - Add incremental sync cursors and durable checkpoints per connector.

### 1.5 Job worker scalability
- Current problem: Job worker is a polling loop with small concurrency and uses per-instance in-memory dedup.
- Why it matters: In multi-replica deployments, each replica competes to poll; dedup is not cross-instance; job storms are possible.
- What to do:
  - Introduce distributed job queue semantics (visibility timeouts, leases, worker heartbeats).
  - Move dedup to the database (unique fingerprints with TTL) or a shared store.
  - Add job prioritization semantics that are enforced at claim time.

### 1.6 Frontend bundle size, rendering, and hydration costs
- Current problem: The dashboard and other pages are large, chart-heavy, and likely ship many libraries to all users.
- Why it matters: Large JS bundles slow first paint and degrade adoption, especially for enterprise users behind restrictive networks.
- What to do:
  - Add route-level code splitting and lazy loading for heavy pages.
  - Add bundle analysis as a CI check with budgets.
  - Reduce global imports of heavy charting dependencies where not needed.

### 1.7 SSE/event stream performance
- Current problem: SSE clients are kept in memory; broadcast iterates over all clients; no backpressure/slow-client handling beyond try/catch.
- Why it matters: With many users and many events, broadcasts can become O(N) per event and block the event loop.
- What to do:
  - Add per-client buffering limits and drop/disconnect policy.
  - Add event type filtering and subscription-based delivery.
  - Consider a pub/sub backbone if cross-replica delivery is needed.

---

## 2) Security

### 2.1 Session security and CSRF hardening
- Current problem: Cookie-based sessions are used and some defaults are permissive (sameSite lax; secure depends on FORCE_HTTPS; a default session secret exists as a fallback).
- Why it matters: Cookie sessions without robust CSRF protection are a common enterprise security blocker.
- What to do:
  - Remove any default/fallback secrets; require a strong secret per environment.
  - Implement CSRF protection for state-changing endpoints and document how the frontend obtains/sends tokens.
  - Move sameSite defaults toward stricter settings where feasible and document cross-domain implications.

### 2.2 Security middleware baseline
- Current problem: Express hardening is partial (JSON body limits and x-powered-by disabled exist; other standard protections are missing or not uniformly enforced).
- Why it matters: Enterprises expect baseline OWASP protections and security headers; gaps increase exploitability.
- What to do:
  - Add a complete security middleware baseline (security headers, input sanitization, and consistent rate limiting strategy).
  - Ensure middleware is applied before all routes.

### 2.3 Input validation coverage
- Current problem: Some endpoints use validation patterns, but validation is not universal and not always centralized. Some external provider configurations are accepted without strict validation.
- Why it matters: Validation gaps lead to injection issues, operational incidents, and corrupted data.
- What to do:
  - Enforce schema validation for every request body, query parameter, and path parameter.
  - Validate connector configs per connector type and explicitly validate URL formats, allowed protocols, and credential fields.

### 2.4 Secrets handling and redaction
- Current problem: Secrets are stored in AWS Secrets Manager and synced into Kubernetes secrets, but runtime redaction and “never log secrets” guardrails are not consistently enforced.
- Why it matters: Leaked credentials are catastrophic; enterprises require strong guarantees.
- What to do:
  - Implement centralized secret redaction at logging boundaries.
  - Add automated scanning to prevent committing secrets and to catch accidental log leaks.
  - Rotate secrets on a fixed schedule and build “rotate + verify” runbooks.

### 2.5 IAM and AWS credential model
- Current problem: Some AWS clients are configured using access key env vars (example: server/ai.ts), which can accidentally encourage long-lived static credentials.
- Why it matters: IRSA / role-based auth is the correct model on EKS; static keys increase blast radius.
- What to do:
  - Use IAM roles for service accounts and remove the requirement for AWS access keys inside pods.
  - Ensure each subsystem uses least-privilege IAM policies (S3 read/write specific prefixes; Bedrock invoke model only; etc.).

### 2.6 Multi-tenancy and org boundary enforcement
- Current problem: Org context is derived from memberships and an x-org-id header. Any inconsistency across routes increases risk.
- Why it matters: Cross-tenant data exposure is an existential risk for a SOC platform.
- What to do:
  - Enforce an “orgId required” middleware for all org-scoped routes.
  - Add automated tests for cross-tenant boundary violations across critical endpoints.
  - Add audit logs for org context switches and denied access attempts.

### 2.7 Webhook and outbound integration security
- Current problem: Webhooks use HMAC signature, but broader security posture for outbound calls (allowlists, SSRF prevention, retries, idempotency) must be formalized.
- Why it matters: Outbound webhooks are a common SSRF / data exfiltration vector.
- What to do:
  - Validate webhook URLs (scheme, hostname, deny internal ranges unless explicitly allowed).
  - Add outbound request policies (timeouts, retries, circuit breakers) and per-webhook rate limits.
  - Add webhook delivery logs with redaction.

### 2.8 Supply chain security
- Current problem: Dependency management is active but the pipeline does not enforce vulnerability thresholds or license policies.
- Why it matters: Enterprise security review will require a reproducible SBOM story and an upgrade cadence.
- What to do:
  - Add continuous dependency vulnerability scanning with a policy.
  - Add license scanning and a process for exceptions.

---

## 3) Architecture

### 3.1 Split the monolithic routes file
- Current problem: server/routes.ts is very large and contains many unrelated domains (auth, alerts, incidents, connectors, AI, compliance, admin, etc.).
- Why it matters: Large single files slow iteration, cause merge conflicts, and make ownership unclear.
- What to do:
  - Decompose routes into domain modules (alerts, incidents, connectors, ai, compliance, admin, operations).
  - Implement a consistent routing composition pattern with shared middleware.

### 3.2 Enforce layered boundaries (routes -> service -> storage)
- Current problem: Some route handlers may mix concerns (validation, business logic, storage, integration calls).
- Why it matters: Tight coupling blocks future extraction of services and makes correctness and testing harder.
- What to do:
  - Introduce service layer modules per domain.
  - Keep storage as persistence-only; keep routes as HTTP-only.

### 3.3 Domain event model standardization
- Current problem: There is an outbox processor and event patterns, but event taxonomy and versioning are not fully formalized.
- Why it matters: Events become an integration contract; breaking changes must be managed.
- What to do:
  - Define an event catalog (names, payload shape contracts, versioning strategy, deprecation policy).
  - Ensure every mutation emits a domain event consistently and idempotently.

### 3.4 Connector framework abstraction
- Current problem: Connector logic is implemented in a single large connector engine with many provider-specific branches.
- Why it matters: Adding new connectors becomes risky; provider-specific bugs can impact others.
- What to do:
  - Create a connector plugin interface (auth, test, sync, cursor, normalize).
  - Make each connector its own module with isolated dependencies.

### 3.5 AI subsystem as a product platform
- Current problem: AI integrations (Bedrock/SageMaker) are embedded in application logic; prompt and schema contracts exist but could be more modular.
- Why it matters: AI features will expand quickly; you need consistent model governance and cost controls.
- What to do:
  - Centralize model invocation, budgeting, caching, and error handling.
  - Add a prompt registry with versioning and auditability.

---

## 4) Scalability

### 4.1 Horizontal scaling readiness
- Current problem: Some state is per-process (in-memory caches, SSE clients, job dedup map).
- Why it matters: Horizontal scaling is essential for enterprise loads; per-process state leads to inconsistencies.
- What to do:
  - Identify and eliminate non-essential in-memory state or move it to shared stores.
  - Ensure statelessness for API pods (except short-lived in-memory optimizations).

### 4.2 Data lifecycle management
- Current problem: Alerts and telemetry will grow rapidly; retention and archiving exist conceptually but need full lifecycle governance.
- Why it matters: Storage cost and query performance will degrade; compliance requires controlled retention.
- What to do:
  - Implement tiered retention policies per data type and plan.
  - Add cold storage (S3) export and rehydration paths.
  - Add deletion workflows that are tenant-safe and auditable.

### 4.3 Large tenant isolation
- Current problem: Shared RDS for all orgs is simplest, but enterprise “noisy neighbor” scenarios are expected.
- Why it matters: Large customers require predictable performance and sometimes dedicated storage.
- What to do:
  - Add plan-driven isolation options: dedicated RDS instance, dedicated schema, or dedicated cluster.
  - Add throttling and quotas (ingestion rate, AI tokens, connector sync frequency) with enforcement.

---

## 5) Developer Experience (DX)

### 5.1 Dev environment parity and reproducibility
- Current problem: Local dev vs AWS dev parity depends on environment variables and ad-hoc configuration.
- Why it matters: New engineers need quick onboarding; reproducibility is key for incident debugging.
- What to do:
  - Provide a single documented way to start the stack locally (DB, migrations, seed, mock integrations).
  - Add “dev checks” scripts: formatting, linting, typecheck, unit tests, integration tests.

### 5.2 CI signal quality
- Current problem: CI builds Docker image on PR, deploys on main; deeper test suites are limited.
- Why it matters: CI should prevent regressions and provide confidence for rapid shipping.
- What to do:
  - Add unit test and integration test stages to PR workflows.
  - Add static analysis checks (security scanning, dependency scanning, secret scanning).

### 5.3 Tooling consistency
- Current problem: There is TypeScript strictness and build scripts, but missing standard lint/format workflows.
- Why it matters: Consistent style reduces review overhead and defect rate.
- What to do:
  - Add linting and formatting (ESLint + Prettier or equivalent) with CI enforcement.
  - Add pre-commit hooks for fast feedback.

---

## 6) Testing

### 6.1 Unit tests for core business logic
- Current problem: There are no conventional test files discovered by common patterns.
- Why it matters: High-change areas (correlation scoring, normalization, RBAC) need regression safety.
- What to do:
  - Add unit test coverage for correlation-engine scoring, predictive-engine analytics, normalizer mappings, and RBAC permission checks.

### 6.2 Integration/contract tests for connectors and webhooks
- Current problem: Integration testing exists conceptually but needs comprehensive, deterministic harnesses.
- Why it matters: Connectors break frequently due to provider API changes; contract tests catch drift early.
- What to do:
  - Build provider-mocked tests using captured fixtures and validated normalization outputs.
  - Add replayable webhook delivery tests (signature correctness, retry behavior).

### 6.3 End-to-end UI tests for workflows
- Current problem: Complex SOC workflows (triage, escalation, playbook execution) likely lack E2E coverage.
- Why it matters: UI regressions are costly and reduce analyst trust.
- What to do:
  - Add E2E tests for login, org selection, alert triage, incident creation, playbook execution, and connector setup.

---

## 7) UI/UX

### 7.1 Consistent loading, empty, and error states
- Current problem: Loading skeletons and empty states exist, but consistency across all pages and workflows is an ongoing need.
- Why it matters: Analysts interpret missing UI states as “broken product”.
- What to do:
  - Ensure every data-driven panel has: loading skeleton, empty state with next best action, and error recovery action.

### 7.2 Workflow-first navigation
- Current problem: Navigation is feature-rich but can still overwhelm new users without workflow guidance.
- Why it matters: Enterprise adoption depends on fast time-to-value.
- What to do:
  - Add role-based default landing pages.
  - Add guided flows for first connector, first ingestion, first incident, first playbook.

### 7.3 Accessibility as a continuous standard
- Current problem: Accessibility improvements exist, but coverage should be systematic.
- Why it matters: Enterprise procurement can require WCAG compliance.
- What to do:
  - Add automated a11y testing in CI.
  - Audit focus order, semantic landmarks, and contrast in all major pages.

### 7.4 Information architecture for high-cardinality lists
- Current problem: Alerts/incidents lists can become dense.
- Why it matters: Analysts need speed and clarity.
- What to do:
  - Add advanced filtering UX (saved filters, filter chips, query builder).
  - Add bulk operations and keyboard-driven triage consistently.

---

## 8) Features

### 8.1 Enterprise-grade org and identity lifecycle
- Current problem: Org membership auto-provisioning exists, but enterprise onboarding requires richer workflows.
- Why it matters: Enterprises need controlled invitations, approvals, SSO enforcement, and auditability.
- What to do:
  - Add invitation flows, domain verification, SCIM provisioning, and SSO enforcement options per org.
  - Add policies: MFA required, device/session policies, IP allowlists.

### 8.2 Incident response lifecycle completeness
- Current problem: Incident model exists with workflow states, but enterprise IR requires evidence, approvals, and postmortems.
- Why it matters: SOC operations require traceability.
- What to do:
  - Add evidence timelines, immutable audit trails, approvals for response actions, and post-incident review workflows.

### 8.3 Automation and playbooks as a governed system
- Current problem: Playbook execution exists; governance and safe rollbacks need continuous enhancement.
- Why it matters: Automation without guardrails is dangerous.
- What to do:
  - Add approval gates, simulation mode, blast radius previews, and guaranteed rollback semantics.

### 8.4 Reporting and compliance as first-class products
- Current problem: Report scheduler and compliance pages exist; enterprise requires template governance and evidence management.
- Why it matters: Compliance is a major buyer driver.
- What to do:
  - Add report template versioning, evidence attachment workflows (S3-backed), and compliance control mapping helpers.

---

## 9) API Design

### 9.1 Versioning and deprecation policy
- Current problem: Coexistence of /api and /api/v1 endpoints with mixed response shapes.
- Why it matters: External customers need stable contracts.
- What to do:
  - Publish a version policy (v1 stability guarantees, v2 path for breaking changes).
  - Add explicit deprecation headers and a migration guide for legacy endpoints.

### 9.2 Pagination/filter/sort correctness contract
- Current problem: Pagination exists but needs uniform semantics across domains.
- Why it matters: Inconsistent pagination breaks UIs and integrations.
- What to do:
  - Standardize offset/limit vs cursor pagination rules.
  - Standardize filter operators and search behavior.

### 9.3 OpenAPI completeness
- Current problem: OpenAPI exists but must remain complete and reflect all routes.
- Why it matters: Typed clients, SDKs, and integrations depend on it.
- What to do:
  - Ensure OpenAPI spec includes every endpoint, every error response, and authentication requirements.
  - Add CI validation that spec is regenerated and consistent.

---

## 10) Database

### 10.1 Pool sizing and connection management
- Current problem: Pool is created with default settings.
- Why it matters: Under load, default pool behavior can saturate DB connections or cause request latency.
- What to do:
  - Configure pool max/min, idle timeouts, statement timeouts, and application_name.
  - Add connection health metrics and alerts.

### 10.2 Migration discipline
- Current problem: Drizzle push is used; long-term you need a formal migration history for enterprise change control.
- Why it matters: Enterprises require repeatable, audited schema evolution.
- What to do:
  - Move toward migration files and a migration pipeline.
  - Add safe rollback plans for schema changes.

### 10.3 Large table strategies
- Current problem: Alerts and telemetry tables will become huge.
- Why it matters: Performance and cost.
- What to do:
  - Add partitioning or sharding strategy (time-based partitions) for the largest tables.
  - Add archival tables and background archival jobs.

---

## 11) Observability

### 11.1 Metrics storage and retention
- Current problem: SLI metrics are flushed into storage; long-term retention and aggregation strategy is needed.
- Why it matters: Observability data itself can become high-cardinality.
- What to do:
  - Decide what belongs in PostgreSQL vs time-series systems.
  - Add rollups (minute/hour/day) and retention windows.

### 11.2 Tracing and correlation
- Current problem: Request logs exist, but no distributed tracing across jobs/outbox/connector calls.
- Why it matters: Root-cause analysis requires end-to-end traces.
- What to do:
  - Add OpenTelemetry instrumentation for HTTP, database, and outbound calls.
  - Propagate correlation IDs through job payloads and outbox events.

### 11.3 Alerting maturity
- Current problem: SLO evaluation exists and logs breaches; external alert dispatch is limited.
- Why it matters: Production operations require paging and incident creation.
- What to do:
  - Integrate SLO breaches with notification channels (Slack, email, PagerDuty) and create incidents automatically when appropriate.

---

## 12) Dependency Management

### 12.1 Upgrade cadence and policy
- Current problem: Dependencies are modern but need a policy for continuous upgrades.
- Why it matters: Security vulnerabilities and ecosystem breaking changes.
- What to do:
  - Establish upgrade cadence (weekly minor, monthly patch, quarterly major review).
  - Automate updates with CI gating.

### 12.2 Reduce bloat and isolate optional deps
- Current problem: Many AWS clients and UI libraries are present; some may not be used in all deployments.
- Why it matters: Bundle size and attack surface.
- What to do:
  - Audit actual imports and remove unused dependencies.
  - Split optional integrations into separate packages or dynamic imports.

---

## 13) Internationalization & Localization (i18n/l10n)

### 13.1 UI text externalization
- Current problem: Strings are embedded in UI components; date formatting is often hard-coded to en-US.
- Why it matters: Enterprise customers often require localization.
- What to do:
  - Adopt an i18n framework and externalize all user-facing strings.
  - Standardize date/number formatting with locale-aware utilities.

### 13.2 Time zones and compliance reporting
- Current problem: Some analytics and trend labels are generated with implicit time zone assumptions.
- Why it matters: SOC reporting is time-sensitive and must be accurate per tenant.
- What to do:
  - Store and display times consistently with tenant-configurable time zones.
  - Ensure reporting and SLA calculations are time zone safe.

---

## 14) Deployment & Infrastructure

### 14.1 Kubernetes manifests hardening
- Current problem: Deployments exist for staging/uat/production; continuous hardening is needed.
- Why it matters: Security posture and reliability.
- What to do:
  - Add pod security contexts, read-only root filesystem, drop capabilities, non-root user, and resource requests/limits.
  - Add network policies to restrict egress/ingress.

### 14.2 Readiness/liveness and graceful shutdown
- Current problem: Health checks exist but may not cover readiness vs liveness semantics.
- Why it matters: Prevents traffic to unhealthy pods and ensures safe rollouts.
- What to do:
  - Implement readiness probes that verify DB connectivity and critical dependencies.
  - Implement graceful shutdown hooks for in-flight requests, job processing, and SSE clients.

### 14.3 Rollout safety and progressive delivery
- Current problem: Argo Rollouts is used; further guardrails can reduce risk.
- Why it matters: Enterprise environments require predictable release processes.
- What to do:
  - Add automated analysis steps during canary (error rates, latency, key business metrics).
  - Add fast rollback triggers and runbooks.

### 14.4 Backup/restore and DR drills
- Current problem: Backup/restore strategy is documented; operationalization needs continuous drills.
- Why it matters: DR readiness is a requirement.
- What to do:
  - Automate periodic restore tests to a non-prod environment.
  - Track RPO/RTO in dashboards and treat regressions as incidents.

---

## Appendix A: High-priority “next 30 days” execution plan

1. Security baseline completion (CSRF, secure session secret requirements, strict validation everywhere, SSRF protections for webhooks)
2. Architecture refactor of server/routes.ts into domain modules with consistent envelopes and error codes
3. Testing foundation: unit tests for correlation/normalization/RBAC, plus connector contract tests
4. Distributed state fixes: remove default org behavior; move dedup and cache strategy to shared stores
5. Observability upgrade: structured logs + requestId correlation + OpenTelemetry baseline

## Appendix B: High-risk areas to treat as “never regress”

- Multi-tenant org boundary enforcement (orgId derivation, x-org-id handling, storage queries)
- Connector credential handling and redaction
- Webhook delivery (SSRF prevention, signature correctness, retries)
- AI invocation safety (cost control, rate limiting, data exposure)
- Incident/alert mutation handlers emitting correct outbox events and invalidating caches
