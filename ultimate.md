# SecureNexus: Next-Generation Improvement Roadmap (v2)

This document replaces the original ultimate.md. Every item from v1 has been implemented and merged. This is a fresh, codebase-driven catalog of the next wave of improvements across SecureNexus, derived from a deep audit of the current 46K+ lines of server code, 31 frontend pages, 24 connector plugins, and full CI/CD + K8s infrastructure.

For every item below, the structure is:

- Current state (what exists today)
- Gap (what is missing or weak)
- What to do (exactly what should be implemented or changed)

Scope assumptions (based on current repo + infra conventions):

- Backend: Node.js + Express, Drizzle ORM, PostgreSQL on RDS, ~46K server LOC
- Frontend: React + Vite + Tailwind + Radix, 31 pages
- Deploy: EKS (staging/uat/production), Argo Rollouts, GitHub Actions, AWS Secrets Manager, S3
- Platform: Multi-tenant org model + RBAC + 24 connector plugins + AI (Bedrock) + job queue + outbox

---

## 0) Type Safety and Code Hygiene

### 0.1 Eliminate `as any` epidemic across route handlers

- Current state: The server codebase contains 601 `as any` type casts, with the heaviest concentrations in route handlers (playbooks: 67, incidents: 43, integrations: 36, enterprise-org: 36, investigations: 34, threat-intel: 33, compliance: 28). The client has an additional 29 `as any` casts.
- Gap: `as any` defeats TypeScript's type system entirely. Each cast is a potential runtime crash that the compiler cannot catch. Route handlers are the most dangerous location because they process untrusted user input.
- What to do:
  - Replace every `as any` with proper typed interfaces derived from the Drizzle schema or Zod-validated request shapes.
  - Prioritize route handlers first (they process external input), then service modules, then internal utilities.
  - Add an ESLint rule (`@typescript-eslint/no-explicit-any`) set to error, not warn, and enforce in CI.
  - Target: zero `as any` casts remaining across the entire codebase.

### 0.2 Replace `error: any` catch blocks with narrowed `unknown`

- Current state: Route handlers in admin.ts (22 occurrences), operations.ts (20), report-governance.ts (9), lifecycle.ts (8), connectors.ts (8) and many others use loose `catch (err)` or `catch (error: any)` patterns.
- Gap: Catching `any` and accessing `.message` directly can crash on non-Error objects. This also prevents proper error classification and structured logging.
- What to do:
  - Replace all `catch (error: any)` with `catch (error: unknown)` and use `error instanceof Error ? error.message : String(error)` consistently.
  - Create a shared `toErrorMessage(error: unknown): string` utility to centralize this pattern.
  - Audit all catch blocks to ensure errors are classified (operational vs programmer) and surfaced appropriately.

### 0.3 Replace `Math.random()` with cryptographically secure alternatives where needed

- Current state: `Math.random()` is used in 15+ server files for generating IDs (connector event IDs, CSPM scan IDs, DR drill durations, endpoint telemetry), shuffling arrays, and simulating probabilities.
- Gap: `Math.random()` is not cryptographically secure and produces predictable output. When used for event IDs or identifiers in a security platform, this creates collision risk and potential ID prediction vectors.
- What to do:
  - Replace all ID generation uses with `crypto.randomUUID()` or `crypto.randomBytes()`.
  - For simulation/probability uses (CSPM scanner, endpoint telemetry, DR drills), document that these are intentionally non-cryptographic.
  - Add a lint rule to flag new `Math.random()` usage in server code and require explicit justification.

### 0.4 Centralize module-level mutable state inventory

- Current state: At least 10 server modules maintain module-level `Map` instances for state (osint-feeds feedCache, slo-alerting lastBreachNotifications and recentIncidentKeys, tenant-throttle orgQuotaOverrides and orgUsage, connector-plugin registry, canary-analysis lastTriggerFired, and others).
- Gap: Module-level mutable state does not survive pod restarts, is not shared across replicas in multi-pod EKS deployments, and creates inconsistent behavior under horizontal scaling.
- What to do:
  - Inventory every module-level Map/Set/object that holds runtime state.
  - Classify each as: (a) acceptable per-instance cache with TTL, (b) must be moved to shared store (Redis or DB), or (c) can be eliminated entirely.
  - For category (a), add TTL-based eviction and metrics. For category (b), implement a shared state abstraction backed by Redis or PostgreSQL advisory locks.

---

## 1) Storage Layer Maturity

### 1.1 Decompose the monolithic storage module

- Current state: `server/storage.ts` is 4,926 lines containing every database operation for every domain (alerts, incidents, connectors, orgs, compliance, AI, telemetry, DR drills, etc.) in a single class.
- Gap: A single 5K-line storage file is a merge conflict magnet, makes domain ownership unclear, and prevents independent testing of storage operations per domain.
- What to do:
  - Split storage.ts into domain-specific storage modules (alert-storage.ts, incident-storage.ts, connector-storage.ts, org-storage.ts, compliance-storage.ts, etc.).
  - Each module exports typed functions that operate on a shared database instance.
  - Keep a thin storage barrel file (storage/index.ts) for backward compatibility during migration.
  - Add per-domain storage unit tests with in-memory or test database.

### 1.2 Schema file decomposition

- Current state: `shared/schema.ts` is 4,505 lines containing all Drizzle table definitions, insert schemas, and type exports in a single file.
- Gap: Same merge conflict and ownership issues as storage.ts. Changes to one domain's schema require touching the same massive file.
- What to do:
  - Split schema.ts into domain-specific schema files (schema/alerts.ts, schema/incidents.ts, schema/orgs.ts, etc.).
  - Re-export from a barrel file (shared/schema/index.ts) to avoid breaking imports.
  - Each schema file should also export its Zod insert schemas and TypeScript types.

### 1.3 Database transaction boundaries

- Current state: Most storage operations are individual queries without explicit transaction boundaries.
- Gap: Multi-step mutations (e.g., create incident + emit outbox event + update audit log) can partially succeed, leaving the database in an inconsistent state.
- What to do:
  - Identify all multi-step mutation flows and wrap them in explicit database transactions.
  - Create a `withTransaction` helper that handles commit/rollback and integrates with structured logging.
  - Ensure outbox events are always written in the same transaction as the mutation they represent.

### 1.4 Query builder type safety

- Current state: Route handlers frequently cast query results with `as any` to work around Drizzle type inference gaps.
- Gap: The 457 `as any` casts in route handlers are largely caused by untyped or loosely typed storage return values.
- What to do:
  - Add explicit return types to every storage function using Drizzle's `InferSelectModel` and `InferInsertModel` types.
  - Where joins or aggregates are used, define explicit result interfaces rather than casting.
  - This will naturally eliminate most `as any` casts in route handlers.

---

## 2) API Contract Hardening

### 2.1 Request validation coverage for all endpoints

- Current state: Some endpoints use Zod validation, but many route handlers extract `req.body`, `req.query`, and `req.params` without schema validation, relying on runtime assumptions.
- Gap: Unvalidated input is the root cause of multiple Devin Review findings across PRs (TypeErrors from malformed payloads, cross-org bypasses from unscoped parameters).
- What to do:
  - Create Zod schemas for every route handler's input (body, query, params).
  - Create a shared `validateRequest` middleware that validates and types the request in one step.
  - Ensure validated types flow through to storage calls, eliminating the need for `as any` casts.

### 2.2 Response type contracts

- Current state: API responses are built inline in route handlers with ad-hoc object shapes.
- Gap: Frontend developers and external integrators cannot rely on stable response shapes. Changes to response shapes are not caught at compile time.
- What to do:
  - Define explicit response interfaces per endpoint.
  - Add response serialization that strips internal fields and enforces the contract.
  - Consider adding response validation in development/staging mode to catch contract violations early.

### 2.3 Rate limiting per tenant and per endpoint

- Current state: Global rate limiting exists, but per-tenant and per-endpoint rate limiting is not granular.
- Gap: A single noisy tenant or a burst on a specific endpoint can degrade the entire platform.
- What to do:
  - Implement tiered rate limits: global, per-tenant, per-endpoint, and per-user.
  - Store rate limit state in Redis for cross-pod consistency.
  - Return standard `Retry-After` headers and `429` responses with clear error messages.
  - Add rate limit metrics and alerting for quota exhaustion.

### 2.4 API documentation completeness

- Current state: OpenAPI spec exists and CI validates it, but endpoint coverage may have drifted as new routes were added across 24+ route files.
- Gap: Incomplete API documentation blocks SDK generation and enterprise integration onboarding.
- What to do:
  - Audit every route file and ensure every endpoint is documented in the OpenAPI spec.
  - Add CI validation that compares registered Express routes against OpenAPI paths and fails on drift.
  - Add example request/response bodies for every endpoint.

---

## 3) Frontend Polish and Production Readiness

### 3.1 Interactive feedback on all actionable elements

- Current state: Buttons and interactive elements exist across 31 pages, but hover/active/focus states are inconsistent.
- Gap: Without clear interactive feedback, users cannot confirm their clicks registered, making the app feel unresponsive.
- What to do:
  - Audit all Button, Card, and interactive elements across all 31 pages.
  - Ensure every clickable element has distinct hover (color/shadow change), active (pressed state), and focus (ring/outline) styles.
  - Standardize using Tailwind utility classes or a shared interactive component wrapper.

### 3.2 Loading skeletons and empty states consistency

- Current state: Loading skeletons and empty states exist on some pages but are not universal.
- Gap: Pages that show blank space during loading or "0" values when data is absent feel broken to analysts during live SOC operations.
- What to do:
  - Audit every data-driven component and ensure it has three states: loading skeleton, populated, and empty (with illustration and next-best-action CTA).
  - Create reusable `<DataState>` wrapper component that handles all three states consistently.
  - Prioritize dashboard, alerts, incidents, and connectors pages first.

### 3.3 Form validation with real-time feedback

- Current state: Form submissions exist across settings, connectors, playbooks, and other pages, but validation feedback varies.
- Gap: Users submit invalid data and only learn about errors after a server round-trip, causing frustration.
- What to do:
  - Implement client-side Zod validation (reusing server schemas where possible) with real-time field-level error messages.
  - Show validation errors inline as users type (debounced), not just on submit.
  - Add visual indicators (red borders, error text) immediately on invalid fields.

### 3.4 Search UX completeness

- Current state: Search functionality exists in navigation (command palette) and some list pages.
- Gap: Search bars that return no results without feedback feel broken. Users need "No results found" states and search suggestions.
- What to do:
  - Ensure every search input shows: loading state during search, "No results found" with suggestions when empty, and result counts.
  - Add recent searches and saved search functionality for analysts who repeatedly search the same patterns.

### 3.5 Responsive layout for tablet breakpoints

- Current state: The application is designed for desktop-first usage with a collapsible sidebar.
- Gap: Enterprise users increasingly use tablets for SOC monitoring. Tablet breakpoints (768px-1024px) may cause sidebar/content overlap.
- What to do:
  - Test and fix all 31 pages at 768px, 1024px, and 1280px breakpoints.
  - Ensure sidebar auto-collapses at tablet widths.
  - Ensure data tables and charts reflow gracefully without horizontal scrolling.

### 3.6 Breadcrumb navigation for deep flows

- Current state: Navigation uses sidebar and command palette, but deep flows (alert detail, incident detail, investigation, playbook execution) lack breadcrumb trails.
- Gap: Analysts lose context when navigating deep into detail views and have no clear path back.
- What to do:
  - Add breadcrumb components for all detail/nested pages (alert detail, incident detail, entity graph, investigation, playbook execution, connector config).
  - Breadcrumbs should reflect the navigation hierarchy and support browser back/forward.

### 3.7 Z-index layering audit

- Current state: Multiple overlay components exist (profile menus, command palette, modals, dropdowns, toast notifications).
- Gap: Overlapping z-index values can cause dropdowns to clip behind content or modals to appear behind other overlays.
- What to do:
  - Define a z-index scale (base: 0, dropdown: 50, modal: 100, toast: 150, command-palette: 200) and enforce it via CSS custom properties.
  - Audit all overlay components for correct stacking behavior.

### 3.8 Accessibility audit and WCAG 2.1 compliance

- Current state: ARIA labels and semantic HTML improvements have been made. CI includes an accessibility audit.
- Gap: Systematic contrast checking, focus order verification, and screen reader testing across all 31 pages has not been completed.
- What to do:
  - Run axe-core or Lighthouse accessibility audit on every page and fix all critical/serious violations.
  - Ensure text contrast meets WCAG 2.1 AA standard (4.5:1 for normal text, 3:1 for large text).
  - Audit and fix focus order for all interactive flows (triage, escalation, playbook execution).
  - Add keyboard navigation testing to E2E test suite.

### 3.9 Meta tags and SEO for landing page

- Current state: The landing page exists with marketing content, but meta tags may still use default Vite framework values.
- Gap: Poor meta tags hurt discoverability and look unprofessional when links are shared (Slack, email previews).
- What to do:
  - Set proper `<title>`, `<meta description>`, and Open Graph tags for the landing page and key public routes.
  - Add favicon and apple-touch-icon that match the brand.

### 3.10 Console error cleanup

- Current state: The application may have 404 errors for missing resources (map files, icons, fonts) visible in browser console.
- Gap: Console errors visible to technical evaluators during demos create an impression of poor quality.
- What to do:
  - Audit browser console on every page for 404s, deprecation warnings, and uncaught errors.
  - Fix all missing resource references.
  - Add a CI check that captures console errors during E2E tests and fails on unexpected errors.

### 3.11 Consistent iconography and typography

- Current state: Icons are used across all pages from Lucide React, but mixing filled vs outlined styles may occur.
- Gap: Inconsistent icon styles and typography hierarchy between navigation and content areas reduce visual polish.
- What to do:
  - Standardize on one icon style (outlined recommended for Lucide) across all pages.
  - Define and enforce a typography scale (headings, body, caption, mono) via Tailwind config.
  - Audit card padding, spacing, and border radius for consistency across all pages.

---

## 4) Testing Depth

### 4.1 Storage layer unit tests

- Current state: 7 test files exist covering correlation-engine, normalizer, RBAC, org-boundary, predictive-engine, connectors integration, and webhooks integration.
- Gap: The 4,926-line storage module has zero dedicated unit tests. Storage bugs are only caught by integration tests or in production.
- What to do:
  - Add unit tests for every critical storage function using a test database or mocked Drizzle instance.
  - Prioritize: alert CRUD, incident lifecycle, connector sync state, org membership, audit log writes.
  - Target: 80% statement coverage for storage module.

### 4.2 Route handler integration tests

- Current state: No integration tests for HTTP route handlers (request in, response out).
- Gap: Route handlers contain validation, authorization, business logic, and error handling. Without integration tests, regressions in any layer are only caught in production.
- What to do:
  - Add supertest-based integration tests for critical routes: auth, alerts CRUD, incidents CRUD, connectors, playbook execution, DR drills.
  - Test happy paths, validation errors, authorization failures, and edge cases.
  - Run these in CI on every PR.

### 4.3 Frontend component tests

- Current state: No frontend component tests exist.
- Gap: UI regressions (broken layouts, missing states, incorrect data display) are only caught by manual review or E2E tests.
- What to do:
  - Add React Testing Library tests for critical components: AlertsList, IncidentDetail, Dashboard widgets, ConnectorConfig forms, PlaybookEditor.
  - Test loading states, empty states, error states, and user interactions.
  - Add Storybook for design system components if the team grows.

### 4.4 Contract tests for all 24 connector plugins

- Current state: Connector integration tests exist for some connectors, but not all 24 plugins have dedicated contract tests.
- Gap: Connector plugins normalize external provider data. Without per-connector contract tests, provider API changes cause silent data corruption.
- What to do:
  - Add snapshot-based contract tests for every connector plugin using captured provider response fixtures.
  - Each test should verify: authentication flow, data fetch, normalization output shape, and error handling.
  - Add a CI matrix that runs all 24 connector tests in parallel.

### 4.5 Performance regression tests

- Current state: No automated performance benchmarks exist.
- Gap: Performance regressions (slow queries, large payloads, memory leaks) are only detected in production.
- What to do:
  - Add benchmark tests for top-10 most-called endpoints measuring p50/p95/p99 latency.
  - Add memory usage checks for long-running processes (SSE connections, job workers).
  - Run benchmarks in CI and alert on regressions beyond threshold.

---

## 5) Security Hardening (Next Wave)

### 5.1 Content Security Policy tightening

- Current state: CSP headers are set but may be permissive to avoid breaking functionality.
- Gap: Overly permissive CSP allows XSS vectors. Enterprise security reviews flag permissive CSP as a finding.
- What to do:
  - Audit current CSP directives and tighten to allow only known origins.
  - Add nonce-based script loading for inline scripts.
  - Test CSP in report-only mode first, then enforce after verifying no breakage.

### 5.2 Dependency vulnerability SLA

- Current state: Dependabot and GitGuardian scan dependencies. No formal SLA for vulnerability remediation.
- Gap: Enterprise customers require documented vulnerability response times (critical: 24h, high: 7d, medium: 30d).
- What to do:
  - Define and document vulnerability remediation SLAs by severity.
  - Add automated PR creation for security updates with priority labels.
  - Add a dashboard showing current vulnerability count and age.

### 5.3 Secrets rotation automation

- Current state: Secret rotation infrastructure exists (server/secret-rotation.ts), but automated rotation schedules and verification are not fully operational.
- Gap: Static secrets that are never rotated are a ticking time bomb. Enterprise audits check rotation evidence.
- What to do:
  - Implement automated rotation for: database credentials (90-day cycle), session secrets (30-day cycle), API keys (quarterly).
  - Add rotation verification (can the app authenticate with the new secret?) before committing the rotation.
  - Add rotation audit log and alerting for failed rotations.

### 5.4 Request signing for internal service calls

- Current state: Internal service calls (job queue, outbox processor, scheduler) use the same Express server and shared storage instance.
- Gap: If the architecture evolves to microservices, internal calls need authentication. Even now, spoofed internal requests could bypass authorization.
- What to do:
  - Add HMAC-based request signing for internal service calls.
  - Verify signatures on receiving endpoints.
  - This also prepares for future microservice extraction.

### 5.5 Audit log immutability

- Current state: Audit logs are written to PostgreSQL and are mutable (can be updated or deleted by anyone with database access).
- Gap: Enterprise compliance frameworks (SOC 2, ISO 27001) require immutable audit trails.
- What to do:
  - Add append-only audit log table with no UPDATE or DELETE permissions for the application role.
  - Implement periodic export of audit logs to S3 with write-once (Object Lock) policy.
  - Add hash chain verification (each log entry includes hash of previous entry) for tamper detection.

---

## 6) Observability and Operations

### 6.1 Structured error classification

- Current state: Errors are caught and logged, but there is no systematic classification of errors (operational vs programmer, transient vs permanent, user-facing vs internal).
- Gap: Without classification, on-call engineers cannot distinguish between "retry will fix it" and "code is broken" from logs alone.
- What to do:
  - Define error categories: OperationalError (retryable), ValidationError (user input), AuthorizationError (access denied), InternalError (programmer bug), UpstreamError (external dependency).
  - Create typed error classes for each category with required metadata (isRetryable, httpStatus, errorCode).
  - Ensure all catch blocks classify errors before logging or returning.

### 6.2 Health check depth

- Current state: Readiness and liveness probes exist. Readiness checks DB connectivity and server readiness flag.
- Gap: Health checks do not verify dependent services (S3, Secrets Manager, Bedrock) or critical background processes (job worker, outbox processor, DR scheduler).
- What to do:
  - Add deep health check endpoint that verifies: DB connectivity, S3 access, Secrets Manager access, job worker status, outbox processor status, and SSE client count.
  - Keep liveness probe shallow (process is alive). Make readiness probe medium (DB connected). Add a separate `/api/ops/health/deep` for operational dashboards.

### 6.3 Alert fatigue reduction for SLO breaches

- Current state: SLO evaluation creates incidents and dispatches notifications for breaches.
- Gap: Repeated SLO breaches for the same target can create alert storms if cooldown/dedup logic is insufficient.
- What to do:
  - Implement sliding-window dedup for SLO breach notifications (only alert once per target per window).
  - Add breach severity escalation (warn after 1 breach, page after 3 consecutive breaches).
  - Add "SLO health" summary notification (daily digest of all SLO statuses) as an alternative to per-breach alerts.

### 6.4 Distributed tracing completeness

- Current state: OpenTelemetry tracing module exists (server/tracing.ts). Correlation IDs propagate through requests.
- Gap: Tracing may not cover all code paths: job execution, outbox processing, connector sync, SSE broadcast, and DR drill execution.
- What to do:
  - Add trace spans for: job claim/execute/complete, outbox event process, connector sync cycle, SSE event broadcast, DR drill execution.
  - Ensure parent-child span relationships are correct across async boundaries.
  - Add trace sampling configuration to control cost in production.

---

## 7) Infrastructure and Deployment

### 7.1 Blue-green database migration strategy

- Current state: `npm run db:push` is used for schema changes, which applies changes directly without rollback capability.
- Gap: Failed migrations in production can cause downtime with no rollback path. Enterprise change management requires reversible migrations.
- What to do:
  - Migrate from `db:push` to versioned migration files (Drizzle Kit generates them).
  - Add pre-deployment migration validation (dry-run against a clone of production schema).
  - Add rollback migration for every forward migration.
  - Add migration status to health checks.

### 7.2 Pod disruption budgets

- Current state: EKS deployments exist for staging/uat/production with Argo Rollouts.
- Gap: Without PodDisruptionBudgets, cluster maintenance or node scaling can take down all replicas simultaneously.
- What to do:
  - Add PodDisruptionBudgets for production deployments (minAvailable: 1 or maxUnavailable: 1).
  - Add to staging and UAT as well for parity.

### 7.3 Horizontal Pod Autoscaler tuning

- Current state: Resource requests and limits are set in K8s manifests.
- Gap: Without HPA, the deployment runs at fixed replica count regardless of load, either wasting resources or becoming overloaded.
- What to do:
  - Add HPA based on CPU and custom metrics (request rate, queue depth).
  - Set appropriate min/max replicas per environment (staging: 1-2, production: 2-6).
  - Add scale-down stabilization window to prevent flapping.

### 7.4 Egress network policy tightening

- Current state: Network policies exist in K8s manifests.
- Gap: Egress policies may be too permissive, allowing pods to reach arbitrary internet destinations.
- What to do:
  - Restrict egress to known destinations: RDS endpoint, S3 endpoints, Secrets Manager endpoint, connector provider IPs/domains.
  - Use AWS PrivateLink for AWS service access where possible.
  - Add egress monitoring and alerting for unexpected destinations.

### 7.5 Disaster recovery RTO improvement

- Current state: DR drill scheduler exists with automated restore tests and RPO/RTO tracking.
- Gap: RTO is bounded by RDS snapshot restore time, which can be slow for large databases.
- What to do:
  - Implement read replica promotion as a faster DR strategy (RTO less than 5 minutes vs 30+ minutes for snapshot restore).
  - Add automated failover runbooks that promote read replicas.
  - Add cross-region read replica for geographic redundancy.

---

## 8) AI Platform Maturity

### 8.1 Prompt versioning and A/B testing

- Current state: Prompt registry exists (server/ai/prompt-registry.ts) with versioning.
- Gap: No mechanism to A/B test prompts in production or measure prompt quality metrics.
- What to do:
  - Add prompt variant support with traffic splitting (e.g., 90% stable, 10% candidate).
  - Add quality metrics per prompt variant (user feedback, accuracy, response time).
  - Add automatic rollback if a prompt variant degrades quality below threshold.

### 8.2 AI response caching

- Current state: AI model calls go through the model gateway with budget controls.
- Gap: Identical or near-identical queries produce redundant model invocations, wasting cost.
- What to do:
  - Add semantic caching for AI responses (hash prompt + context, cache response with TTL).
  - Add cache hit rate metrics and cost savings tracking.
  - Ensure cache keys include org context to prevent cross-tenant data leakage.

### 8.3 AI model fallback chain

- Current state: AI integration uses AWS Bedrock.
- Gap: Single model provider dependency means AI features are fully down during Bedrock outages.
- What to do:
  - Add model fallback chain: primary model, fallback model (different Bedrock model), and graceful degradation (cached/templated responses).
  - Add circuit breaker for model calls with automatic fallback activation.
  - Add model health monitoring and alerting.

### 8.4 AI cost attribution per tenant

- Current state: AI budget controls exist at the platform level.
- Gap: Cannot attribute AI costs to individual tenants for usage-based billing or internal showback.
- What to do:
  - Add per-tenant AI token usage tracking (input tokens, output tokens, model, timestamp).
  - Add cost calculation based on model pricing and expose in usage-billing page.
  - Add per-tenant AI budget limits with enforcement.

---

## 9) Connector Ecosystem

### 9.1 Connector health monitoring dashboard

- Current state: 24 connector plugins exist with sync capabilities.
- Gap: No centralized view showing which connectors are healthy, which are failing, last sync time, and error rates.
- What to do:
  - Add connector health dashboard showing: last sync status, sync frequency, error count, data volume per connector.
  - Add automated alerting for connectors that have not synced within their expected interval.
  - Add connector-specific error classification (auth expired, rate limited, provider down, normalization error).

### 9.2 Connector credential lifecycle

- Current state: Connector credentials are stored and used for sync.
- Gap: No automated detection of expired or soon-to-expire credentials. Expired credentials cause silent sync failures.
- What to do:
  - Add credential expiry tracking per connector.
  - Add proactive alerts 7 days before credential expiry.
  - Add one-click credential rotation flow in the UI.
  - Add credential validation test before saving (test connectivity with provided credentials).

### 9.3 Connector data quality scoring

- Current state: Connectors normalize external data into a common schema.
- Gap: No visibility into normalization quality (missing fields, type mismatches, dropped records).
- What to do:
  - Add data quality scoring per connector sync: completeness (% of fields populated), accuracy (% of fields passing validation), freshness (time since last record).
  - Surface data quality scores in the connector health dashboard.
  - Alert on quality degradation (e.g., completeness drops below 80%).

### 9.4 Bulk connector management

- Current state: Connectors are managed individually.
- Gap: Enterprises with 20+ connectors need bulk operations (enable/disable all, bulk credential update, bulk test).
- What to do:
  - Add bulk select and bulk action support on the connectors page.
  - Add "test all connectors" one-click action.
  - Add connector groups/tags for organizational management.

---

## 10) Multi-Tenancy Depth

### 10.1 Tenant data export (right to data portability)

- Current state: Tenant data is stored in shared tables with orgId scoping.
- Gap: Enterprise customers and GDPR/CCPA require the ability to export all tenant data on request.
- What to do:
  - Add a tenant data export endpoint that generates a complete archive (JSON or CSV) of all data for an org.
  - Include: alerts, incidents, entities, audit logs, playbooks, connectors config (redacted credentials), reports, compliance evidence.
  - Add export job queue with progress tracking and download link.

### 10.2 Tenant data deletion (right to erasure)

- Current state: No systematic tenant data deletion workflow exists.
- Gap: GDPR Article 17 requires the ability to delete all tenant data on request.
- What to do:
  - Add a tenant data deletion workflow that removes all org-scoped data across all tables.
  - Add deletion verification (count records before and after).
  - Add deletion audit log (retained separately from deleted data).
  - Add soft-delete with retention period before hard deletion for accidental deletion recovery.

### 10.3 Tenant resource usage visibility

- Current state: Usage metering exists for plan limits.
- Gap: Tenants cannot see their own resource usage breakdown (storage, API calls, AI tokens, connector syncs) in a self-service dashboard.
- What to do:
  - Add per-tenant usage dashboard showing: storage used, API calls (by endpoint), AI tokens consumed, connector sync volume, active users.
  - Add usage trends (daily/weekly/monthly) with projections.
  - Add usage alerts when approaching plan limits.

---

## 11) Operational Workflows

### 11.1 Incident war room

- Current state: Incident detail page exists with evidence, audit trails, and response actions.
- Gap: During active incidents, analysts need a real-time collaborative view (live timeline, shared context, assigned actions).
- What to do:
  - Add incident war room page with: real-time event timeline (SSE-powered), assigned responder list, live status updates, shared investigation notes.
  - Add @mention support in incident notes for tagging responders.
  - Add incident status change notifications via SSE to all war room participants.

### 11.2 Playbook marketplace

- Current state: Playbook editor and execution exist with governance controls.
- Gap: Organizations start from scratch when building playbooks. No shared templates or community playbooks.
- What to do:
  - Add curated playbook template library (phishing response, ransomware containment, data breach notification, insider threat investigation).
  - Add "import from template" flow that creates a new playbook from a template with org-specific customization.
  - Add playbook sharing between organizations (opt-in, anonymized).

### 11.3 Investigation timeline visualization

- Current state: Investigation agent and entity graph exist.
- Gap: Complex investigations spanning multiple alerts, entities, and time ranges lack a visual timeline view.
- What to do:
  - Add investigation timeline component showing events, alerts, entity interactions, and analyst actions on a time axis.
  - Add zoom, filter by entity/source, and annotation capabilities.
  - Add timeline export for inclusion in incident reports.

---

## 12) Compliance and Reporting

### 12.1 Evidence chain of custody

- Current state: Compliance evidence management exists.
- Gap: Enterprise auditors require proof that evidence was not tampered with after collection (chain of custody).
- What to do:
  - Add cryptographic hashing of evidence at collection time.
  - Add hash verification on evidence retrieval.
  - Add chain of custody log showing who accessed/downloaded evidence and when.

### 12.2 Automated compliance gap analysis

- Current state: Compliance controls and frameworks are mapped.
- Gap: No automated analysis of which controls are met, partially met, or not met based on actual system configuration and data.
- What to do:
  - Add automated compliance gap analysis engine that evaluates current system state against framework requirements.
  - Generate gap reports with remediation recommendations.
  - Track compliance posture score over time.

### 12.3 Report scheduling with SLA tracking

- Current state: Report scheduler exists for periodic report generation.
- Gap: No visibility into whether scheduled reports were generated on time and whether recipients received them.
- What to do:
  - Add report generation SLA tracking (was the report generated within the scheduled window?).
  - Add delivery confirmation (email sent, downloaded, viewed).
  - Add alerting for failed or late report generations.

---

## 13) Performance Optimization (Next Wave)

### 13.1 Database connection pooling optimization

- Current state: Database pool exists with configured settings.
- Gap: Pool settings may not be optimized for the specific RDS instance size and workload pattern.
- What to do:
  - Profile connection usage patterns (peak concurrent connections, average query duration, connection idle time).
  - Tune pool size based on RDS max_connections, replica count, and workload characteristics.
  - Add connection pool metrics to observability dashboard.

### 13.2 Frontend bundle analysis and optimization

- Current state: Bundle size check exists in CI.
- Gap: No detailed analysis of what contributes to bundle size and which chunks can be optimized.
- What to do:
  - Add webpack-bundle-analyzer (or vite-bundle-visualizer) output to CI artifacts.
  - Identify top-5 largest chunks and evaluate lazy loading opportunities.
  - Add tree-shaking verification for large dependencies (Radix, Recharts, Lucide icons).
  - Set per-chunk size budgets in CI.

### 13.3 API response compression

- Current state: Express serves responses, but compression may not be optimized.
- Gap: Large API responses (alert lists, entity graphs, compliance reports) without compression waste bandwidth and increase latency.
- What to do:
  - Verify gzip/brotli compression is enabled for all API responses above a threshold.
  - Add ETags for cacheable responses.
  - Add response size metrics to identify endpoints returning oversized payloads.

### 13.4 Database query plan monitoring

- Current state: Performance middleware and query budgets exist.
- Gap: No continuous monitoring of actual query execution plans in production.
- What to do:
  - Add periodic EXPLAIN ANALYZE logging for top-N slowest queries.
  - Add alerting when query plans change (e.g., index stops being used).
  - Add query plan dashboard showing current vs expected execution strategies.

---

## Appendix A: Priority execution plan (next 30 days)

1. Type safety sweep: Eliminate all 601 `as any` casts (start with route handlers, then storage, then utilities)
2. Storage decomposition: Split storage.ts and schema.ts into domain modules
3. Request validation: Add Zod schemas for all route handler inputs
4. Frontend polish: Interactive feedback, loading skeletons, empty states across all 31 pages
5. Testing depth: Storage unit tests, route integration tests, all 24 connector contract tests

## Appendix B: High-risk areas to monitor continuously

- Multi-tenant org boundary enforcement (every storage query must filter by orgId)
- Module-level mutable state (Maps that drift across pods)
- Error handling completeness (no silent catch blocks)
- Connector credential lifecycle (expired credentials = blind spots)
- AI cost controls (unbounded model calls = unbounded bills)
- Database migration safety (irreversible schema changes)
