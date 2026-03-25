<!-- GSD:project-start source:PROJECT.md -->
## Project

Project not yet initialized. Run /gsd:new-project to set up.
<!-- GSD:project-end -->

<!-- GSD:stack-start source:research/STACK.md -->
## Technology Stack

## Current State Assessment
### What Already Works Well (Keep As-Is)
| Component | Current | Verdict |
|-----------|---------|---------|
| Structured Logger | Custom `server/logger.ts` with AsyncLocalStorage, JSON output, deep redaction, correlation IDs | Sufficient. Custom logger is well-designed. Pino migration is optional, not urgent. |
| Connection Pooling | `pg.Pool` with health monitoring, statement timeouts, utilization alerts | Sufficient for single-instance. Needs PgBouncer for multi-pod. |
| Graceful Shutdown | `scaling-state.ts` handler registry, `request-lifecycle.ts` in-flight drain | Well-implemented. |
| TypeScript Strict | `strict: true` already enabled in tsconfig.json | Good baseline. |
| Rate Limiting | `express-rate-limit` per-IP and per-org | Solid. |
| Security Headers | `helmet` v8 | Current. |
| Testing | Vitest 4.x + Playwright 1.58 + coverage | Solid framework in place. |
| Linting | ESLint 9 flat config + typescript-eslint + Prettier + Husky | Modern setup. |
| Metrics | Prometheus + custom SLI/SLO | Already production-grade. |
| Tracing | Jaeger-compatible distributed tracing | Present. |
## Recommended Additions
### 1. Structured Logging Improvements
| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| Keep custom `logger.ts` | N/A | Structured JSON logging | Already has redaction, AsyncLocalStorage context, child loggers. Replacing with Pino gains marginal perf at high migration cost for 230-line custom logger that works well. | HIGH |
| `eslint-plugin-no-console` (via existing `no-console` rule) | Built-in | Eliminate remaining console.log | Already configured as `warn` in ESLint. Upgrade to `error` to enforce. Zero new deps. | HIGH |
| Log shipping via stdout | N/A | CloudWatch/Datadog ingestion | Logger already writes JSON to stdout/stderr. K8s FluentBit sidecar or CloudWatch agent picks this up. No code changes needed. | HIGH |
### 2. TypeScript Strict Mode Hardening
| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| typescript | 5.7+ | Upgrade from 5.6.3 | 5.7 adds `--isolatedDeclarations` for faster builds and better DX. 5.8 (if available) adds further strictness. | MEDIUM |
| `@typescript-eslint/strict-type-checked` | Bundled with typescript-eslint 8.x | Stricter type rules | Adds `no-unsafe-argument`, `no-unsafe-assignment`, `no-unsafe-call`, `no-unsafe-member-access`, `no-unsafe-return`. These catch real bugs in a security platform. | HIGH |
| `eslint-plugin-security` | ^3.0.0 | Security-specific lint rules | Detects `eval()`, non-literal RegExp, `child_process` misuse, prototype pollution patterns. Essential for a security product. | MEDIUM |
| `knip` | ^5.0.0 | Dead code detection | Finds unused exports, files, dependencies. Large codebase (storage.ts is 244KB) likely has dead code. | HIGH |
### 3. Connection Pooling & Database Hardening
| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| PgBouncer | 1.23+ | External connection pooler | With multi-pod EKS deployment, each pod opens 20 connections. 3 pods = 60 connections. PgBouncer in transaction mode pools these down to ~20 actual DB connections. Deploy as sidecar or shared service. | HIGH |
| AWS RDS Proxy | Managed | Alternative to PgBouncer | Managed connection pooler for RDS. Zero operational overhead but ~15% latency overhead vs PgBouncer. Supports IAM auth. Choose this if ops team is small. | HIGH |
| Read replica routing | N/A | Offload read queries | Add a `readDb` pool pointing to RDS read replica for analytics, dashboard stats, entity graph queries. Keep `db` for writes. | MEDIUM |
| `drizzle-orm` read replica support | 0.39+ | Built-in read/write split | Drizzle supports `withReplicas()` for automatic read/write routing. Verify with current version. | LOW |
### 4. Node.js Production Hardening
| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| Node.js `--max-old-space-size` | Built-in | Heap memory limit | Set to 75% of K8s container memory limit. Prevents OOM kill by triggering GC pressure before K8s kills the pod. | HIGH |
| `--enable-source-maps` | Built-in | Production stack traces | The app builds to `dist/index.cjs` via esbuild. Without source maps, stack traces point to bundled code. | HIGH |
| `clinic.js` | ^14.0.0 | Performance profiling (dev dep) | Flame graphs, event loop analysis for debugging production perf issues. Not shipped to production. | MEDIUM |
| `node:cluster` | Built-in | Multi-process | NOT recommended. EKS horizontal pod autoscaling is the correct scaling mechanism. Clustering inside a pod complicates graceful shutdown (already implemented) and K8s health checks. | HIGH (not to use) |
- Add `process.memoryUsage()` to the existing Prometheus metrics endpoint
- Set `--max-http-header-size=16384` (default 16KB is fine, but be explicit)
- Enable `UV_THREADPOOL_SIZE=16` for workloads with filesystem/DNS operations (connector syncs, report PDF generation)
### 5. Dependency Audit & Vulnerability Scanning
| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| `npm audit --audit-level=high` | Built-in | CI pipeline gate | Free, zero config. Block merges on high/critical vulns. Already available. | HIGH |
| Socket.dev GitHub App | SaaS | Supply chain attack detection | Goes beyond CVEs -- detects typosquatting, install scripts, network access, telemetry in dependencies. For a security platform, this matters. Free for open source. | MEDIUM |
| `better-npm-audit` | ^3.11.0 | Allowlist known issues | Wraps `npm audit` with exception management. Lets you acknowledge accepted risks without breaking CI. | MEDIUM |
| Dependabot | GitHub native | Automated dependency PRs | Already available in GitHub. Configure for security updates only (not version bumps) to reduce noise. | HIGH |
| Snyk | SaaS | Deep vuln scanning | Most comprehensive DB but expensive. Use only if Socket.dev + npm audit is insufficient. | LOW |
| `license-checker` | ^25.0.0 | License compliance | Ensure no GPL/AGPL deps in a commercial SaaS product. Run in CI. | MEDIUM |
# In GitHub Actions
- npm audit --audit-level=high --omit=dev
- npx license-checker --failOn "GPL-3.0;AGPL-3.0"
### 6. Testing for Security-Critical Applications
| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| Vitest (keep) | 4.x | Unit/integration testing | Already in place. Increase coverage thresholds. | HIGH |
| Playwright (keep) | 1.58+ | E2E testing | Already in place. Add auth flow and RBAC E2E tests. | HIGH |
| `supertest` | ^7.0.0 | HTTP integration tests | Test Express routes with real middleware stack without starting server. Better than mocking req/res for API contract testing. | HIGH |
| `@faker-js/faker` | ^9.0.0 | Realistic test data | Current test factories use hardcoded values. Faker generates realistic security data for fuzz-like testing. | MEDIUM |
| `msw` (Mock Service Worker) | ^2.7.0 | External service mocking | Mock AWS Bedrock, S3, connector APIs in integration tests. Better than `vi.mock` for HTTP-level mocking -- tests real serialization. | MEDIUM |
| Property-based testing via `fast-check` | ^4.0.0 | Input fuzzing | For a security platform: fuzz normalizer inputs, API validation boundaries, PII detection patterns. Finds edge cases unit tests miss. | MEDIUM |
- Phase 1: Raise to 30% (current baseline + critical paths)
- Phase 2: Raise to 50% (after adding supertest API tests)
- Phase 3: Target 70% for security-critical modules (normalizer, RBAC, auth, PII engine, correlation)
### 7. Additional Production Hardening
| Technology | Version | Purpose | Why | Confidence |
|------------|---------|---------|-----|------------|
| Redis / ElastiCache | 7.x | Shared state for multi-pod | `scaling-state.ts` identifies 4 stores needing shared backend: AI circuit breakers, webhook circuit breakers, webhook rate buckets, SLO breach cooldown. Required before scaling beyond 1 replica. | HIGH |
| `ioredis` | ^5.4.0 | Redis client | Supports clustering, sentinels, pipeline. Standard choice for Node.js + Redis. | HIGH |
| `tsx` removal for production | N/A | Avoid dev tooling in prod | Production already uses `node dist/index.cjs`. Verify Dockerfile does not use tsx. | HIGH |
| Source map generation | esbuild config | Production debugging | Enable `sourcemap: true` in `script/build.ts` for esbuild. Combine with `--enable-source-maps` flag. | HIGH |
## Alternatives Considered
| Category | Recommended | Alternative | Why Not |
|----------|-------------|-------------|---------|
| Logger | Keep custom logger.ts | Pino 9 | Custom logger already has redaction, AsyncLocalStorage, child loggers. Migration cost > marginal perf gain. |
| Logger | Keep custom logger.ts | Winston 3 | Winston is slower than both Pino and the custom logger. No benefit. |
| Connection Pooler | AWS RDS Proxy | PgBouncer sidecar | PgBouncer is better perf but adds operational burden. RDS Proxy is managed. |
| Clustering | EKS HPA (don't cluster) | node:cluster | Clustering inside pods conflicts with K8s scaling model. Already solved. |
| Vuln Scanning | npm audit + Socket.dev | Snyk | Snyk free tier is limited. npm audit + Socket.dev covers 95% of cases. |
| Test Runner | Vitest (keep) | Jest | Already on Vitest. No reason to switch. |
| HTTP Test | supertest | Vitest mocks | supertest tests real middleware stack, not just handler logic. |
| Property Testing | fast-check | N/A | Only mature property testing lib for JS/TS. |
| Redis Client | ioredis | node-redis | ioredis has better cluster support, pipeline API, and TypeScript types. |
## Installation
# New production dependencies
# New dev dependencies
# TypeScript upgrade (verify latest stable first)
## Environment Variable Additions
| Variable | Required | Description |
|----------|----------|-------------|
| `REDIS_URL` | Yes (multi-pod) | Redis/ElastiCache connection string |
| `LOG_LEVEL` | No | Override log level (debug/info/warn/error) |
| `UV_THREADPOOL_SIZE` | No | libuv thread pool size (default 4, recommend 16) |
| `NODE_OPTIONS` | No | `--max-old-space-size=1536 --enable-source-maps` |
## Sources & Confidence Notes
- Codebase analysis: HIGH confidence (directly read all relevant files)
- Library recommendations: MEDIUM confidence (based on training data, WebSearch was unavailable for version verification)
- Version numbers: LOW confidence for newest releases -- verify `npm info [pkg] version` before installing
- Architecture decisions (no clustering, keep custom logger, use RDS Proxy): HIGH confidence (based on codebase-specific analysis)
<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->
## Conventions

## Naming Patterns
- TypeScript source files: `kebab-case.ts` (e.g., `server/alert-router.ts`, `server/threat-enrichment.ts`, `client/src/components/command-palette.tsx`)
- React components: `kebab-case.tsx` (e.g., `app-sidebar.tsx`, `theme-provider.tsx`)
- Test files: `__tests__/` directory with `.test.ts` suffix (e.g., `server/__tests__/normalizer.test.ts`)
- E2E tests: `e2e/` directory with `.spec.ts` suffix (e.g., `e2e/login.spec.ts`)
- Configuration files: camelCase (e.g., `eslint.config.js`, `vitest.config.ts`, `tailwind.config.ts`)
- camelCase for all functions and methods (e.g., `normalizeAlert`, `resolveOrgContext`, `startReportScheduler`)
- Async functions follow camelCase pattern (e.g., `correlateAlert`, `createAuditLog`)
- Prefixes for utility functions:
- camelCase for all variables and constants (e.g., `userId`, `alertId`, `orgId`)
- SCREAMING_SNAKE_CASE for module-level constants (e.g., `ROLE_HIERARCHY`, `ALERT_SEVERITIES`, `PRODUCTION_ENVS`)
- Constants exported from schema: SCREAMING_SNAKE_CASE arrays (e.g., `ALERT_STATUSES`, `CONNECTOR_TYPES`)
- Underscore prefix for intentionally unused variables (e.g., `_parseErr`, `_unused`, matching ESLint rule `argsIgnorePattern: "^_"`)
- PascalCase for all types, interfaces, and type aliases (e.g., `Alert`, `NormalizedAlert`, `ApiEnvelope<T>`, `Request`, `Response`)
- Type imports explicitly marked: `import type { X }` (e.g., `import type { Alert, Incident } from "@shared/schema"`)
- Drizzle schema exports match database table names in camelCase (e.g., `alerts`, `incidents`, `organizations`)
## Code Style
- Tool: Prettier (configured via `.prettierrc`)
- Line width: 120 characters
- Indentation: 2 spaces
- Quotes: double quotes (singleQuote: false)
- Semicolons: always (semi: true)
- Trailing commas: all (trailingComma: "all")
- Arrow functions: always include parens (arrowParens: "always")
- Line endings: LF (endOfLine: "lf")
- Tool: ESLint with TypeScript support (`eslint.config.js`)
- Base config: typescript-eslint recommended + JS recommended + prettier
- React-specific: react-hooks rules enforced
- Unused variables rule: Warn with `^_` prefix allowed (argsIgnorePattern, varsIgnorePattern, etc.)
- Console usage: warn, only `console.warn` and `console.error` allowed
## Import Organization
- `@shared/*` → `shared/` - Shared types, schemas, and constants
- `@/*` → `client/src/` - Client-side imports in React components
- No aliasing for server imports (use relative paths)
## Error Handling
- Use canonical `ERROR_CODES` from `server/api-response.ts` (all-caps, e.g., `UNAUTHENTICATED`, `FORBIDDEN`, `VALIDATION_ERROR`)
- All API errors return via helper functions: `replyError()`, `replyUnauthenticated()`, `replyForbidden()`, `replyBadRequest()`, `replyNotFound()`, `replyConflict()`, `replyValidation()`
- Errors are structured as `ApiError` objects with code, message, optional field, and optional details
- All API responses wrapped in `ApiEnvelope<T>` with canonical shape: `{ data: T | null, meta: ApiMeta, errors: ApiError[] | null }`
- Express middleware logs using `logger.child()` for context
## Logging
- Create a logger instance in each module: `const log = logger.child("module-name");`
- Levels: `debug`, `info`, `warn`, `error`
- Include context as second argument (object): `log.info("message", { userId, orgId, route })`
- Log auth failures: org access denied, suspicious activity, policy violations
- Log async task lifecycle: start, completion, error
## Comments
- Complex logic (correlation scoring, threat enrichment algorithms)
- Non-obvious business rules (e.g., tenant isolation, rate limiting windows)
- Workarounds or temporary fixes (mark with "TODO", "FIXME", "HACK", "XXX")
- Disable ESLint rules inline only with justification: `/* eslint-disable @typescript-eslint/no-explicit-any */`
- Optional; used selectively for public APIs and complex signatures
- Not enforced project-wide but present in some files (e.g., `storage.ts` imports)
- Type exports are self-documenting via TypeScript types
## Function Design
- Prefer functions under 50 lines
- Break logic into smaller, named helpers if exceeding 50 lines
- Use middleware/utility functions for cross-cutting concerns
- Limit to 3+ parameters; use object destructuring for complex cases
- Use `Partial<T>` for optional overrides in factories
- Use explicit return types: `function getName(): string { ... }`
- Async functions return Promise: `async function fetchAlert(): Promise<Alert> { ... }`
- Use union types for multiple outcomes: `Promise<Alert | null>` or `AlertResult | ErrorResult`
## Module Design
- Named exports for functions and types: `export function createUser() { ... }` and `export type User = { ... }`
- Avoid default exports; use named exports for better IDE support
- Group related functions (e.g., all storage functions in `storage.ts`)
- Used in `shared/schema.ts` to export all DB schemas and types
- Used in `client/src/components/ui/` for shadcn/ui components
- Pattern: `export * from "./models/auth"` in `shared/schema.ts`
- Keep modules focused on one responsibility
- Large files get subdirectories (e.g., `server/storage/` for tiering-manager, cold-query)
- Routes organized in `server/routes/` subdirectory by domain
## Type Safety
- Strict mode enabled: `"strict": true` in `tsconfig.json`
- No implicit any: errors on untyped parameters
- Nullable handling: explicit `T | null` or `T | undefined`
- Database layer: Drizzle ORM provides type safety with generated types
- Minimize type assertions (`as`)
- When necessary, use `as` with justification comment
- Cast Express request properties: `(req as any).user` where needed
## Testing Conventions
<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->
## Architecture

## Pattern Overview
- Multi-tenant SaaS with organization isolation at database level
- Monolithic backend with modular route-based endpoint organization
- Event-driven async processing with job queue and outbox patterns
- Extensive AI/ML integration via AWS Bedrock
- Canary deployments on AWS EKS with Argo Rollouts
## Layers
- Purpose: React UI for security operations dashboards and workflows
- Location: `client/src/`
- Contains: Pages (28 domains), components (UI library + features), hooks (auth, org context, events), lib (queryClient, utilities)
- Depends on: Backend APIs (`/api/*`), TanStack Query for state, wouter for routing
- Used by: End users, team members with RBAC roles
- Purpose: Route incoming requests to domain-specific handlers, apply middleware (auth, rate limit, CSRF, security policies)
- Location: `server/index.ts`, `server/routes.ts`, `server/routes/*.ts` (110+ domain route files)
- Contains: Express middleware stack, route registration, response envelopes, error handling
- Depends on: Express 5, security-middleware, api-response helpers
- Used by: Frontend, external API consumers, webhooks
- Purpose: Domain-specific logic organized by feature (alerts, incidents, compliance, playbooks, etc.)
- Location: `server/routes/` (one route file per domain)
- Contains: Handler functions that coordinate with storage, engines, and integrations
- Pattern: Each route file exports `register[Domain]Routes(app)` function
- Examples: `server/routes/alerts.ts`, `server/routes/incidents.ts`, `server/routes/compliance.ts`
- Purpose: All database queries, type-safe via Drizzle ORM
- Location: `server/storage.ts` (244KB, ~6000+ query functions)
- Contains: Query builders, insert/update/delete operations, complex joins
- Depends on: Drizzle ORM, PostgreSQL schema (`shared/schema.ts`)
- Used by: Route handlers, engines, background workers
- Purpose: Single source of truth, multi-tenant PostgreSQL (AWS RDS)
- Location: Schema in `shared/schema.ts` (all table definitions with Zod schemas)
- Connection: `server/db.ts` (pg pool with 20 connections in prod, 5 in dev)
- Tables: 80+ tables including alerts, incidents, organizations, connectors, audit_logs, entities, IOCs, CSPM, endpoint telemetry, job_queue, and many domain-specific tables
- Patterns: Drizzle ORM with relations, unique indexes for deduplication (orgId + source + sourceEventId on alerts)
- Purpose: Async/scheduled work for correlations, reporting, metrics, SLOs
- Location: `server/*-scheduler.ts`, `server/job-queue.ts`, `server/*-processor.ts`
- Includes: Report scheduler, metrics rollup, SLO alerting, retention, archival, DR drills, stale slot reaper
- Started: On app boot via bootstrap functions in `server/index.ts`
- Pattern: Periodic setInterval with error tracking and graceful shutdown
- Purpose: Core intelligence for alert correlation, narrative generation, autonomous response
- Location: `server/ai.ts` (71KB), `server/ai/` (11 modules: budget, vector-search, model-gateway, prompt-registry, etc.)
- Integrations: AWS Bedrock (Mistral Large 2), SageMaker optional
- Features: Token budgeting, prompt templating, active learning, confidence scoring, vector search
- Used by: Routes, correlation engine, predictive engine, autonomous SOC
- Purpose: Pull alerts from 24+ security tools, normalize to OCSF, push to integrations
- Locations: `server/connector-engine.ts`, `server/connectors/`, `server/cloud-connectors/`, `server/integrations/`
- Connectors: CrowdStrike EDR, Splunk, Palo Alto, AWS GuardDuty, Wiz, SentinelOne, Elastic, QRadar, Fortinet, Okta, Proofpoint, etc.
- Normalizer: `server/normalizer.ts` (40KB) transforms source data to OCSF schema
- Validation: `server/connector-config-validator.ts` validates connection parameters
- Purpose: Link related alerts into incidents using entity graph, MITRE ATT&CK alignment, temporal analysis
- Locations: `server/correlation-engine.ts`, `server/graph-correlation.ts`, `server/entity-resolver.ts`, `server/threat-enrichment.ts`
- Correlation Config: 24-hour time window, min 1 shared entity, 0.65 confidence threshold for incident creation
- Weights: sharedEntity (0.25), mitreAlignment (0.2), temporalProximity (0.15), categoryMatch (0.15), etc.
- Graph DB: Security graph engine (`server/security-graph-engine.ts`) for attack path analysis
- Purpose: Transform disparate alert formats to unified schema, enrich with threat intel, PII masking
- Locations: `server/normalizer.ts`, `server/ocsf.ts`, `server/pii-engine.ts`, `server/threat-intel-feeds.ts`, `server/ioc-matcher.ts`
- OCSF: Open Cybersecurity Schema Framework compliance
- Enrichment: Threat intel feeds, IOC matching, entity metadata lookup, confidence boosting
- Purpose: Execute automated incident response actions (isolate host, block IP, quarantine file, etc.)
- Locations: `server/remediation-engine.ts`, `server/action-dispatcher.ts`, `server/response-actions` (table)
- Statuses: pending → executing → completed/failed, with rollback capability
- Integrations: Endpoint agents, firewall APIs, cloud security tools
- Purpose: Enforce security policies, compliance frameworks, CSPM, data residency, retention
- Locations: `server/policy-engine.ts`, `server/policy-packs-engine.ts`, `server/cspm-scanner.ts`, `server/data-lifecycle.ts`, `server/retention-scheduler.ts`, `server/partition-strategy.ts`
- Features: Policy compliance scoring, compliance gap detection, DSAR handling, data archival to cold storage, retention enforcement
- Purpose: Multi-tenant isolation, rate limiting, RBAC, audit logging, encryption
- Locations: `server/tenant-isolation.ts`, `server/tenant-throttle.ts`, `server/rbac.ts`, `server/security-middleware.ts`, `server/tenant-isolation.ts`
- Auth: Replit OpenID Connect (primary), Passport.js with Google/GitHub OAuth2, session-based via express-session
- API Keys: SHA-256 hashed, X-API-Key header auth for programmatic ingestion
- Audit: Chain-hash audit logs with tamper evidence (`server/audit-logs` table)
- Purpose: Real-time updates, email/Slack/Teams notifications, webhook delivery with replay protection
- Locations: `server/event-bus.ts`, `server/outbox-processor.ts`, `server/notification-dispatcher.ts`, `server/email-service.ts`
- Real-time: Server-sent events (SSE) on `/api/events`
- Outbox Pattern: Reliable event delivery to webhooks and integrations
- Idempotency: X-Idempotency-Key header support on mutations
- Purpose: Prometheus metrics, request tracing, error tracking, performance budgets, SLI/SLO tracking
- Locations: `server/prometheus.ts`, `server/tracing.ts`, `server/error-tracker.ts`, `server/db-performance.ts`, `server/sli-middleware.ts`, `server/slo-alerting.ts`
- Metrics: Request latency, error rates, connector sync times, query performance
- Tracing: Jaeger-compatible distributed tracing with correlation IDs
- Deception Platform: `server/deception-engine.ts` (honeypot management)
- Threat Hunting: `server/threat-hunting` routes, `server/hunt-engine.ts`
- Predictive Defense: `server/predictive-engine.ts` (anomaly detection, forecasting)
- Autonomous SOC: `server/soc-copilot-engine.ts`, autonomous response policies
- Supply Chain Security: `server/supply-chain-engine.ts` (vendor risk, TPRM)
- Ransomware Intelligence: `server/ransomware-intelligence.ts` (IOC feeds, attack patterns)
- Dark Web Monitoring: `server/dark-web-monitor.ts` (threat intel from dark web)
- Data Discovery: `server/data-discovery.ts`, `server/data-lake` routes
## Data Flow
- React: TanStack Query (with queryClient in `client/src/lib/queryClient.ts`)
- Cache key strategy by domain (alerts, incidents, connectors, etc.)
- Server-side pagination via page/pageSize in ApiMeta
- Express session (express-session + connect-pg-simple)
- Stored in sessions table (PostgreSQL backend)
- Auto-promoted to superadmin on deserialize if user is owner
- Job queue (`job_queue` table): reports, archival, metric rollups, etc.
- Worker processes jobs via `startJobWorker()`
- Failed jobs retry with exponential backoff
## Key Abstractions
- Purpose: Canonical response format for all endpoints
- Location: `server/api-response.ts`
- Structure: `{ data: T | null, meta: {...}, errors: ApiError[] | null }`
- Used by: All route handlers via `reply()`, `replyError()`, `replyForbidden()`, etc.
- Provides: Machine-readable error codes, pagination metadata, request IDs
- Purpose: Multi-tenant data segregation
- Pattern: Every table has `orgId` column, queries filter by org
- Enforcement: Middleware checks request user's org membership before route handlers execute
- Scope: `withOrgScope()` helper in `server/with-org-scope.ts`
- Purpose: Represent users, hosts, IPs, domains, files, processes as nodes and relationships
- Location: `entities` table with `type` (user/host/ip/domain/file_hash/email/url/process) and `value`
- Relations: `alertEntities` junction table links alerts to entities
- Graph Queries: `entity-resolver.ts` finds connected entities for attack path analysis
- Purpose: Group related alerts by shared entities, temporal proximity, MITRE alignment
- Location: `correlationClusters` table
- Confidence: Weighted sum of factors (shared entity, temporal proximity, MITRE alignment, severity, category, kill chain progression)
- Threshold: 0.65 confidence triggers incident creation
- Purpose: Codify response workflows
- Location: `playbooks` table, `server/routes/playbooks.ts`
- Triggers: alert_created, alert_critical, incident_created, incident_escalated, alert_category_deception, manual
- Execution: Stored in `playbookExecutions` with statuses (pending/executing/completed/failed)
- Approvals: `playbookApprovals` table for human-in-the-loop workflows
- Purpose: Credentials and endpoints for external tools
- Location: `connectors` table with encrypted credentials
- Auth Types: oauth2, api_key, basic, aws_credentials, token, certificate
- Validation: `connector-config-validator.ts` ensures required fields present
- Purpose: Runtime feature toggles for gradual rollouts
- Location: `server/feature-flags.ts`
- Pattern: Environment-based or organization-specific flags
- Purpose: In-memory caching for expensive queries (threat intel, entity lookups)
- Location: `server/query-cache.ts`
- TTL: Configurable per query type
- Used by: Correlation, enrichment, analytics queries
## Entry Points
- Location: `server/index.ts`
- Triggers: `npm run dev` or `npm run start`
- Responsibilities:
- Location: `client/src/main.tsx`, rendered to `client/src/App.tsx`
- Triggers: Vite dev server or built bundle
- Responsibilities:
- Location: `server/routes/index.ts` → `registerAllDomainRoutes()`
- Imports 110+ route files and calls `register[Domain]Routes(app)` for each
- Applies org rate limiting and security policy enforcement middleware
- Starts outbox processor for webhook delivery
## Error Handling
- `replyUnauthenticated()` - missing or invalid session
- API key validation: missing/invalid/revoked/scope denied
- Webhook signature validation failures
- `replyForbidden()` - insufficient RBAC permissions
- `ORG_ACCESS_DENIED` - user not in requested organization
- `PERMISSION_DENIED` - insufficient role/scope
- `replyValidation()` - request body/query param validation failures
- Field-level error details included
- Zod schema errors mapped to ApiError format
- Resource doesn't exist or user lacks permission to view it
- No information leak about existence
- Idempotency key mismatch or unique constraint violation
- Used for concurrent update prevention
- Global IP-based rate limiter: 300 req/min per IP (production)
- Org-based rate limiter: tenant throttle enforcement
- Ingestion-specific rate limiter for API key auth
- `replyInternal()` - unhandled exceptions
- Error tracking via `error-tracker.ts` for debugging
- User receives generic message, details logged server-side
- Try-catch in critical paths with fallback behavior
- Warnings logged but requests don't fail
- Outbox processor ensures event delivery reliability
## Cross-Cutting Concerns
- Framework: `server/logger.ts` (structured logging with child contexts)
- Pattern: `logger.child("component-name").info("message", {context})`
- Correlation IDs: Attached to all log entries for request tracing
- Framework: Zod for schema validation
- Patterns: `insertSchema` from `drizzle-zod` for DB types, custom validators in route handlers
- Request body validation before handler execution
- Query parameter validation for pagination and filters
- Primary: Replit Auth (OpenID Connect)
- Secondary: Google/GitHub OAuth2 via Passport.js
- Session: Express-session with PostgreSQL store (sessions table)
- API Key: X-API-Key header, SHA-256 hashed in database
- Auto-promotion: Superadmin role on deserialize if user is org owner
- Four roles: owner, admin, analyst, read_only
- Scopes: incidents, connectors, api_keys, response_actions, settings, team
- Enforcement: Middleware checks `req.user.role` and `req.user.orgId` before handler
- Permission check helper: `rbac.ts` module
- All sensitive mutations recorded in `auditLogs` table
- Chain-hash structure for tamper evidence (each entry references previous hash)
- Fields: userId, orgId, action, resourceType, resourceId, changes, timestamp, previousHash, currentHash
- Used for compliance audits and forensics
- Global: `express-rate-limit` middleware (300 req/min per IP in production)
- Per-org: `orgRateLimitMiddleware` from `server/middleware/org-rate-limit.ts`
- Ingestion: Special limiter for `/api/ingest/alert` endpoints
- Skip: Health checks, metrics endpoints exempt in production
- Framework: `csurf` middleware applied to all state-changing requests
- Endpoint: `GET /api/csrf-token` returns token for new sessions
- Validation: Token checked on POST/PUT/DELETE requests
- Added via `applyCsrfProtection(app)` in routes.ts
- In-flight tracking: `inFlightMiddleware` to count pending requests
- Graceful shutdown: `waitForInFlightDrain()` waits for requests to complete
- Timeout: `requestTimeoutMiddleware` kills slow requests (30s production, 60s dev)
- Performance budget: `performanceBudgetMiddleware` rejects if pool utilization > 80%
- Gzip compression on responses > 1KB (except SSE streams)
- Filters out text/event-stream to preserve real-time updates
- Correlation ID middleware: Unique request ID across logs
- Distributed tracing: Jaeger-compatible spans via `tracing.ts`
- Request context: Passed through middleware stack
<!-- GSD:architecture-end -->

<!-- GSD:workflow-start source:GSD defaults -->
## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:
- `/gsd:quick` for small fixes, doc updates, and ad-hoc tasks
- `/gsd:debug` for investigation and bug fixing
- `/gsd:execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.
<!-- GSD:workflow-end -->



<!-- GSD:profile-start -->
## Developer Profile

> Profile not yet configured. Run `/gsd:profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.
<!-- GSD:profile-end -->
