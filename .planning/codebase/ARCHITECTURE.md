# Architecture

**Analysis Date:** 2026-03-25

## Pattern Overview

**Overall:** Monolithic full-stack application (Express.js + React SPA) with domain-organized route modules and a single massive storage layer.

**Key Characteristics:**
- Single Express.js server serves both REST API and React SPA (Vite dev / static prod)
- Multi-tenant architecture with org-scoped data isolation via `orgId` on all queries
- Domain routes are split into ~110 individual route files under `server/routes/`, all registered in `server/routes/index.ts`
- All database queries funnel through a single `storage` singleton exported from `server/storage.ts` (6,222 lines)
- Canonical API envelope `{ data, meta, errors }` wraps all `/api/*` responses via middleware
- Background schedulers and workers start on boot alongside the HTTP server
- Real-time updates via Server-Sent Events (SSE) through an in-process event bus

## Layers

**Presentation Layer (Client):**
- Purpose: React SPA with lazy-loaded pages, sidebar layout, auth gating
- Location: `client/src/`
- Contains: Pages (`client/src/pages/`), reusable components (`client/src/components/`), hooks (`client/src/hooks/`), utility libs (`client/src/lib/`)
- Depends on: TanStack Query for data fetching, wouter for routing, shadcn/ui for components
- Used by: End users via browser

**API Layer (Routes):**
- Purpose: HTTP endpoint definitions, request validation, auth/RBAC enforcement, response formatting
- Location: `server/routes/`
- Contains: ~110 domain-specific route files, each exporting a `register*Routes(app)` function
- Depends on: Auth middleware (`server/auth/`), RBAC (`server/rbac.ts`), request validator (`server/request-validator.ts`), storage layer
- Used by: Client SPA, external API consumers (API key auth), webhooks

**Auth & RBAC Layer:**
- Purpose: Session-based authentication (Passport.js), OAuth2 (Google/GitHub), API key auth, role-based access control
- Location: `server/auth/` (Passport setup, session, auth routes), `server/rbac.ts` (org context resolution, role checks), `server/routes/shared.ts` (API key auth)
- Contains: `setupAuth()`, `isAuthenticated` middleware, `resolveOrgContext`, `requireOrgRole`, `requirePermission`, `apiKeyAuth`, `requireScope`
- Depends on: Storage layer for user/membership lookups
- Used by: All authenticated route handlers

**Business Logic Layer (Engines):**
- Purpose: Core domain logic -- AI analysis, correlation, connectors, threat intel, etc.
- Location: `server/*.ts` (top-level engine files), `server/ai/` (AI subsystem), `server/connectors/` (25 connector plugins), `server/cloud-connectors/` (AWS/Azure/GCP), `server/native-detections/` (built-in detection rules)
- Contains: `server/ai.ts` (71KB, primary AI orchestration), `server/correlation-engine.ts`, `server/graph-correlation.ts`, `server/connector-engine.ts`, `server/normalizer.ts`, `server/entity-resolver.ts`, `server/predictive-engine.ts`, `server/soc-copilot-engine.ts`, and ~40 more domain engines
- Depends on: Storage layer, external APIs (AWS Bedrock, S3), config
- Used by: Route handlers

**Storage Layer:**
- Purpose: All database read/write operations via Drizzle ORM
- Location: `server/storage.ts` (6,222 lines -- single file with all DB query methods), `server/db.ts` (connection pool + Drizzle instance)
- Contains: One exported `storage` singleton implementing hundreds of query methods
- Depends on: `server/db.ts` (pg Pool + Drizzle), `shared/schema.ts` (table definitions)
- Used by: Every route handler and engine

**Schema Layer (Shared):**
- Purpose: Database table definitions (Drizzle ORM), Zod validation schemas, TypeScript types, constants
- Location: `shared/schema.ts` (12,814 lines), `shared/models/auth.ts`
- Contains: All `pgTable()` definitions, insert schemas via `drizzle-zod`, enums/constants (`ALERT_SEVERITIES`, `ROLE_PERMISSIONS`, etc.)
- Depends on: Drizzle ORM, Zod
- Used by: Both server and client (shared types)

**Middleware Layer:**
- Purpose: Cross-cutting concerns applied to all or subsets of requests
- Location: `server/middleware/` (domain middleware), plus top-level middleware files
- Contains:
  - `server/envelope-middleware.ts` -- wraps all `res.json()` into `{ data, meta, errors }`
  - `server/security-middleware.ts` -- Helmet, CORS, input sanitization
  - `server/sli-middleware.ts` -- SLI metrics collection
  - `server/middleware/org-rate-limit.ts` -- per-org rate limiting
  - `server/middleware/security-policy-enforcement.ts` -- IP allowlists, session policy
  - `server/middleware/plan-enforcement.ts` -- usage tier limits
  - `server/request-timeout.ts` -- 30s request timeout
  - `server/tracing.ts` -- distributed tracing
  - `server/prometheus.ts` -- Prometheus metrics
- Used by: Express middleware pipeline in `server/index.ts`

**Background Services Layer:**
- Purpose: Scheduled tasks and async workers that run alongside the HTTP server
- Location: Various `server/*.ts` files
- Contains:
  - `server/report-scheduler.ts` -- scheduled PDF generation
  - `server/job-queue.ts` -- async job processing from `job_queue` table
  - `server/sli-middleware.ts` (`startSliCollection`) -- SLI metric aggregation
  - `server/slo-alerting.ts` -- SLO breach detection
  - `server/retention-scheduler.ts` -- data retention cleanup
  - `server/partition-strategy.ts` (`startArchivalScheduler`) -- data archival
  - `server/metrics-rollup.ts` -- metrics rollup
  - `server/outbox-processor.ts` -- transactional outbox pattern for reliable event delivery
  - `server/dr-drill-scheduler.ts` -- disaster recovery drills
  - `server/distributed-concurrency.ts` (`startStaleSlotReaper`) -- cleanup stale concurrency slots
  - `server/ai/budget.ts` (`startBudgetResetScheduler`) -- AI budget resets
- Started in: `server/index.ts` after `httpServer.listen()`
- Shutdown: Graceful via `registerShutdownHandler()` in `server/scaling-state.ts`

## Data Flow

**Alert Ingestion (Push via API Key):**

1. External system sends POST to `/api/ingest/alert` or `/api/ingest/alerts/bulk` with `X-API-Key` header
2. `apiKeyAuth` middleware in `server/routes/shared.ts` validates key (SHA-256 hash lookup), sets `req.orgId`
3. Optional `verifyWebhookSignature` checks HMAC-SHA256 signature with replay protection
4. `server/normalizer.ts` normalizes alert fields across 6 source formats via `normalizeAlert()`
5. `storage.createAlert()` persists to `alerts` table with dedup via `(orgId, source, sourceEventId)` unique index
6. `publishOutboxEvent()` writes to outbox table for reliable downstream delivery
7. Event bus emits `alert:created` for SSE push to connected clients

**Alert Ingestion (Pull via Connectors):**

1. Connector sync triggered manually (`POST /api/connectors/:id/sync`) or by job queue
2. `server/connector-engine.ts` acquires distributed concurrency slot for provider
3. Connector plugin (from `server/connectors/*.ts`, 25 implementations) fetches alerts from external API
4. Alerts normalized via `server/normalizer.ts`, then batch-inserted via storage layer
5. Job run recorded in `connector_job_runs` table

**Client Data Fetch:**

1. React component uses TanStack Query with query key (e.g., `["/api/v1/alerts"]`)
2. `getQueryFn` in `client/src/lib/queryClient.ts` makes fetch with `credentials: "include"` and `X-Org-Id` header
3. Response automatically unwrapped from `{ data, meta, errors }` envelope via patched `res.json()`
4. For mutations, CSRF token auto-fetched from `/api/csrf-token` and attached as `X-CSRF-Token`

**Real-Time Updates (SSE):**

1. Client connects via `useEventStream` hook to `GET /api/events` (SSE endpoint)
2. `server/event-bus.ts` manages client connections with buffering, slow-client detection, and keep-alive
3. Events are org-scoped: clients only receive events for their organization
4. Event types: `alert:created`, `alert:updated`, `incident:created`, `incident:updated`, `correlation:found`, `entity:resolved`, `system:health`

**State Management:**
- Server: Stateless request handling; all state in PostgreSQL. In-memory caches (`server/query-cache.ts`) with TTL for read-heavy queries.
- Client: TanStack Query cache with `staleTime: Infinity` (manual invalidation). Org context via React context (`OrgContext`). Theme via `ThemeProvider`.

## Key Abstractions

**Storage Singleton:**
- Purpose: Central data access object with methods for every table operation
- Examples: `server/storage.ts` -- exports `storage` instance
- Pattern: Single class with hundreds of methods (e.g., `storage.getAlertsPaginatedWithSort()`, `storage.createAlert()`, `storage.getUserMemberships()`). All org-scoped queries use `withOrgFilter()` from `server/with-org-scope.ts`.

**Connector Plugin System:**
- Purpose: Pluggable interface for pulling alerts from 25+ security tools
- Examples: `server/connectors/crowdstrike.ts`, `server/connectors/splunk.ts`, `server/connectors/wazuh.ts`
- Pattern: Each plugin implements `ConnectorPlugin` interface (from `server/connectors/connector-plugin.ts`). Registered via `server/connectors/registry.ts`. Engine in `server/connector-engine.ts` handles concurrency, backoff, and slot management.

**API Envelope:**
- Purpose: Standardized response format for all API endpoints
- Examples: `server/api-response.ts` (types + helpers), `server/envelope-middleware.ts` (auto-wrapping)
- Pattern: `ApiEnvelope<T> = { data: T | null, meta: ApiMeta, errors: ApiError[] | null }`. Helper functions: `reply()`, `replyError()`, `replyBadRequest()`, `replyNotFound()`, etc. Client-side auto-unwrap in `client/src/lib/queryClient.ts`.

**Domain Route Modules:**
- Purpose: Organize API endpoints by domain (alerts, incidents, connectors, etc.)
- Examples: `server/routes/alerts.ts`, `server/routes/incidents.ts`, `server/routes/connectors.ts`
- Pattern: Each file exports `registerXRoutes(app: Express)`. Routes use shared middleware chain: `isAuthenticated` -> `resolveOrgContext` -> `requireOrgId` -> `requirePermission(scope, action)` -> handler. All registered centrally in `server/routes/index.ts`.

**RBAC Middleware Chain:**
- Purpose: Multi-tenant authorization with role-based permissions
- Examples: `server/rbac.ts`
- Pattern: 4-tier role hierarchy (`owner > admin > analyst > read_only`). `resolveOrgContext` reads `X-Org-Id` header to set `req.orgId` and `req.orgRole`. `requirePermission(scope, action)` checks `ROLE_PERMISSIONS` map from `shared/schema.ts`.

**Event Bus (SSE):**
- Purpose: Real-time push of server events to connected browser clients
- Examples: `server/event-bus.ts`
- Pattern: Node.js EventEmitter-based. Manages `ManagedClient` objects with per-client buffering (max 64), slow-client detection, and 30s keep-alive. Events are org-scoped.

## Entry Points

**Server Bootstrap:**
- Location: `server/index.ts`
- Triggers: `npm run dev` or `node dist/index.js`
- Responsibilities: Creates Express app, applies middleware stack (compression, security, rate limiting, JSON parsing, CSRF, tracing, SLI, envelope wrapping), registers routes via `registerRoutes()`, seeds DB, starts background services, begins listening on configured port (default 5000). Handles graceful shutdown on SIGTERM/SIGINT.

**Route Registration:**
- Location: `server/routes.ts` -> `server/routes/index.ts`
- Triggers: Called from `server/index.ts` during startup
- Responsibilities: `registerRoutes()` in `server/routes.ts` sets up auth (Passport), CSRF, org rate limiting, security policy enforcement, outbox processor, then calls `registerAllDomainRoutes()` which invokes all ~110 domain route registrars.

**Client App:**
- Location: `client/src/App.tsx`
- Triggers: Browser navigation to the app
- Responsibilities: Wraps app in ErrorBoundary -> QueryClientProvider -> ThemeProvider -> TooltipProvider. `AppContent` checks auth state: unauthenticated users see landing/auth pages; authenticated users get `AuthenticatedApp` with sidebar layout, SSE connection, org context, and ~150 lazy-loaded routes.

**Database Schema:**
- Location: `shared/schema.ts` (12,814 lines), `shared/models/auth.ts`
- Triggers: Referenced at build time and by Drizzle migrations
- Responsibilities: Defines all PostgreSQL tables, indexes, relations, insert schemas (via drizzle-zod), TypeScript types, and domain constants (severities, statuses, sources, role permissions).

**Vite Dev Server:**
- Location: `server/vite.ts`
- Triggers: Development mode only (`NODE_ENV=development`)
- Responsibilities: Sets up Vite middleware on the Express server for HMR and SPA serving.

## Error Handling

**Strategy:** Layered error handling with canonical error codes and envelope wrapping.

**Patterns:**
- All API errors use `ApiError` type with machine-readable `code` from `ERROR_CODES` constant in `server/api-response.ts`
- Helper functions (`replyBadRequest`, `replyNotFound`, `replyForbidden`, `replyValidation`, `replyInternal`) ensure consistent HTTP status + error code pairing
- Global error handler in `server/index.ts` catches unhandled Express errors, logs stack in dev, returns generic message in prod
- `errorTrackingMiddleware` in `server/error-tracker.ts` captures all unhandled errors before the global handler
- Unhandled promise rejections logged but do not crash the process
- Uncaught exceptions cause immediate `process.exit(1)`
- Client-side: `ErrorBoundary` component wraps entire app; `extractApiError()` in `client/src/lib/queryClient.ts` parses envelope errors

## Cross-Cutting Concerns

**Logging:** Structured JSON logger (`server/logger.ts`) with child loggers per module (e.g., `logger.child("rbac")`). Correlation IDs attached via `correlationMiddleware`. Request logging via `requestLogger`.

**Validation:** Zod schemas for config (`server/config.ts`). Drizzle-zod `createInsertSchema()` for DB inserts. `server/request-validator.ts` provides `validateBody()`, `validateQuery()`, `validatePathId()` middleware with predefined schemas (`bodySchemas`, `querySchemas`).

**Authentication:** Passport.js with local strategy (email/password with bcrypt), Google OAuth2, GitHub OAuth2. Sessions stored in PostgreSQL via `connect-pg-simple`. API key auth for programmatic access (SHA-256 hashed keys). CSRF protection on mutations via double-submit pattern.

**Multi-Tenancy:** All data scoped by `orgId`. `resolveOrgContext` middleware reads `X-Org-Id` header or defaults to user's first active membership. `requireOrgId` enforces presence. `withOrgFilter()` in `server/with-org-scope.ts` ensures every DB query includes org scoping. `server/tenant-isolation.ts` and `server/tenant-throttle.ts` provide additional isolation and per-tenant rate limiting.

**Observability:** Prometheus metrics (`server/prometheus.ts`), SLI/SLO monitoring (`server/sli-middleware.ts`, `server/slo-alerting.ts`), distributed tracing (`server/tracing.ts`), request timeout enforcement (`server/request-timeout.ts`), connection pool health monitoring (`server/db.ts`).

**Security:** Helmet headers, CORS, input sanitization (`server/security-middleware.ts`), rate limiting (global + per-org + per-endpoint), SSRF protection on outbound webhooks (`server/outbound-security.ts`), PII masking (`server/pii-engine.ts`), webhook signature verification (HMAC-SHA256 with replay protection).

---

*Architecture analysis: 2026-03-25*
