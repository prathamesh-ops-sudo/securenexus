# Codebase Structure

**Analysis Date:** 2026-03-25

## Directory Layout

```
securenexus/
├── client/                    # React SPA (Vite)
│   ├── public/                # Static assets served as-is
│   ├── src/
│   │   ├── App.tsx            # Root component, routing, auth gating
│   │   ├── assets/            # Images, icons
│   │   ├── components/        # Reusable UI components
│   │   │   └── ui/            # shadcn/ui primitives
│   │   ├── hooks/             # Custom React hooks
│   │   ├── lib/               # Utility functions, API client, i18n
│   │   └── pages/             # ~150 lazy-loaded page components
│   └── index.html             # SPA entry HTML
├── server/                    # Express.js backend
│   ├── index.ts               # App bootstrap, middleware stack, server start
│   ├── routes.ts              # Top-level route registration (auth, CSRF, domain routes)
│   ├── routes/                # ~110 domain route modules
│   │   ├── index.ts           # registerAllDomainRoutes() -- imports and calls all route registrars
│   │   ├── shared.ts          # Shared route utilities (API key auth, rate limiters, helpers)
│   │   ├── alerts.ts          # Alert CRUD endpoints
│   │   ├── incidents.ts       # Incident CRUD endpoints
│   │   ├── connectors.ts      # Connector management endpoints
│   │   ├── ingestion.ts       # Alert ingestion (push) endpoints
│   │   ├── health.ts          # Health/readiness/liveness probes
│   │   ├── well-known.ts      # /.well-known/* endpoints
│   │   └── ...                # ~105 more domain route files
│   ├── auth/                  # Authentication subsystem
│   │   ├── index.ts           # Re-exports setupAuth, isAuthenticated, registerAuthRoutes
│   │   ├── session.ts         # Passport.js config, session setup, isAuthenticated middleware
│   │   ├── routes.ts          # Login, register, logout, OAuth callback routes
│   │   └── storage.ts         # Auth-specific DB queries
│   ├── ai/                    # AI/ML subsystem
│   │   ├── autonomous-analyst.ts  # Autonomous investigation agent
│   │   ├── budget.ts          # AI usage budget tracking
│   │   ├── confidence-scorer.ts   # AI confidence scoring
│   │   ├── enhanced-prompts.ts    # Prompt templates
│   │   ├── investigation-runner.ts # Investigation orchestration
│   │   ├── model-gateway.ts   # Multi-model routing
│   │   ├── prompt-registry.ts # Prompt version management
│   │   ├── rule-generator.ts  # AI-generated detection rules
│   │   ├── tokenizer.ts       # Token counting
│   │   ├── vector-search.ts   # Vector similarity search
│   │   └── active-learning.ts # Active learning pipeline
│   ├── connectors/            # Pull-based connector plugins (25 integrations)
│   │   ├── connector-plugin.ts    # ConnectorPlugin interface definition
│   │   ├── registry.ts        # Plugin registration
│   │   ├── crowdstrike.ts     # CrowdStrike EDR connector
│   │   ├── splunk.ts          # Splunk SIEM connector
│   │   ├── wazuh.ts           # Wazuh connector
│   │   └── ...                # 22 more connector plugins
│   ├── cloud-connectors/      # Cloud security connectors
│   │   ├── index.ts           # Cloud connector registry
│   │   ├── aws.ts             # AWS security connector
│   │   ├── azure.ts           # Azure security connector
│   │   ├── gcp.ts             # GCP security connector
│   │   ├── attack-path-analyzer.ts
│   │   ├── drift-detector.ts
│   │   ├── dspm-scanner.ts
│   │   └── remediation-engine.ts
│   ├── integrations/          # Third-party service integrations
│   │   ├── slack-channel.ts   # Slack notifications
│   │   ├── github-app.ts      # GitHub App integration
│   │   ├── gitlab.ts          # GitLab integration
│   │   ├── microsoft365.ts    # M365 integration
│   │   └── ...                # 7 more integrations
│   ├── middleware/             # Express middleware modules
│   │   ├── org-rate-limit.ts  # Per-org rate limiting
│   │   ├── security-policy-enforcement.ts  # IP allowlists, session policy
│   │   ├── plan-enforcement.ts    # Usage tier limits
│   │   ├── super-admin.ts     # Super admin middleware
│   │   ├── auth-rate-limit.ts # Auth endpoint rate limiting
│   │   └── data-residency.ts  # Data residency enforcement
│   ├── native-detections/     # Built-in detection rules
│   │   ├── index.ts
│   │   ├── builtin-rules.ts
│   │   └── evaluator.ts
│   ├── reporting/             # Report generation
│   │   ├── pdf-generator.ts
│   │   └── chart-renderer.ts
│   ├── storage/               # Storage extensions
│   │   ├── tiering-manager.ts # Hot/warm/cold data tiering
│   │   └── cold-query.ts      # Cold storage query support
│   ├── __tests__/             # Server-side unit tests
│   ├── storage.ts             # Main storage singleton (6,222 lines, all DB queries)
│   ├── db.ts                  # PostgreSQL pool + Drizzle ORM instance
│   ├── ai.ts                  # Primary AI orchestration (71KB)
│   ├── config.ts              # Zod-validated configuration from env vars
│   ├── rbac.ts                # RBAC middleware (resolveOrgContext, requireOrgRole, requirePermission)
│   ├── api-response.ts        # Canonical ApiEnvelope types + reply helpers
│   ├── envelope-middleware.ts # Auto-wraps res.json() into envelope
│   ├── logger.ts              # Structured JSON logger
│   ├── normalizer.ts          # Alert normalization (6 source transformers)
│   ├── connector-engine.ts    # Connector sync orchestration with distributed concurrency
│   ├── correlation-engine.ts  # Alert correlation logic
│   ├── graph-correlation.ts   # Graph-based correlation
│   ├── entity-resolver.ts     # Entity extraction and resolution
│   ├── event-bus.ts           # SSE event bus for real-time updates
│   ├── with-org-scope.ts      # Org-scoped query helpers (withOrgFilter)
│   ├── request-validator.ts   # Zod-based request validation middleware
│   ├── security-middleware.ts # Helmet, CORS, sanitization
│   ├── openapi.ts             # OpenAPI spec generation (94KB)
│   ├── seed.ts                # Database seeding
│   ├── job-queue.ts           # Async job worker
│   ├── outbox-processor.ts    # Transactional outbox pattern
│   └── ...                    # ~50 more engine/utility files
├── shared/                    # Code shared between client and server
│   ├── schema.ts              # All DB table definitions, Zod schemas, types (12,814 lines)
│   └── models/
│       └── auth.ts            # User, session, org membership table definitions
├── migrations/                # Drizzle ORM migration files
│   └── meta/                  # Migration metadata
├── e2e/                       # End-to-end tests (Playwright)
├── k8s/                       # Kubernetes manifests
│   ├── base/                  # Base K8s resources
│   ├── staging/               # Staging overlay
│   ├── uat/                   # UAT overlay
│   ├── production/            # Production overlay
│   ├── monitoring/            # Prometheus + Grafana configs
│   └── argo-rollouts/         # Canary deployment configs
├── scripts/                   # Build and utility scripts
├── script/                    # Additional scripts
├── docs/                      # Documentation
├── .github/
│   ├── workflows/             # CI/CD pipelines (GitHub Actions)
│   ├── scripts/               # CI helper scripts
│   └── ISSUE_TEMPLATE/        # Issue templates
├── .husky/                    # Git hooks (commitlint, etc.)
├── package.json               # Dependencies and scripts
├── tsconfig.json              # TypeScript configuration
├── vite.config.ts             # Vite build configuration
├── vitest.config.ts           # Vitest test configuration
├── tailwind.config.ts         # Tailwind CSS configuration
├── drizzle.config.ts          # Drizzle ORM config
├── eslint.config.js           # ESLint configuration
├── commitlint.config.js       # Commit message linting
├── playwright.config.ts       # Playwright E2E config
└── postcss.config.js          # PostCSS configuration
```

## Directory Purposes

**`client/src/pages/`:**
- Purpose: One file per page/view in the application (~150 files)
- Contains: React components, each default-exported and lazy-loaded in `App.tsx`
- Key files: `dashboard.tsx`, `alerts.tsx`, `alert-detail.tsx`, `incidents.tsx`, `incident-detail.tsx`, `connectors.tsx`, `landing.tsx`

**`client/src/components/`:**
- Purpose: Reusable UI components shared across pages
- Contains: Application-level components (`app-sidebar.tsx`, `command-palette.tsx`, `notification-bell.tsx`, `error-boundary.tsx`, `loading-screen.tsx`) and `ui/` subdirectory with shadcn/ui primitives
- Key files: `app-sidebar.tsx` (main navigation), `command-palette.tsx` (keyboard shortcuts), `error-boundary.tsx`

**`client/src/hooks/`:**
- Purpose: Custom React hooks for shared stateful logic
- Contains: 8 hooks
- Key files: `use-auth.ts` (login/logout/register via TanStack Query), `use-event-stream.ts` (SSE connection), `use-org-context.ts` (multi-tenant org switching)

**`client/src/lib/`:**
- Purpose: Non-React utility code
- Contains: API client, feature flags, i18n, CSS utilities
- Key files: `queryClient.ts` (TanStack Query config, `apiRequest()`, CSRF handling, envelope unwrapping), `utils.ts` (Tailwind `cn()` helper), `feature-flags.ts`, `i18n.ts`

**`server/routes/`:**
- Purpose: All HTTP endpoint definitions, organized by domain
- Contains: ~110 route files, each exporting `register*Routes(app: Express): void`
- Key files: `index.ts` (central registrar), `shared.ts` (shared utilities, rate limiters, API key auth, webhook signature verification, idempotency), `alerts.ts`, `incidents.ts`, `ingestion.ts`, `health.ts`

**`server/auth/`:**
- Purpose: Authentication system
- Contains: Passport.js setup, session management, auth-specific routes and storage
- Key files: `session.ts` (Passport strategies, `isAuthenticated` middleware), `routes.ts` (login/register/logout/OAuth), `storage.ts` (user CRUD for auth)

**`server/ai/`:**
- Purpose: AI/ML subsystem for analysis, investigation, detection
- Contains: 11 modules covering autonomous analysis, budget tracking, prompt management, model routing
- Key files: `model-gateway.ts`, `investigation-runner.ts`, `autonomous-analyst.ts`, `prompt-registry.ts`, `budget.ts`

**`server/connectors/`:**
- Purpose: Pull-based security tool connector plugins
- Contains: 25 connector implementations plus plugin interface and registry
- Key files: `connector-plugin.ts` (interface), `registry.ts` (plugin registration), individual connectors (e.g., `crowdstrike.ts`, `splunk.ts`, `wazuh.ts`, `elastic.ts`)

**`server/middleware/`:**
- Purpose: Express middleware for cross-cutting concerns
- Contains: 8 middleware modules
- Key files: `org-rate-limit.ts`, `security-policy-enforcement.ts`, `plan-enforcement.ts`, `super-admin.ts`

**`shared/`:**
- Purpose: Code imported by both client and server
- Contains: Database schema, types, validation schemas, constants
- Key files: `schema.ts` (12,814 lines -- all table definitions, Zod schemas, enums), `models/auth.ts` (user/session tables)

**`k8s/`:**
- Purpose: Kubernetes deployment manifests
- Contains: Base resources and environment-specific overlays (staging, UAT, production), Argo Rollouts canary configs, Prometheus/Grafana monitoring
- Key files: `base/`, `production/`, `argo-rollouts/`

**`migrations/`:**
- Purpose: Drizzle ORM database migrations
- Contains: SQL migration files generated by `drizzle-kit`
- Generated: Yes (via `drizzle-kit generate`)
- Committed: Yes

## Key File Locations

**Entry Points:**
- `server/index.ts`: Server bootstrap, middleware stack, background service startup
- `client/src/App.tsx`: React app root, routing, auth gating, provider hierarchy
- `server/routes.ts`: Top-level route registration entry point
- `server/routes/index.ts`: Central domain route registrar (all ~110 route files)

**Configuration:**
- `server/config.ts`: Zod-validated config parsed from environment variables
- `tsconfig.json`: TypeScript compiler configuration
- `vite.config.ts`: Vite build/dev server configuration
- `vitest.config.ts`: Test runner configuration
- `drizzle.config.ts`: Drizzle ORM / migration configuration
- `tailwind.config.ts`: Tailwind CSS configuration
- `eslint.config.js`: ESLint rules
- `commitlint.config.js`: Conventional commit enforcement
- `playwright.config.ts`: E2E test configuration

**Core Logic:**
- `server/storage.ts`: All database query methods (6,222 lines)
- `server/ai.ts`: Primary AI orchestration (71KB)
- `server/connector-engine.ts`: Connector sync orchestration
- `server/correlation-engine.ts`: Alert correlation
- `server/graph-correlation.ts`: Graph-based entity correlation
- `server/normalizer.ts`: Alert normalization across sources
- `server/entity-resolver.ts`: Entity extraction and resolution
- `server/rbac.ts`: RBAC middleware
- `server/api-response.ts`: Canonical API envelope types and helpers
- `server/event-bus.ts`: SSE real-time event bus

**Database:**
- `server/db.ts`: PostgreSQL connection pool + Drizzle ORM instance
- `shared/schema.ts`: All table definitions (12,814 lines)
- `shared/models/auth.ts`: User, session, impersonation tables

**Testing:**
- `server/__tests__/`: Server-side unit tests
- `e2e/`: Playwright E2E tests
- `vitest.config.ts`: Unit test runner config
- `playwright.config.ts`: E2E test config

## Naming Conventions

**Files:**
- `kebab-case.ts` / `kebab-case.tsx`: All source files use kebab-case (e.g., `alert-detail.tsx`, `use-auth.ts`, `api-response.ts`)
- Page files match their URL path: `/alerts` -> `alerts.tsx`, `/entity-graph` -> `entity-graph.tsx`
- Hook files prefixed with `use-`: `use-auth.ts`, `use-event-stream.ts`
- Route files match their domain: `alerts.ts`, `incidents.ts`, `connectors.ts`
- Engine files suffixed with `-engine.ts`: `correlation-engine.ts`, `connector-engine.ts`, `predictive-engine.ts`

**Directories:**
- `kebab-case`: All directories use kebab-case
- Domain grouping: `connectors/`, `cloud-connectors/`, `integrations/`, `native-detections/`

**Exports:**
- Route modules: `export function register*Routes(app: Express): void`
- Hooks: `export function use*(): ReturnType`
- Pages: `export default` (for lazy loading)
- Storage: Single `export const storage` singleton

## Where to Add New Code

**New API Endpoint (existing domain):**
- Add handler to the appropriate file in `server/routes/*.ts`
- Add any new DB queries to `server/storage.ts`
- Add any new table columns to `shared/schema.ts`

**New API Domain (new feature area):**
- Create `server/routes/my-feature.ts` exporting `registerMyFeatureRoutes(app: Express)`
- Import and call it in `server/routes/index.ts`
- Add storage methods to `server/storage.ts`
- Add schema to `shared/schema.ts` if new tables needed

**New Page:**
- Create `client/src/pages/my-feature.tsx` with default export
- Add lazy import in `client/src/App.tsx`: `const MyFeaturePage = lazy(() => import("@/pages/my-feature"))`
- Add Route in the `<Switch>` block of `AuthenticatedApp`
- Add sidebar link in `client/src/components/app-sidebar.tsx`

**New Reusable Component:**
- Create `client/src/components/my-component.tsx`
- For shadcn/ui primitives: add to `client/src/components/ui/`

**New Hook:**
- Create `client/src/hooks/use-my-hook.ts`

**New Connector Plugin:**
- Create `server/connectors/my-connector.ts` implementing `ConnectorPlugin` interface
- Register in `server/connectors/registry.ts`
- Add connector type to `CONNECTOR_TYPES` array in `shared/schema.ts`

**New Background Service:**
- Create `server/my-scheduler.ts` with `start*()` and `stop*()` exports
- Start in `server/index.ts` after `httpServer.listen()`
- Register shutdown handler via `registerShutdownHandler()`

**New Middleware:**
- Create `server/middleware/my-middleware.ts`
- Apply in `server/index.ts` (global) or in specific route files (per-route)

**New Engine/Business Logic:**
- Create `server/my-engine.ts` at the server root level
- Import from route handlers as needed

**Database Migrations:**
- Modify tables in `shared/schema.ts`
- Run `npx drizzle-kit generate` to create migration
- Migration files land in `migrations/`

## Special Directories

**`migrations/`:**
- Purpose: SQL migration files for database schema changes
- Generated: Yes (via `drizzle-kit generate`)
- Committed: Yes

**`k8s/`:**
- Purpose: Kubernetes deployment manifests for EKS
- Generated: No (hand-maintained)
- Committed: Yes

**`.github/workflows/`:**
- Purpose: CI/CD pipeline definitions
- Generated: No
- Committed: Yes

**`client/src/components/ui/`:**
- Purpose: shadcn/ui component primitives
- Generated: Partially (via `npx shadcn-ui add`)
- Committed: Yes (customized after generation)

**`.planning/`:**
- Purpose: Planning and analysis documents for development workflow
- Generated: By development tooling
- Committed: Yes

---

*Structure analysis: 2026-03-25*
