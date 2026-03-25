# Coding Conventions

**Analysis Date:** 2026-03-25

## Naming Patterns

**Files:**
- Server route modules: `kebab-case.ts` (e.g., `server/routes/threat-intel.ts`, `server/routes/entity-graph-advanced.ts`)
- Server service modules: `kebab-case.ts` (e.g., `server/correlation-engine.ts`, `server/outbound-security.ts`)
- Client pages: `kebab-case.tsx` (e.g., `client/src/pages/alert-detail.tsx`, `client/src/pages/threat-intel.tsx`)
- Client hooks: `use-kebab-case.ts` (e.g., `client/src/hooks/use-auth.ts`, `client/src/hooks/use-org-context.ts`)
- Client components: `kebab-case.tsx` (e.g., `client/src/components/app-sidebar.tsx`, `client/src/components/error-boundary.tsx`)
- Shared schema: `shared/schema.ts` (single monolithic file) with sub-models in `shared/models/`
- Test files: `{module-name}.test.ts` or `{module-name}.integration.test.ts` inside `server/__tests__/`

**Functions:**
- Use `camelCase` for all functions and methods
- Route registration: `registerXxxRoutes(app: Express)` pattern (e.g., `registerAlertsRoutes`, `registerConnectorsRoutes`)
- Storage methods: `verbNoun` pattern (e.g., `storage.getAlert()`, `storage.createAlert()`, `storage.updateConnectorJobRun()`)
- Middleware factories: `requireXxx()` returns middleware (e.g., `requireOrgId`, `requirePermission("scope", "action")`, `requireMinRole("admin")`)
- API response helpers: `replyXxx()` pattern (e.g., `replyError`, `replyBadRequest`, `replyNotFound`, `replyForbidden`)

**Variables:**
- Use `camelCase` for variables and parameters
- Constants: `UPPER_SNAKE_CASE` for module-level constants (e.g., `ERROR_CODES`, `ALERT_SEVERITIES`, `ROLE_HIERARCHY`, `LEGACY_SUNSET_DATE`)
- Enum-like arrays: `const XXXX_YYYY = [...] as const` pattern (e.g., `ALERT_STATUSES`, `CONNECTOR_TYPES`)

**Types:**
- Use `PascalCase` for interfaces and types
- Drizzle schema types: `type Alert`, `type InsertAlert` derived from table schemas
- Zod schemas: `camelCase` with `Schema` suffix (e.g., `insertAlertSchema`, `paginationSchema`)
- API types: `ApiEnvelope<T>`, `ApiError`, `ApiMeta`, `ErrorCode`

## Code Style

**Formatting:**
- Prettier with config at `.prettierrc`
- Double quotes (not single quotes): `"singleQuote": false`
- Semicolons required: `"semi": true`
- Trailing commas everywhere: `"trailingComma": "all"`
- Print width: 120 characters
- Tab width: 2 spaces
- Arrow parens always: `(x) => x`
- End of line: LF

**Linting:**
- ESLint with flat config at `eslint.config.js`
- TypeScript ESLint recommended rules
- `@typescript-eslint/no-unused-vars`: warn (prefix unused with `_`)
- `@typescript-eslint/no-explicit-any`: warn (widely used via `(req as any)`)
- `no-console`: warn (only `console.warn` and `console.error` allowed; use `logger` instead)
- React hooks rules enforced for client code
- React Refresh plugin for client

**Pre-commit:**
- Husky + lint-staged
- On `*.{ts,tsx}`: runs `eslint --quiet` and `prettier --check`
- On `*.{json,md,yml,yaml}`: runs `prettier --check`

**Commit Messages:**
- Conventional Commits enforced via `commitlint.config.js`
- Allowed types: `feat`, `fix`, `chore`, `docs`, `test`, `refactor`, `perf`, `ci`, `build`, `style`, `revert`
- Subject must not be empty, type must not be empty

## Import Organization

**Order:**
1. Node.js built-ins (e.g., `crypto`, `async_hooks`)
2. External packages (e.g., `express`, `zod`, `drizzle-orm`)
3. Internal shared (e.g., `@shared/schema`)
4. Internal server modules (e.g., `../storage`, `./shared`, `../rbac`)

**Path Aliases:**
- `@/*` maps to `./client/src/*` (frontend imports)
- `@shared/*` maps to `./shared/*` (shared code)

**Import Style:**
- Use `import type` for type-only imports: `import type { Express, Request, Response } from "express";`
- Named imports preferred over default imports
- Re-exports from barrel files: `server/routes/shared.ts` re-exports common utilities

## Error Handling

**API Response Envelope:**
All API responses use the canonical `ApiEnvelope<T>` from `server/api-response.ts`:
```typescript
{ data: T | null, meta: ApiMeta, errors: ApiError[] | null }
```

**Error Reply Helpers (use these, do not construct raw JSON):**
- `reply(res, data, meta?, status?)` - Success response
- `replyBadRequest(res, message, code?)` - 400
- `replyUnauthenticated(res, message?, code?)` - 401
- `replyForbidden(res, message, code?)` - 403
- `replyNotFound(res, message?, code?)` - 404
- `replyConflict(res, message, code?)` - 409
- `replyValidation(res, errors[])` - 422
- `replyRateLimit(res, message?, code?)` - 429
- `replyInternal(res, message?)` - 500
- `replyNotImplemented(res, message?)` - 501
- `replyUpstream(res, message, details?)` - 502

All defined in `server/api-response.ts`. The convenience wrapper `sendEnvelope()` in `server/routes/shared.ts` delegates to these.

**Error Codes:**
Use `ERROR_CODES` constants from `server/api-response.ts`. Machine-readable strings like `"UNAUTHENTICATED"`, `"FORBIDDEN"`, `"VALIDATION_ERROR"`, `"RATE_LIMITED"`.

**Route Handler Pattern:**
```typescript
app.get("/api/v1/resource", isAuthenticated, validateQuery(querySchemas.xxx), async (req, res) => {
  try {
    const orgId = (req as any).user?.orgId;
    const data = await storage.getResource(orgId);
    return sendEnvelope(res, data, { meta: { total: data.length } });
  } catch (error: any) {
    return sendEnvelope(res, null, {
      status: 500,
      errors: [{ code: "RESOURCE_FETCH_FAILED", message: "Failed to fetch resource", details: error?.message }],
    });
  }
});
```

**Legacy vs V1 Endpoints:**
- Legacy endpoints (e.g., `/api/alerts`) return raw JSON: `res.json(data)`
- V1 endpoints (e.g., `/api/v1/alerts`) return enveloped JSON via `sendEnvelope()`
- New endpoints MUST use the V1 envelope pattern
- Legacy endpoints get deprecation headers via `legacyEndpoint()` middleware from `server/api-response.ts`

**Client-Side Error Handling:**
- `throwIfResNotOk(res)` in `client/src/lib/queryClient.ts` throws on non-2xx responses
- `extractApiError(body, fallback)` extracts human-readable error from envelope
- `ensureArray(val)` safely extracts arrays from enveloped or raw responses

## Logging

**Framework:** Custom structured JSON logger at `server/logger.ts`

**Usage Pattern:**
```typescript
import { logger } from "./logger";

// Create child logger with source tag
const log = logger.child("rbac");

// Log with structured context
log.info("Operation succeeded", { userId, orgId, duration: 42 });
log.warn("Something concerning", { error: String(err) });
log.error("Operation failed", { error: String(err), context: "relevant data" });
```

**Key Rules:**
- Always use `logger` (not `console.log`). ESLint warns on `console`.
- Use `logger.child("source-name")` to tag log entries with a source
- Pass errors as `{ error: String(err) }` in the context object
- Logger auto-redacts sensitive fields (passwords, tokens, API keys, emails)
- Request correlation via `correlationMiddleware` adds `requestId`, `orgId`, `userId` to all logs
- Levels: `debug`, `info`, `warn`, `error`. Production minimum: `info`.

## Comments

**When to Comment:**
- Section dividers use ASCII box comments: `// --- Section Name ---` or `// ─── Section Name ───`
- JSDoc on exported middleware factories explaining usage
- Inline comments for non-obvious business logic
- `eslint-disable` comments at top of test files for `@typescript-eslint/no-explicit-any`

**JSDoc:**
- Used sparingly, mainly on middleware factories and public utilities
- Example from `server/routes/shared.ts`:
```typescript
/**
 * Scope enforcement middleware for API key authenticated routes.
 * Checks that the API key has the required scope(s) before allowing access.
 * Must be used AFTER apiKeyAuth middleware.
 *
 * @param requiredScope - A single scope string (e.g. "ingest:write") or an array
 */
```

## Function Design

**Size:** No explicit limit, but route handlers tend to be 20-50 lines each. Storage functions are small single-query functions.

**Parameters:**
- Express handlers: `(req, res)` or `(req, res, next)` for middleware
- Middleware factories: return `(req, res, next) => void`
- Storage methods: accept typed objects (e.g., `InsertAlert`, `InsertIncident`)
- Use Zod `.safeParse()` for request body validation

**Return Values:**
- Route handlers return `Response` via `res.json()` / `sendEnvelope()` / `replyXxx()`
- Storage methods return typed results (e.g., `Promise<Alert>`, `Promise<Alert[]>`)
- Middleware calls `next()` on success, returns error response on failure

## Module Design

**Route Module Pattern:**
Each domain has a dedicated route file in `server/routes/` exporting a single registration function:
```typescript
// server/routes/alerts.ts
export function registerAlertsRoutes(app: Express): void {
  app.get("/api/alerts", isAuthenticated, async (req, res) => { ... });
  app.post("/api/alerts", isAuthenticated, resolveOrgContext, requireOrgId, async (req, res) => { ... });
}
```

**Shared Route Utilities:**
Common imports are re-exported from `server/routes/shared.ts`:
- `storage` - database access
- `logger` - structured logging
- `sendEnvelope` - envelope response helper
- `reply`, `replyError`, `replyForbidden`, etc. - error helpers
- `p()` - param string extractor
- `getOrgId()` - org context extractor
- `apiKeyAuth`, `requireScope`, `verifyWebhookSignature` - auth middleware
- Rate limiters: `generalLimiter`, `strictLimiter`, `ingestionLimiter`

**Barrel File:**
`server/routes/index.ts` registers all domain routes via `registerAllDomainRoutes(app)`.

**Exports:**
- Default exports for React page components (used with `lazy()`)
- Named exports for everything else

## Request Validation

**Framework:** Zod schemas in `server/request-validator.ts`

**Pattern:**
```typescript
import { validateBody, validateQuery, validatePathId, querySchemas, bodySchemas } from "../request-validator";

// Validate query parameters
app.get("/api/v1/alerts", isAuthenticated, validateQuery(querySchemas.alertsList), async (req, res) => {
  const { offset, limit, search } = (req as any).validatedQuery;
  // ...
});

// Validate path parameter is valid ID
app.get("/api/alerts/:id", isAuthenticated, validatePathId("id"), async (req, res) => { ... });

// Validate request body
app.post("/api/resource", isAuthenticated, validateBody(bodySchemas.createResource), async (req, res) => { ... });
```

Validated data is attached to `(req as any).validatedQuery` or `(req as any).validatedBody`.

## Middleware Chaining

**Standard middleware chain for protected, org-scoped routes:**
```typescript
app.post(
  "/api/resource",
  isAuthenticated,         // Session auth check
  resolveOrgContext,       // Resolve org from session/header
  requireOrgId,            // Ensure org context exists
  requirePermission("scope", "action"),  // RBAC check
  enforcePlanLimit("resource_type"),     // Plan limits
  async (req, res) => { ... }
);
```

**For API-key authenticated routes (ingestion):**
```typescript
app.post(
  "/api/ingest/alert",
  apiKeyAuth,              // API key validation
  requireScope("ingest:write"),  // Scope check
  verifyWebhookSignature,  // Optional webhook sig verification
  ingestionLimiter,        // Rate limiting
  async (req, res) => { ... }
);
```

## Frontend Patterns

**Page Components:**
- All pages use default exports (required for `React.lazy()`)
- Lazy-loaded in `client/src/App.tsx`
- Routing via `wouter` `<Switch>` and `<Route>`
- Pages wrap content in layout components from sidebar

**Data Fetching:**
- TanStack Query for all server state
- `getQueryFn({ on401: "throw" | "returnNull" })` as default query function
- `apiRequest(method, url, data?)` for mutations (auto-attaches CSRF token and org context)
- `fetchPaginated<T>(basePath, params)` for paginated endpoints
- `ensureArray(data)` to safely handle envelope/raw array responses

**State Management:**
- Server state: TanStack Query (no local copy)
- Auth state: `useAuth()` hook at `client/src/hooks/use-auth.ts`
- Org context: `useOrgContextProvider()` + `OrgContext` at `client/src/hooks/use-org-context.ts`
- Theme: `ThemeProvider` at `client/src/components/theme-provider.tsx`
- Org ID persisted in `localStorage` as `securenexus.activeOrgId`

**UI Components:**
- shadcn/ui components in `client/src/components/ui/`
- Icons from `lucide-react`
- Styling with TailwindCSS
- Class merging with `clsx` + `tailwind-merge`

## Database Patterns

**ORM:** Drizzle ORM with PostgreSQL

**Schema Definition (in `shared/schema.ts`):**
```typescript
export const alerts = pgTable("alerts", {
  id: uuid("id").defaultRandom().primaryKey(),
  orgId: text("org_id"),
  title: text("title").notNull(),
  severity: text("severity").notNull(),
  // ...
}, (table) => [
  index("idx_alerts_org_id").on(table.orgId),
]);
```

**Insert Schemas:** Generated via `createInsertSchema(table)` from `drizzle-zod`

**Storage Layer:**
All database queries go through `server/storage.ts` which exports a `storage` object with methods like:
- `storage.getAlert(id)` / `storage.createAlert(data)` / `storage.updateAlert(id, data)`
- `storage.getAlertsPaginatedWithSort({ orgId, offset, limit, ... })`
- Always filter by `orgId` for tenant isolation

## Security Conventions

**Org Isolation:** Every data query MUST include `orgId` filter. Use `getOrgId(req)` or `(req as any).orgId`.

**RBAC:** Apply via middleware chain: `resolveOrgContext` -> `requireOrgId` -> `requirePermission(scope, action)` or `requireMinRole(role)`.

**CSRF:** Non-GET requests require `X-CSRF-Token` header. Client fetches token from `/api/csrf-token`.

**API Keys:** SHA-256 hashed before storage. Prefixed with `snx_`. Secret fields redacted in logs and responses.

**Audit Logging:** Security-relevant actions logged via `storage.createAuditLog()`. Fire-and-forget with `.catch()`.

---

*Convention analysis: 2026-03-25*
