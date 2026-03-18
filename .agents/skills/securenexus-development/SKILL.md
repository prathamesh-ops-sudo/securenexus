# SecureNexus Development Skills

## Architecture Overview
- **Stack**: React (Vite) + Express + PostgreSQL + Drizzle ORM
- **Client**: `client/src/` — React SPA with shadcn/ui components, TanStack Query, wouter routing
- **Server**: `server/` — Express with TypeScript, session-based auth, CSRF protection
- **Shared**: `shared/` — Shared schema types between client and server
- **Monorepo**: Single `package.json` at root, `npm run dev` starts both client and server

## Key Conventions

### Frontend Patterns
- All API responses are wrapped in `{ data, meta, errors }` envelope — use `apiRequest()` from `@/lib/queryClient` which auto-unwraps
- Use `ensureArray()` for defensive array handling from API responses
- Pages are in `client/src/pages/` — one file per feature (e.g., `dashboard.tsx`, `alerts.tsx`)
- Components use shadcn/ui primitives from `@/components/ui/`
- Auth hook: `useAuth()` from `@/hooks/use-auth`
- Page title: `usePageTitle()` from `@/hooks/use-page-title`
- i18n formatting: `formatDateTime()`, `formatChartDateLabel()`, `formatTime()` from `@/lib/i18n`
- Charts use Recharts with theme-aware CSS variables: `hsl(var(--border))`, `hsl(var(--muted-foreground))`, `hsl(var(--background))`
- Dark mode: Use Tailwind `dark:` variants and CSS variables — never hardcode `#fff` or `#000` in chart configs

### Backend Patterns
- Routes registered in `server/routes/` — each domain has its own file
- Multi-tenant: Every query MUST include `org_id` filter via `getOrgId(req)`
- Auth middleware chain: `isAuthenticated, resolveOrgContext, requireOrgId`
- CSRF: Non-GET requests need CSRF token (handled by `apiRequest()` on frontend)
- Caching: Use `cacheGetOrLoad()` with `buildCacheKey()` from `../query-cache`
- Storage layer: `storage.getX(orgId)` methods in `server/storage.ts`

### Widget/Dashboard Patterns
- Widget config stored in localStorage via `loadWidgetConfig()`/`saveWidgetConfig()`
- Widget types: `WidgetId` union type, `WidgetConfig` with id/label/visible/pinned/order
- Drag-and-drop: Uses `@dnd-kit/sortable` with `SortableWidget` wrapper
- Per-widget skeletons: `WidgetSkeleton` component for independent loading states
- Keyboard shortcuts: Global listener in Dashboard, guards against input/textarea focus

## Development Commands
- `npm run dev` — Start dev server (client + server)
- `npx tsc --noEmit` — TypeScript typecheck
- Pre-commit hooks: eslint + prettier (via lint-staged)
- No test suite currently configured

## Environment Setup
- Copy `.env` from template, needs DATABASE_URL for PostgreSQL
- Google OAuth configured for auth
- AWS SES for emails (staging uses sandbox mode)
- Staging: https://staging.aricatech.xyz (CloudFront + App Runner)

## Git Conventions
- Branch naming: `devin/{timestamp}-{descriptive-slug}`
- Never force push, never amend commits
- Use `git add` with specific files only
- Pre-commit hooks run eslint and prettier automatically

## Common Gotchas
- API envelope: Always check if response is wrapped in `{ data }` — use `ensureArray()` or `apiRequest()` 
- CSRF token: Mutations fail without it — `apiRequest()` handles this automatically
- Org context: Every API call needs `X-Org-Id` header (handled by `apiRequest()` and `getQueryFn()`)
- Chart theme: Use `hsl(var(--background))` not `#fff` for activeDot strokes in dark mode
- Widget order: `widgetConfig` array order determines render order after drag-and-drop
