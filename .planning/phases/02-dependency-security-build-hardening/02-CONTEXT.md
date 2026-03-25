# Phase 2: Dependency Security & Build Hardening - Context

**Gathered:** 2026-03-25
**Status:** Ready for planning

<domain>
## Phase Boundary

Upgrade vulnerable dependencies, move runtime DDL to proper Drizzle migrations, and implement API key rotation with grace period. This phase eliminates known security vulnerabilities and build-time hacks before structural changes begin.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion
All implementation choices are at Claude's discretion — infrastructure/security phase. Key guidance:
- Upgrade @xmldom to 1.0.0+ with strict DTD disabling
- Upgrade passport-github2 and passport-google-oauth20 to latest stable
- Upgrade Stripe SDK to latest stable
- Move ai_inference_log CREATE TABLE from runtime ai.ts to Drizzle migration
- API key rotation: generate new key, deprecate old with 24h grace period, soft-delete
- Run npm audit after upgrades to verify no high/critical findings remain
- Test OAuth flows still work after passport upgrades
- Preserve existing API contracts — no breaking changes

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `shared/schema.ts` — Contains all Drizzle table definitions and Zod schemas
- `server/db.ts` — Drizzle ORM connection and pool setup
- `server/auth/session.ts` — OAuth strategy configuration (Google, GitHub)
- `server/routes.ts` — API key endpoints

### Established Patterns
- Drizzle ORM for all database operations
- Drizzle Kit for migration generation (`npx drizzle-kit generate`)
- API key auth via X-API-Key header with SHA-256 hashing
- Passport.js strategies for OAuth

### Integration Points
- `server/ai.ts` — Contains runtime CREATE TABLE for ai_inference_log (to be moved to migration)
- `server/auth/session.ts` — passport-google-oauth20 and passport-github2 usage
- `package.json` — Dependency versions for @xmldom, passport-*, stripe
- `shared/schema.ts` — Where ai_inference_log table definition should live

</code_context>

<specifics>
## Specific Ideas

No specific requirements beyond the SEC-01 through SEC-05 scope.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>
