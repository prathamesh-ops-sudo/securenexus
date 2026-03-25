# Phase 2: Dependency Security & Build Hardening - Research

**Researched:** 2026-03-25
**Domain:** Dependency upgrades, database migration management, API key lifecycle
**Confidence:** HIGH

## Summary

Phase 2 addresses five security requirements across three distinct domains: (1) upgrading vulnerable or stale dependencies (@xmldom/xmldom, passport-github2, passport-google-oauth20, Stripe SDK), (2) moving runtime DDL from server/ai.ts to a proper Drizzle migration, and (3) implementing API key rotation with a 24-hour grace period.

The dependency situation is nuanced. passport-github2 (0.1.12) and passport-google-oauth20 (2.0.0) are both effectively unmaintained (last published 6+ years ago) with no newer versions available. The upgrade requirement for these must be interpreted as "verify compatibility, harden configuration, and ensure current usage is secure" rather than bumping to a newer version that does not exist. @xmldom/xmldom has a 0.9.x series available but it is NOT tagged as `latest` on npm (0.8.11 is latest); the requirement mentions "1.0.0+" which does not exist. The practical path is upgrading to 0.9.8 with strict DTD/entity processing disabled. Stripe SDK is already at 20.4.0 and can be bumped to 20.4.1 (minor patch).

**Primary recommendation:** Split into 3 plans: (1) dependency upgrades with xmldom 0.9 migration + Stripe patch, (2) ai_inference_log Drizzle migration, (3) API key rotation endpoint with grace period schema changes.

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| SEC-01 | Upgrade @xmldom to 1.0.0+ with strict DTD disabling | 1.0.0 does not exist. Upgrade to 0.9.8 (latest non-beta). Breaking changes documented below: DOMParser.parseFromString returns Document or undefined, stricter XML validation. Only used in server/routes/sso.ts for SAML signature verification. |
| SEC-02 | Upgrade passport-github2 and passport-google-oauth20 to latest with end-to-end OAuth flow testing | Both packages are at their latest versions already (0.1.12 and 2.0.0 respectively, last published 6+ years ago). Task becomes: verify current usage is secure, add DTD/entity hardening, and write OAuth flow smoke tests. |
| SEC-03 | Upgrade Stripe SDK to latest stable | Currently at ^20.4.0 in package.json, latest is 20.4.1. Minor patch bump. Verify apiVersion alignment. |
| SEC-04 | API key rotation endpoint with 24h grace period and soft-delete | Existing schema has apiKeys table with isActive/revokedAt. Need to add: replacedByKeyId, deprecatedAt, graceExpiresAt columns. New POST /api/api-keys/:id/rotate endpoint. Modify apiKeyAuth to accept deprecated keys within grace window. |
| SEC-05 | Move ai_inference_log CREATE TABLE from runtime ai.ts to Drizzle migration | Runtime DDL at server/ai.ts:60-83 creates table + 3 indexes via raw SQL. Must add Drizzle schema definition in shared/schema.ts and generate migration. Remove ensureInferenceTable() function. |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| @xmldom/xmldom | 0.9.8 | XML/SAML parsing | Latest in 0.9 series. Stricter XML validation, returns undefined on malformed XML (security improvement for SAML). Not tagged `latest` on npm but stable release series. |
| passport-github2 | 0.1.12 (current) | GitHub OAuth | Latest available. Package unmaintained since 2019 but functional. No upgrade available. |
| passport-google-oauth20 | 2.0.0 (current) | Google OAuth | Latest available. Package unmaintained since 2018 but functional. No upgrade available. |
| stripe | ^20.4.1 | Payment processing | Latest stable. Minor patch from current 20.4.0. |
| drizzle-orm | 0.39.3 (current) | ORM + migrations | Already in use. Used for schema definition and migration generation. |
| drizzle-kit | 0.31.8 (current) | Migration tooling | Already in use. `drizzle-kit generate` creates migration SQL. |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| vitest | 4.x (current) | Testing | Write smoke tests for OAuth flow and API key rotation |
| zod | 3.24.x (current) | Validation | Validate rotation request body |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| passport-github2 | @octokit/auth-oauth-user | Would require rewriting entire GitHub auth flow. passport-github2 works and has same API surface. Not worth the risk in a hardening phase. |
| passport-google-oauth20 | google-auth-library | Same concern. Working auth flow, rewrite risk outweighs benefits. |
| @xmldom/xmldom 0.9.8 | Stay on 0.8.11 | 0.8.11 works but 0.9.x has stricter parsing which is a security improvement for SAML handling. Worth the migration effort. |

## Architecture Patterns

### Drizzle Migration Pattern (for SEC-05)

The project uses Drizzle Kit for migrations with this workflow:
1. Define table in `shared/schema.ts` using `pgTable()`
2. Run `drizzle-kit generate` to create SQL migration in `./migrations/`
3. Run `tsx scripts/migrate.ts` to apply migrations
4. Migration journal tracked in `migrations/meta/_journal.json`

Current state: 3 migrations exist (0000, 0001, 0002). The next migration will be 0003.

### API Key Auth Flow (for SEC-04)

Current flow in `server/routes/shared.ts`:
```
Request → apiKeyAuth middleware → hashApiKey(header) → storage.getApiKeyByHash(hash) → check isActive → attach orgId
```

For rotation with grace period, the auth flow must be extended:
```
Request → apiKeyAuth middleware → hashApiKey(header) → storage.getApiKeyByHash(hash)
  → if active: allow
  → if deprecated AND graceExpiresAt > now(): allow (with deprecation warning header)
  → if revoked or grace expired: reject
```

### API Key Rotation Flow (for SEC-04)

```
POST /api/api-keys/:id/rotate
  1. Verify old key exists and is active
  2. Generate new key (generateApiKey())
  3. Create new key record linked to old key
  4. Mark old key as deprecated (not revoked) with graceExpiresAt = now + 24h
  5. Return new key (shown once) + deprecation info for old key
  6. Write audit log entry
```

### Anti-Patterns to Avoid
- **Runtime DDL:** Never create tables at runtime (the exact problem SEC-05 fixes). All schema changes go through Drizzle migrations.
- **Hard revoke on rotation:** Never immediately revoke old keys. Consumers need the grace period to update.
- **Upgrading unmaintained packages by force:** passport-github2 and passport-google-oauth20 have no newer versions. Attempting `npm update` achieves nothing.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Migration generation | Manual SQL files | `drizzle-kit generate` | Drizzle generates correct SQL from schema diff, handles indexes, ensures journal consistency |
| API key hashing | Custom hash function | Existing `hashApiKey()` in shared.ts | Already uses SHA-256, consistent across codebase |
| OAuth strategy configuration | New auth library | Existing passport strategies | Working, tested in production. Hardening is about configuration, not replacement. |

## Common Pitfalls

### Pitfall 1: xmldom 0.9 Breaking Change - parseFromString Returns Undefined
**What goes wrong:** TypeScript compilation fails or runtime null pointer when DOMParser.parseFromString returns undefined for malformed XML.
**Why it happens:** 0.9 changed return type from `Document` to `Document | undefined`. Malformed SAML responses will trigger this.
**How to avoid:** Add null check after parseFromString call in server/routes/sso.ts:68. The existing code already has a try/catch but needs the undefined guard.
**Warning signs:** TypeScript errors on `doc.` property access after upgrade.

### Pitfall 2: xmldom 0.9 Stricter XML Validation
**What goes wrong:** Previously accepted non-well-formed XML now throws errors or returns undefined.
**Why it happens:** 0.9 enforces XML well-formedness more strictly than 0.8.
**How to avoid:** This is actually a security IMPROVEMENT for SAML. Malformed SAML should be rejected. Ensure error handling covers the undefined case gracefully.
**Warning signs:** SAML login failures in testing with edge-case SAML responses.

### Pitfall 3: API Key Grace Period Auth Race Condition
**What goes wrong:** During the 24-hour grace window, both old and new keys work. If not handled carefully, the old key's orgId/scopes may differ from the new key.
**Why it happens:** Rotation could theoretically change scopes between old and new key.
**How to avoid:** Copy scopes from old key to new key during rotation. Grace period only extends authentication, not authorization changes.
**Warning signs:** Different behavior depending on which key a consumer uses during grace window.

### Pitfall 4: ai_inference_log Table Already Exists in Production
**What goes wrong:** Drizzle migration tries to CREATE TABLE but it already exists from runtime DDL.
**Why it happens:** The runtime `ensureInferenceTable()` already created the table in the live database.
**How to avoid:** Use `CREATE TABLE IF NOT EXISTS` in the migration SQL OR use a two-step approach: (1) add schema to shared/schema.ts, (2) generate migration, (3) manually edit the generated SQL to use IF NOT EXISTS, (4) remove runtime DDL from ai.ts.
**Warning signs:** Migration fails on deployed environments but works on fresh databases.

### Pitfall 5: Stripe API Version Mismatch
**What goes wrong:** Upgrading Stripe SDK version without matching apiVersion causes unexpected API behavior changes.
**Why it happens:** Stripe SDK pins an API version. The current code hardcodes `apiVersion: "2025-01-27.acacia"` with a type cast.
**How to avoid:** After upgrading to 20.4.1, check what the new `LatestApiVersion` type expects. The cast `as Stripe.LatestApiVersion` will mask mismatches.
**Warning signs:** TypeScript warning on the `as` cast, or unexpected Stripe API behavior.

## Code Examples

### xmldom 0.9 Migration - SAML Signature Verification
```typescript
// Source: server/routes/sso.ts - BEFORE (0.8.x)
const doc = new DOMParser().parseFromString(xml, "text/xml");
const signatureNode = findSignatureNode(doc);

// AFTER (0.9.x) - handle undefined return
const doc = new DOMParser().parseFromString(xml, "text/xml");
if (!doc) {
  logger.child("sso").warn("Failed to parse SAML XML - malformed document");
  return false;
}
const signatureNode = findSignatureNode(doc);
```

### Drizzle Schema for ai_inference_log (SEC-05)
```typescript
// Add to shared/schema.ts
export const aiInferenceLog = pgTable(
  "ai_inference_log",
  {
    id: serial("id").primaryKey(),
    tier: varchar("tier").notNull(),
    model: varchar("model").notNull(),
    promptId: varchar("prompt_id"),
    promptVersion: integer("prompt_version"),
    inputTokens: integer("input_tokens").notNull().default(0),
    outputTokens: integer("output_tokens").notNull().default(0),
    latencyMs: integer("latency_ms").notNull().default(0),
    costEstimateUsd: doublePrecision("cost_estimate_usd").notNull().default(0),
    cached: boolean("cached").notNull().default(false),
    success: boolean("success").notNull().default(true),
    errorMessage: text("error_message"),
    orgId: varchar("org_id"),
    createdAt: timestamp("created_at").defaultNow(),
  },
  (table) => [
    index("idx_ai_inference_log_tier").on(table.tier),
    index("idx_ai_inference_log_created").on(table.createdAt),
    index("idx_ai_inference_log_org").on(table.orgId),
  ],
);
```

### API Key Rotation Schema Additions
```typescript
// Add to apiKeys table in shared/schema.ts
deprecatedAt: timestamp("deprecated_at"),      // when key was deprecated (rotation triggered)
graceExpiresAt: timestamp("grace_expires_at"), // when grace period ends (deprecatedAt + 24h)
replacedByKeyId: varchar("replaced_by_key_id"),// ID of the replacement key
```

### API Key Auth with Grace Period
```typescript
// Modified apiKeyAuth in server/routes/shared.ts
const apiKey = await storage.getApiKeyByHash(hash);
if (!apiKey) {
  return replyUnauthenticated(res, "Invalid API key.", ERROR_CODES.API_KEY_INVALID);
}
if (apiKey.revokedAt) {
  return replyUnauthenticated(res, "API key has been revoked.", ERROR_CODES.API_KEY_REVOKED);
}
if (!apiKey.isActive && apiKey.deprecatedAt && apiKey.graceExpiresAt) {
  const now = new Date();
  if (now <= apiKey.graceExpiresAt) {
    // Key is deprecated but within grace period - allow with warning
    res.setHeader("X-API-Key-Deprecated", "true");
    res.setHeader("X-API-Key-Expires", apiKey.graceExpiresAt.toISOString());
    // Continue auth flow...
  } else {
    return replyUnauthenticated(res, "API key grace period expired.", ERROR_CODES.API_KEY_EXPIRED);
  }
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| @xmldom/xmldom 0.8.x | 0.9.x series (not tagged latest) | 2024 | Stricter XML parsing, undefined returns, security improvements |
| passport-github2 updates | Package frozen at 0.1.12 | 2019 (last publish) | No updates available. Works but unmaintained. |
| passport-google-oauth20 updates | Package frozen at 2.0.0 | 2018 (last publish) | No updates available. Works but unmaintained. |
| Runtime CREATE TABLE | Drizzle Kit migrations | Project convention | All DDL should go through migration pipeline |

**Deprecated/outdated:**
- passport-github2: Unmaintained since 2019. No alternative in passport ecosystem. Long-term plan should consider direct OAuth2 implementation.
- passport-google-oauth20: Unmaintained since 2018. Same long-term consideration.
- Note: Both packages are feature-complete for their use case and have no known CVEs. "Unmaintained" does not mean "insecure" here.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Vitest 4.x |
| Config file | vitest.config.ts |
| Quick run command | `npx vitest run --reporter=verbose` |
| Full suite command | `npx vitest run --coverage` |

### Phase Requirements to Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| SEC-01 | xmldom upgrade does not break SAML parsing | unit | `npx vitest run server/__tests__/sso-saml.test.ts -x` | No - Wave 0 |
| SEC-02 | OAuth strategies initialize without error | unit | `npx vitest run server/__tests__/oauth-setup.test.ts -x` | No - Wave 0 |
| SEC-03 | Stripe client initializes with updated SDK | unit | `npx vitest run server/__tests__/stripe-service.test.ts -x` | No - Wave 0 |
| SEC-04 | API key rotation creates new key, deprecates old with 24h grace | unit | `npx vitest run server/__tests__/api-key-rotation.test.ts -x` | No - Wave 0 |
| SEC-04 | Deprecated key within grace period authenticates successfully | unit | `npx vitest run server/__tests__/api-key-auth.test.ts -x` | No - Wave 0 |
| SEC-05 | ai_inference_log schema matches runtime DDL columns | unit | `npx vitest run server/__tests__/ai-inference-schema.test.ts -x` | No - Wave 0 |

### Sampling Rate
- **Per task commit:** `npx vitest run --reporter=verbose`
- **Per wave merge:** `npx vitest run --coverage`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `server/__tests__/api-key-rotation.test.ts` -- covers SEC-04 (rotation logic, grace period auth)
- [ ] `server/__tests__/sso-saml.test.ts` -- covers SEC-01 (SAML parsing with xmldom 0.9)
- [ ] No existing test infrastructure for ingestion/api-key routes or SSO module

## Open Questions

1. **xmldom 0.9 vs staying on 0.8.11**
   - What we know: 0.9.8 exists, has stricter XML parsing (security benefit), but is NOT tagged `latest` on npm. The requirement says "1.0.0+" which does not exist.
   - What's unclear: Whether the xmldom maintainers consider 0.9.x production-ready since it's not tagged `latest`.
   - Recommendation: Upgrade to 0.9.8. The stricter parsing is a security improvement for SAML. The SSO module has only one DOMParser usage that needs a simple undefined guard. If any issues arise, the fallback is staying on 0.8.11.

2. **passport-github2 / passport-google-oauth20 "upgrade"**
   - What we know: Both are at their latest versions. No newer versions exist.
   - What's unclear: Whether the requirement intends us to replace these with alternative libraries.
   - Recommendation: Keep current packages. Focus on hardening: verify profile parsing handles edge cases, add smoke tests, ensure callback URLs use HTTPS. Replacement is high-risk and out of scope for a hardening phase.

3. **ai_inference_log migration on existing databases**
   - What we know: Runtime DDL already created this table in production. Drizzle migration will try to CREATE TABLE.
   - What's unclear: Whether `drizzle-kit generate` will detect the table already exists and skip it.
   - Recommendation: After generating migration, manually verify and edit SQL to use `CREATE TABLE IF NOT EXISTS`. This is safe and idempotent.

## Sources

### Primary (HIGH confidence)
- package.json - verified current dependency versions
- server/routes/sso.ts - xmldom usage (DOMParser for SAML)
- server/auth/session.ts - passport strategy configuration
- server/ai.ts:60-83 - runtime DDL for ai_inference_log
- server/routes/ingestion.ts - API key CRUD endpoints
- server/routes/shared.ts - apiKeyAuth middleware, generateApiKey
- shared/schema.ts - apiKeys table definition
- server/storage.ts - getApiKeyByHash, revokeApiKey implementations
- drizzle.config.ts - migration configuration
- migrations/meta/_journal.json - migration journal (3 existing migrations)

### Secondary (MEDIUM confidence)
- [npm @xmldom/xmldom](https://www.npmjs.com/package/@xmldom/xmldom) - version info, dist-tags (latest=0.8.11, lts=0.8.10)
- [xmldom 0.9 release notes](https://dev.to/karfau/release-090-of-xmldomxmldom-4106) - breaking changes documentation
- [npm passport-github2](https://www.npmjs.com/package/passport-github2) - last published 6 years ago, version 0.1.12
- [npm passport-google-oauth20](https://www.npmjs.com/package/passport-google-oauth20) - last published 7 years ago, version 2.0.0
- [npm stripe](https://www.npmjs.com/package/stripe) - latest 20.4.1
- [Stripe releases](https://github.com/stripe/stripe-node/releases) - API version alignment

### Tertiary (LOW confidence)
- None

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - all versions verified against npm registry
- Architecture: HIGH - all patterns derived from direct codebase analysis
- Pitfalls: HIGH - based on documented breaking changes and known migration patterns

**Research date:** 2026-03-25
**Valid until:** 2026-04-25 (stable domain, unmaintained packages won't change)
