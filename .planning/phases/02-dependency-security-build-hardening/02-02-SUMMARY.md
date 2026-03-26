---
phase: 02-dependency-security-build-hardening
plan: 02
subsystem: security
tags: [api-key-rotation, grace-period, auth-middleware, schema-migration]

# Dependency graph
requires:
  - phase: 02-dependency-security-build-hardening
    plan: 01
    provides: base schema and dependency hardening
provides:
  - API key rotation endpoint with 24-hour grace period
  - Deprecated key auth flow with warning headers
  - deprecateApiKey and getApiKeyById storage methods
  - Idempotent migration for api_keys rotation columns
affects: [ingestion-routes, api-key-auth-middleware]

# Tech tracking
tech-stack:
  added: []
  patterns: [API key rotation with grace period deprecation, warning header pattern for deprecated credentials]

key-files:
  created:
    - migrations/0004_nappy_queen_noir.sql
    - migrations/meta/0004_snapshot.json
  modified:
    - shared/schema.ts
    - server/storage.ts
    - server/routes/ingestion.ts
    - server/routes/shared.ts
    - server/api-response.ts
    - migrations/meta/_journal.json

key-decisions:
  - "Updated getApiKeyByHash to remove isActive filter so deprecated keys within grace window can authenticate"
  - "Added X-API-Key-Replacement header pointing to new key ID for consumer convenience"
  - "Used IF NOT EXISTS for migration idempotency matching pattern from 02-01"

patterns-established:
  - "Grace period deprecation: set isActive=false with deprecatedAt+graceExpiresAt instead of hard revoke"
  - "Warning headers on deprecated credentials: X-API-Key-Deprecated, X-API-Key-Expires, X-API-Key-Replacement"

requirements-completed: [SEC-04]

# Metrics
duration: 7min
completed: 2026-03-25
---

# Phase 02 Plan 02: API Key Rotation with Grace Period Summary

**Implemented API key rotation with 24-hour grace period allowing zero-downtime key transitions via POST /api/api-keys/:id/rotate**

## Performance

- **Duration:** 7 min
- **Started:** 2026-03-25T10:17:33Z
- **Completed:** 2026-03-25T10:24:01Z
- **Tasks:** 2
- **Files modified:** 8

## Accomplishments
- Added deprecatedAt, graceExpiresAt, replacedByKeyId columns to apiKeys schema with idempotent migration
- Added getApiKeyById and deprecateApiKey storage methods to the interface and implementation
- Implemented POST /api/api-keys/:id/rotate endpoint that generates new key, deprecates old with 24h grace
- Updated apiKeyAuth middleware to allow deprecated keys within grace window with deprecation warning headers
- Added API_KEY_EXPIRED error code for keys past their grace period
- Updated getApiKeyByHash to return all keys (not just active) so deprecated keys can authenticate during grace

## Task Commits

Each task was committed atomically:

1. **Task 1: Add rotation columns to apiKeys schema and storage methods** - `64b7372` (feat)
2. **Task 2: Implement rotation endpoint and update auth middleware** - `2e11d1d` (feat)

## Files Created/Modified
- `shared/schema.ts` - Added deprecatedAt, graceExpiresAt, replacedByKeyId columns to apiKeys table; updated insertApiKeySchema omit list
- `server/storage.ts` - Added getApiKeyById, deprecateApiKey methods; updated getApiKeyByHash to remove isActive filter; updated interface
- `server/routes/ingestion.ts` - Added POST /api/api-keys/:id/rotate endpoint with audit logging
- `server/routes/shared.ts` - Updated apiKeyAuth for grace period: deprecated keys within window get warning headers, expired keys rejected
- `server/api-response.ts` - Added API_KEY_EXPIRED error code
- `migrations/0004_nappy_queen_noir.sql` - Idempotent ALTER TABLE ADD COLUMN IF NOT EXISTS for 3 new columns
- `migrations/meta/0004_snapshot.json` - Drizzle schema snapshot
- `migrations/meta/_journal.json` - Updated with migration entry idx 4

## Decisions Made
- Updated getApiKeyByHash to remove the `isActive: true` filter because deprecated keys need to authenticate during their grace window. This is a behavioral change: previously only active keys were returned, now all non-null keys are returned and the auth middleware handles status logic.
- Added X-API-Key-Replacement header (in addition to plan-specified X-API-Key-Deprecated and X-API-Key-Expires) to help consumers discover their replacement key ID.
- Used IF NOT EXISTS for migration columns matching the idempotent pattern established in 02-01.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] getApiKeyByHash filtered out deprecated keys**
- **Found during:** Task 1
- **Issue:** getApiKeyByHash had `where(and(eq(apiKeys.keyHash, hash), eq(apiKeys.isActive, true)))` which would prevent deprecated keys from authenticating during grace period
- **Fix:** Removed isActive filter from the query; auth middleware now handles all status checks
- **Files modified:** server/storage.ts
- **Committed in:** 64b7372 (Task 1 commit)

**2. [Rule 2 - Missing functionality] API_KEY_EXPIRED error code missing**
- **Found during:** Task 2
- **Issue:** ERROR_CODES in api-response.ts did not have API_KEY_EXPIRED, needed for grace period expiry
- **Fix:** Added API_KEY_EXPIRED to ERROR_CODES constant
- **Files modified:** server/api-response.ts
- **Committed in:** 2e11d1d (Task 2 commit)

---

**Total deviations:** 2 auto-fixed (1 bug, 1 missing functionality)
**Impact on plan:** Both fixes were necessary for correct grace period behavior. No scope creep.

## Issues Encountered
- Pre-existing TypeScript errors in server/ai.ts and server/graph-correlation.ts remain (unrelated to this plan)
- drizzle-kit requires DATABASE_URL even for generate; used dummy URL as in 02-01

## Known Stubs
None - no stubs introduced.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- API key rotation is fully implemented with zero-downtime grace period
- Auth middleware properly handles the full key lifecycle: active, deprecated (grace), expired, revoked
- Migration is idempotent and safe for production application

---
*Phase: 02-dependency-security-build-hardening*
*Completed: 2026-03-25*
