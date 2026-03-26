---
phase: 02-dependency-security-build-hardening
plan: 01
subsystem: security
tags: [xmldom, stripe, drizzle, migration, saml, dependency-upgrade]

# Dependency graph
requires:
  - phase: 01-prerequisite-safety-fixes
    provides: structured logging and type safety foundations
provides:
  - xmldom 0.9.x with SAML undefined guard for safe XML parsing
  - ai_inference_log Drizzle schema definition for type-safe queries
  - idempotent migration for ai_inference_log table
  - zero npm audit high/critical vulnerabilities
affects: [03-god-file-decomposition, 04-logging-replacement]

# Tech tracking
tech-stack:
  added: []
  patterns: [IF NOT EXISTS idempotent migration pattern, xmldom 0.9 undefined guard pattern]

key-files:
  created:
    - migrations/0003_hard_george_stacy.sql
    - migrations/meta/0003_snapshot.json
  modified:
    - package.json
    - package-lock.json
    - server/routes/sso.ts
    - shared/schema.ts
    - server/ai.ts
    - migrations/meta/_journal.json

key-decisions:
  - "Cast xmldom Document to globalThis.Node via unknown for xml-crypto compatibility (xmldom 0.9 types diverge from DOM spec)"
  - "Manually trimmed drizzle-kit migration to only ai_inference_log table (drizzle-kit generated full schema diff)"
  - "Used IF NOT EXISTS for both table and indexes since table already exists in production from runtime DDL"

patterns-established:
  - "Idempotent migrations: always use IF NOT EXISTS for tables that may already exist from runtime DDL"

requirements-completed: [SEC-01, SEC-02, SEC-03, SEC-05]

# Metrics
duration: 9min
completed: 2026-03-25
---

# Phase 02 Plan 01: Dependency Security and Build Hardening Summary

**Upgraded xmldom to 0.9.x with SAML undefined guard, resolved all npm audit high/critical vulns, and migrated ai_inference_log from runtime DDL to Drizzle-managed schema**

## Performance

- **Duration:** 9 min
- **Started:** 2026-03-25T10:05:58Z
- **Completed:** 2026-03-25T10:15:08Z
- **Tasks:** 2
- **Files modified:** 7

## Accomplishments
- Upgraded @xmldom/xmldom from ^0.8.11 to ^0.9.8 and added undefined guard for SAML XML parsing safety
- Resolved all 9 npm audit vulnerabilities (multer DoS, qs bypass, rollup path traversal) down to 0
- Moved ai_inference_log table from runtime CREATE TABLE in ai.ts to proper Drizzle schema with idempotent migration
- Removed all runtime DDL (ensureInferenceTable function and 4 call sites) from server/ai.ts

## Task Commits

Each task was committed atomically:

1. **Task 1: Upgrade dependencies and harden xmldom/SAML parsing** - `2321558` (feat)
2. **Task 2: Move ai_inference_log from runtime DDL to Drizzle migration** - `e24279c` (feat)

## Files Created/Modified
- `package.json` - Updated xmldom to ^0.9.8, stripe to ^20.4.1, fixed audit vulns
- `package-lock.json` - Lock file updated with resolved dependencies
- `server/routes/sso.ts` - Added undefined guard after DOMParser.parseFromString, cast for xmldom 0.9 type compat
- `shared/schema.ts` - Added serial import, aiInferenceLog table definition with 3 indexes
- `server/ai.ts` - Removed ensureInferenceTable() function, INFERENCE_TABLE_ENSURED const, and all 4 call sites
- `migrations/0003_hard_george_stacy.sql` - Idempotent CREATE TABLE IF NOT EXISTS with 3 indexes
- `migrations/meta/_journal.json` - Updated with migration entry idx 3
- `migrations/meta/0003_snapshot.json` - Drizzle schema snapshot

## Decisions Made
- Used `as unknown as globalThis.Node` cast for xmldom 0.9 Document type since xmldom 0.9 types no longer extend globalThis.Node but xml-crypto expects it
- Manually trimmed drizzle-kit generated migration (1035 lines covering all missing tables) down to just the ai_inference_log table (22 lines) since other tables are managed elsewhere
- Used IF NOT EXISTS for both table and indexes to ensure migration is idempotent on databases where runtime DDL already created the table

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] xmldom 0.9 Document type incompatibility with xml-crypto**
- **Found during:** Task 1 (xmldom upgrade)
- **Issue:** xmldom 0.9 Document type no longer extends globalThis.Node, causing TS error when passed to findSignatureNode()
- **Fix:** Added `as unknown as globalThis.Node` cast at the call site
- **Files modified:** server/routes/sso.ts
- **Verification:** npx tsc --noEmit shows no sso.ts errors
- **Committed in:** 2321558 (Task 1 commit)

**2. [Rule 1 - Bug] npm audit vulnerabilities in multer, qs, rollup**
- **Found during:** Task 1 (npm audit check)
- **Issue:** 9 vulnerabilities (6 high) in multer (DoS), qs (arrayLimit bypass), rollup (path traversal)
- **Fix:** Ran npm audit fix which updated multer, qs, and rollup to patched versions
- **Files modified:** package.json, package-lock.json
- **Verification:** npm audit --audit-level=high reports 0 vulnerabilities
- **Committed in:** 2321558 (Task 1 commit)

**3. [Rule 3 - Blocking] drizzle-kit generated full schema diff instead of targeted migration**
- **Found during:** Task 2 (migration generation)
- **Issue:** drizzle-kit generate produced 1035-line migration creating ~200 tables it saw as missing from DB
- **Fix:** Manually replaced generated SQL with focused 22-line ai_inference_log migration using IF NOT EXISTS
- **Files modified:** migrations/0003_hard_george_stacy.sql
- **Verification:** grep confirms IF NOT EXISTS present 4 times (1 table + 3 indexes)
- **Committed in:** e24279c (Task 2 commit)

---

**Total deviations:** 3 auto-fixed (1 bug, 2 blocking)
**Impact on plan:** All auto-fixes necessary for correctness and task completion. No scope creep.

## Issues Encountered
- Pre-existing TypeScript errors in server/ai.ts (string|null vs string|undefined, ~18 errors) and server/graph-correlation.ts (~15 errors) are unrelated to this plan's changes and remain unchanged

## Known Stubs
None - no stubs introduced.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Dependencies are up to date with zero high/critical audit findings
- ai_inference_log is now managed by Drizzle ORM schema, ready for type-safe query migration in future phases
- SAML parsing is hardened against xmldom 0.9 breaking changes

---
*Phase: 02-dependency-security-build-hardening*
*Completed: 2026-03-25*
