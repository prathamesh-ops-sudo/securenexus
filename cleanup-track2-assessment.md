# Cleanup Track 2 — Type Consolidation Assessment

**Branch:** `devin/cleanup-track2-types` (from `devin/1775462796-platform-seed`)
**Scope:** Scattered `interface` / `type` / `enum` definitions across `server/`, `client/`, `shared/`
**Approach:** Audit everything, implement only HIGH‑confidence / LOW‑risk consolidations.

## 0. Baseline (before any changes)

Pre-existing failures on the base branch — **not introduced by this track**, must remain ≤ baseline:

- `npm run typecheck` → **3 errors** in 2 files
  - `server/routes/connectors.ts:442` / `:463` — `updateConnectorSyncStatus` missing `lastSyncStatus`
  - `server/routes/security-graph.ts:618` — `type` field not in entity-relationship literal type
- `npm run lint` → **2 errors, 3367 warnings**

The consolidation work below **does not touch** any of those sites.

## 1. Summary of findings

| Bucket                                          | Count          | Notes                                                                                                                                                      |
| ----------------------------------------------- | -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Exported `interface / type / enum` in `server/` | 503            | Many domain-local, engine-internal result types. Only a handful are truly duplicated across engines.                                                       |
| Exported `interface / type / enum` in `client/` | 6              | Almost all page-level types are declared as non-exported `interface` inside the `.tsx` file.                                                               |
| Exported `interface / type / enum` in `shared/` | 749            | Dominated by auto-generated Drizzle `$inferSelect` / `z.infer` types in `shared/schema.ts` (authoritative DB model types).                                 |
| Collisions (same identifier, ≥ 2 files)         | ~120 (by name) | Only ~10 are _true_ duplicates; most are same-name types for semantically different things (`TabId`, `PlanTier`, `ScanResult`, `CorrelationResult`, etc.). |

Full enumeration lives under `/tmp/devin-remote-overflows-*/…` but the material findings are in §2–§4.

## 2. Collisions that look duplicated but are NOT duplicates

These share a name but model different domain concepts. **Do not merge.** Drift here is not drift at all — it's naming collision.

| Identifier                                                                                                                                                                                                                                   | Locations                                                                                      | Why they are not duplicates                                                                                                                                                                                                                          |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CorrelationResult`                                                                                                                                                                                                                          | `server/correlation-engine.ts`, `server/ai.ts`, `server/ai/investigation-runner.ts`            | Three different outputs: correlation-engine returns `{clusterId, confidence, sharedEntities, …}`; `ai.ts` returns LLM grouping output with Diamond/MITRE; `investigation-runner.ts` returns `{relatedAlerts, relatedIncidents, patternDetected}`.    |
| `TriageResult`                                                                                                                                                                                                                               | `server/ai.ts`, `server/ai/autonomous-analyst.ts`                                              | Legacy Bedrock-triage shape vs autonomous-analyst decision record (`decisionId`, `tier`, `outcome`). Client versions match the legacy `ai.ts` shape.                                                                                                 |
| `ScanResult`                                                                                                                                                                                                                                 | `server/dark-web-monitor.ts`, `server/native-collectors-engine.ts`, `server/data-discovery.ts` | Three different scans (dark-web, collector, data-discovery).                                                                                                                                                                                         |
| `PlanTier` (interface/object)                                                                                                                                                                                                                | `server/tiered-packaging-engine.ts`, `client/src/pages/tiered-packaging.tsx`                   | This is a _pricing-plan entity_ (`{id, name, displayName, monthlyPriceCents, limits, …}`), not the string-literal tier enum. Keep separate from the tier-enum consolidation in §3.                                                                   |
| `TabId` (23 hits)                                                                                                                                                                                                                            | Many `client/src/pages/*-hub.tsx`                                                              | Each page derives its own `TabId` from its local `TABS` const (`(typeof TABS)[number]["id"]`). Co-location is the correct pattern.                                                                                                                   |
| `ComplianceControl`                                                                                                                                                                                                                          | `server/storage/types.ts` (DB-derived), two client pages                                       | Client interfaces are small _view models_, not the DB row. Merging to shared risks bringing unused DB columns into the view layer.                                                                                                                   |
| `DetectionRule`, `ResponseAction`, `ApiKey`, `AiFeedback`, `IocEntry`, `IocMatchRule`, `OutboundWebhook`, `InvestigationStep`, `CollectorInstance`, `UsageMetric`, `FeedStatus` (threat-intel variant), `Alert` (in `suppressed-alerts.tsx`) | Shared DB schema type + ad-hoc client “view model” interface                                   | The canonical shape lives in `shared/schema.ts`. Client interfaces are often subsets with stringified dates, renamed fields (`isActive` vs `enabled`), or extra view fields. Replacing them with the full DB type is a MEDIUM-risk surgery (see §5). |

## 3. True duplicates chosen for consolidation (HIGH confidence / LOW risk)

### 3.1 `PlanTier` string-literal type — **HIGH / LOW**

Four **byte-identical** declarations of the tier enum:

```ts
type PlanTier = "free" | "pro" | "enterprise";
```

| File                                  | Line | Export?  |
| ------------------------------------- | ---- | -------- |
| `server/tenant-isolation.ts`          | 10   | `export` |
| `server/tenant-throttle.ts`           | 9    | `export` |
| `server/data-lifecycle.ts`            | 25   | `export` |
| `server/middleware/org-rate-limit.ts` | 8    | local    |

Evidence of pain today: `server/routes/tenant-isolation.ts` already has to alias the duplicate import:

```ts
import { type PlanTier as ThrottlePlanTier, … } from "../tenant-throttle";
```

**Canonical home:** new `shared/types/plan-tier.ts` (client never imports it today, but putting it in `shared/` is consistent with the codebase's "enum-like constants" pattern for truly cross-cutting string literals, and it lets future client code pull the same type without introducing a server → client dependency).

**Risk:** LOW. All four declarations are identical string-literal unions; no runtime surface. Re-export is purely a structural refactor.

**Confidence:** HIGH.

### 3.2 `RequestWithUser` route-handler helper — **HIGH / LOW**

Four near-duplicate `interface RequestWithUser extends Request` declarations in `server/routes/*.ts`, with quiet drift:

| File                                 | Shape                                                   |
| ------------------------------------ | ------------------------------------------------------- |
| `server/routes/chaos-engineering.ts` | `user?: { id?: string; orgId?: string; role?: string }` |
| `server/routes/native-collectors.ts` | `user?: { id?: string; orgId?: string; role?: string }` |
| `server/routes/security-graph.ts`    | `user?: { id?: string; email?: string }`                |
| `server/routes/trust-center.ts`      | `user?: { id?: string; email?: string }`                |

Semantically all four are "Express `Request` where we may have an authenticated user attached". The drift between `{id, orgId, role}` and `{id, email}` is pure accident of which page the author was writing at the time — both sides of the split assign `req.user` via the same `isAuthenticated` middleware stack.

**Canonical home:** `server/routes/types.ts` (new), exporting:

```ts
export interface RequestWithUser extends Request {
  user?: {
    id?: string;
    orgId?: string;
    role?: string;
    email?: string;
    firstName?: string;
    lastName?: string;
  };
}
```

All fields optional, so each existing usage site continues to typecheck unchanged (usages only destructure fields that were already declared locally).

**Risk:** LOW. Union-of-supersets; no call site is narrowing further than it already is. Server-internal only.

**Confidence:** HIGH.

### 3.3 OSINT `FeedStatus` — **HIGH / LOW**

`server/osint-feeds.ts:36` and `client/src/pages/osint-feeds-config.tsx:30` declare **byte-identical** 20-field `FeedStatus` interfaces (the client page is the sole consumer of the server's `/api/osint-feeds/status` endpoint). The other two `FeedStatus` interfaces (`client/src/pages/threat-intel-feeds.tsx`, `client/src/pages/threat-intel.tsx`) are for _different_ endpoints (RSS / threat intel article feeds) and are NOT merged by this track.

**Canonical home:** `shared/types/osint-feeds.ts` (new). Server and the matching client page both import from there.

**Risk:** LOW. Shape is primitives + a literal union; no runtime behavior; identical today.

**Confidence:** HIGH.

## 4. Candidates deferred (MEDIUM / MEDIUM — out of scope)

Documented for a later, more invasive pass:

| Identifier                                                                                                                                           | Locations                                                                                                                                                                                                                                      | Why deferred                                                                                                                                                                                                                                                                                                                                                                        |
| ---------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `OutboundWebhook` (client view-models)                                                                                                               | `developer-portal.tsx`, `settings.tsx`, `webhook-security-center.tsx`                                                                                                                                                                          | Three **diverged** shapes: `{isActive, webhookSecret, lastUsedAt, …}` vs `{isActive, secret, name, events, retryCount, timeoutMs, headers, …}` vs `{enabled, secret, events, …}`, and `id` is alternately `string` and `number`. Shared DB type exists (`shared/schema.ts:3947`); pulling it in requires also reconciling each page's mutation forms and JSON parsing. MEDIUM risk. |
| `IocEntry`, `IocMatchRule`, `DetectionRule`, `ComplianceControl`, `CollectorInstance`, `InvestigationStep`, `ResponseAction`, `AiFeedback`, `ApiKey` | Client page-local `interface` + shared Drizzle type                                                                                                                                                                                            | Client shapes are subsets/variants (often with `Date                                                                                                                                                                                                                                                                                                                                | null → string | null`). Swapping in the full DB row type works but drags in unused DB columns through JSX — best done per-page with a small Pick/Omit utility in `shared/types/`. |
| `WhiteLabelConfig`                                                                                                                                   | `server/reporting/pdf-generator.ts` (PDF-rendering input), `client/src/pages/advanced-reporting.tsx` (subset for PDF render form), `client/src/pages/mssp-partner-portal.tsx` (DB-row view model with `id, orgId, customCss, customDomain, …`) | Two semantically different shapes (PDF render config vs persisted DB row) sharing a name. Needs a rename before consolidation.                                                                                                                                                                                                                                                      |
| `UsageMetric`                                                                                                                                        | 4 client files, 4 different shapes                                                                                                                                                                                                             | All describe "a usage line-item" for different APIs. Not a duplicate; the APIs themselves disagree.                                                                                                                                                                                                                                                                                 |
| `CorrelationResult`                                                                                                                                  | 3 server sites (above)                                                                                                                                                                                                                         | Rename collision, not duplication. Needs domain-level naming work.                                                                                                                                                                                                                                                                                                                  |
| `TriageResult`                                                                                                                                       | 2 server + 3 client                                                                                                                                                                                                                            | Legacy vs autonomous-analyst shapes. Client version should eventually import `TriageResult` from `server/ai.ts`, but server types cannot be imported from client without moving to `shared/`.                                                                                                                                                                                       |
| `server/storage/types.ts` (`IStorage`)                                                                                                               | 1554-line aggregate of re-imported `@shared/schema` types                                                                                                                                                                                      | Already treats `shared/schema.ts` as the single source of truth via `import type { … } from "@shared/schema"`. No drift. No action needed.                                                                                                                                                                                                                                          |
| `shared/models/auth.ts`                                                                                                                              | 4 user/auth types derived from `users / impersonationSessions / failedLoginAttempts` tables                                                                                                                                                    | Intentionally split out; `shared/schema.ts` re-exports them. No drift. No action needed.                                                                                                                                                                                                                                                                                            |

## 5. Implementation plan (for this track only)

1. Add `shared/types/plan-tier.ts` with `export type PlanTier = "free" | "pro" | "enterprise"`.
2. Update 4 server files to `import type { PlanTier } from "@shared/types/plan-tier"` and delete the local declaration.
3. Add `server/routes/types.ts` with the unified `RequestWithUser` superset interface.
4. Update 4 server route files to `import type { RequestWithUser } from "./types"` and delete the local declarations.
5. Add `shared/types/osint-feeds.ts` with `FeedStatus` for the OSINT feeds endpoint.
6. Update `server/osint-feeds.ts` and `client/src/pages/osint-feeds-config.tsx` to import from there.
7. Run `npm run typecheck` and `npm run lint`; require the error count to be ≤ baseline (3 tsc errors, 2 lint errors — all pre-existing and out of scope).

No PR will be opened (per explicit project rule). Changes are committed to `devin/cleanup-track2-types` and pushed for manual review.

## 6. What this track intentionally does NOT do

- Does **not** refactor any of the §2 collisions — they are semantically different types.
- Does **not** touch `shared/schema.ts` or anything auto-derived from Drizzle.
- Does **not** collapse client view-model interfaces into DB row types (§4).
- Does **not** attempt to fix the 3 pre-existing typecheck errors in §0 — that's a separate track.
- Does **not** change lint rules, ESLint config, or `tsconfig.json`.
