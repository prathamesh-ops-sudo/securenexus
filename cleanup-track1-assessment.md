# SecureNexus Cleanup — Track 1: DEDUPLICATION Assessment

**Branch:** `devin/cleanup-track1-dedup` (off `devin/1775462796-platform-seed`)
**Scope:** Scan the entire codebase (`server/`, `client/`, `shared/`) for repeated
logic, copy-pasted functions, and redundant abstractions. Implement only
HIGH-confidence / LOW-risk consolidations. Be conservative.

---

## Summary

The codebase already has several well-designed shared modules:

| Layer  | Shared module                   | What it covers                                                                                                                                                                                                       |
| ------ | ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Server | `server/api-response.ts`        | `ApiEnvelope`, `ApiError`, `ERROR_CODES`, `reply`, `replyError`, `replyUnauthenticated`, `replyForbidden`, `replyBadRequest`, `replyNotFound`, `replyConflict`, `replyValidation`, `replyRateLimit`, `replyInternal` |
| Server | `server/routes/shared.ts`       | Re-exports `reply*` helpers, plus `getOrgId(req)`, `sendEnvelope`, `p()`, rate limiters, API-key auth, webhook signature verification, outbox dispatch                                                               |
| Server | `server/rbac.ts`                | `resolveOrgContext`, `requireOrgId`, `requireOrgRole`, `requireMinRole`, `requirePermission`                                                                                                                         |
| Server | `server/with-org-scope.ts`      | `requireOrgScope`, `withOrgFilter` — strict tenant isolation in storage                                                                                                                                              |
| Server | `server/auth/session.ts`        | `setupAuth`, `isAuthenticated`, `getSession`                                                                                                                                                                         |
| Client | `client/src/lib/queryClient.ts` | `apiRequest`, `getQueryFn`, `fetchPaginated`, `fetchCsrfToken`, `extractApiError`, `ensureArray`, `queryClient`                                                                                                      |
| Client | `client/src/lib/utils.ts`       | `cn` (classname merge)                                                                                                                                                                                               |
| Client | `client/src/lib/auth-utils.ts`  | `isUnauthorizedError`, `redirectToLogin`                                                                                                                                                                             |
| Client | `client/src/lib/i18n.ts`        | `formatDateTime`, currency, number formatting                                                                                                                                                                        |

Because of this existing infrastructure, most of the obvious duplication is
already consolidated. The remaining duplication falls into two groups:

1. **Utility functions duplicated across a handful of pages** (`formatBytes`,
   `truncateHash`, `timeAgo`, `formatDate`, `severityColor`, `apiFetch`).
2. **Legacy patterns in route handlers** (`(req as any).user?.orgId`,
   `res.status(500).json({ message: ... })`) that pre-date the canonical
   envelope helpers.

Only items in Group 1 with a meaningful implementation-identity signal are safe
to consolidate. Group 2 is high-risk (semantic differences) and is documented
below but left unchanged.

---

## Findings

### F1 — `formatBytes` duplicated across 7 pages &nbsp;[HIGH confidence · LOW risk · **CONSOLIDATING**]

**Instances (all client-side):**

| File                                         | Line | Units         | Output format    |
| -------------------------------------------- | ---- | ------------- | ---------------- |
| `client/src/pages/trust-center.tsx`          | 136  | B/KB/MB/GB    | template literal |
| `client/src/pages/native-sensors.tsx`        | 638  | B/KB/MB/GB    | `+ " " +` concat |
| `client/src/pages/evidence-chain-viewer.tsx` | 207  | B/KB/MB/GB    | template literal |
| `client/src/pages/evidence-custody.tsx`      | 135  | B/KB/MB/GB    | template literal |
| `client/src/pages/dev-portal.tsx`            | 113  | B/KB/MB/GB    | template literal |
| `client/src/pages/native-collectors.tsx`     | 280  | B/KB/MB/GB/TB | template literal |
| `client/src/pages/data-lake.tsx`             | 78   | B/KB/MB/GB/TB | template literal |

All seven implementations:

- Guard `bytes === 0` → return `"0 B"`.
- Use `k = 1024` (binary units — NOT decimal).
- Pick the index via `Math.floor(Math.log(bytes) / Math.log(k))`.
- Format to 1 decimal via `parseFloat(… .toFixed(1))`.

For all inputs **< 1 TB**, every implementation produces byte-identical output.
Extending the units array to include `TB`/`PB` does not change the output of any
caller, because those callers only format file sizes where `i ≤ 3`.

**Why it's duplicated:** Copy-paste. Each page needed a display helper and the
author didn't know one already existed elsewhere. There was no shared home for
generic formatting utilities (only `cn()` lives in `lib/utils.ts`).

**Consolidation:** Add `formatBytes(bytes: number): string` to
`client/src/lib/utils.ts`; replace the seven local copies with named imports.

**Explicitly NOT consolidated** (semantically different, kept local):

- `platform-admin.tsx:1241` — only returns KB or MB, never B/GB/TB.
- `data-lifecycle.tsx:98` — uses **decimal** units (`1e3`, `1e6`, `1e9`) instead
  of binary; display convention differs.

### F2 — `truncateHash` duplicated &nbsp;[HIGH confidence · LOW risk · **CONSOLIDATING**]

**Instances:**

- `client/src/pages/evidence-custody.tsx:129`
- `client/src/pages/evidence-chain-viewer.tsx:201`

Both implementations are character-for-character identical:

```ts
function truncateHash(hash: string | null): string {
  if (!hash) return "—";
  if (hash === "GENESIS" || hash === "genesis") return "GENESIS";
  return `${hash.slice(0, 8)}…${hash.slice(-6)}`;
}
```

**Why it's duplicated:** Both files render the audit-chain hash; the second
page clearly copied from the first.

**Consolidation:** Add `truncateHash(hash: string | null): string` to
`client/src/lib/utils.ts`; replace the two local copies with named imports.

---

### F3 — `severityColor` duplicated across 14 pages &nbsp;[MEDIUM confidence · MEDIUM risk · **NOT consolidating**]

14 pages define a local `severityColor` helper, but they fall into **three
semantically different groups**:

| Return style                                                                          | Files                                                                    |
| ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| shadcn Badge variants (`"destructive"`/`"secondary"`/`"outline"`)                     | `email-security`, `dns-security`, `cve-browser`, `developer-security`    |
| Tailwind background + text classes (`"bg-red-500/10 text-red-500 border-red-500/20"`) | `physical-security`, `dark-web-monitoring`, `ai-detection-rules`, `tprm` |
| Pure text-color classes (`"text-red-400"`)                                            | `community-intel`, `cross-cutting`                                       |

Some also differ in which severity buckets exist (e.g. `info` only in some).
Callers consume the returned string as the `variant` prop of a shadcn `<Badge>`,
**or** as a `className`, **or** as a Tailwind fragment inside a composed class.

**Why it's duplicated:** Parallel development — each dashboard page introduced
its own variant that matched its local design system.

**Risk of consolidation:** A single `getSeverityBadgeVariant` helper would
require a variant parameter (`"badge" | "chip" | "text"`), and even then the
exact class strings vary across the chip-style pages (`text-red-500` vs
`text-red-400`, `bg-red-500/10` vs `bg-red-600/20`). Consolidating into one
function would either silently change the rendered appearance of some pages or
require a larger design-system refactor.

**Verdict:** Leave as-is. A design-system-level severity color token would be
the right fix, but that is a design decision, not a deduplication.

---

### F4 — `timeAgo` duplicated across 5 pages &nbsp;[MEDIUM confidence · MEDIUM risk · **NOT consolidating**]

**Instances:**

| File                                           | Variant                                             |
| ---------------------------------------------- | --------------------------------------------------- |
| `client/src/pages/native-sensors.tsx:627`      | seconds precision, `Never`, `Xs / Xm / Xh / Xd ago` |
| `client/src/pages/detection-rules.tsx:219`     | identical to native-sensors                         |
| `client/src/pages/threat-intel-feeds.tsx:87`   | minute precision, adds `"Just now"` for < 1 min     |
| `client/src/pages/osint-feeds-config.tsx:87`   | identical to threat-intel-feeds                     |
| `client/src/pages/identity-governance.tsx:186` | minute precision, no `"Just now"`                   |

**Why it's duplicated:** Copy-paste, with tweaks. Three different "correct"
behaviors exist: show seconds, show "Just now" for fresh events, or round to
minutes.

**Risk of consolidation:** Pinning to any one variant would visibly change
timestamps on every page that uses a different one. The right fix is a
consistent product-wide policy (probably delivered via
`Intl.RelativeTimeFormat`), which is out of scope for a safe dedup.

**Verdict:** Leave as-is.

---

### F5 — `formatDate` duplicated across ~23 pages &nbsp;[LOW confidence · HIGH risk · **NOT consolidating**]

Signatures vary:

- Some return `"N/A"`, others `"—"`, others `""`, others `"-"` for null.
- Some use `toLocaleDateString()` (user locale).
- Some hard-code `"en-US"` with specific options (`month: "short"`, etc.).
- Some call `toLocaleString()` (date + time).
- Some wrap in `try/catch`, others don't.
- `reports.tsx` already delegates to the shared `formatDateTime` from `lib/i18n.ts`.

**Why it's duplicated:** Parallel development. A central `lib/i18n.ts` **does
exist** and has a `formatDateTime()` helper, but most pages never adopted it.

**Risk of consolidation:** Any single shared implementation would either (a) use
the user's locale (silently changing display for en-US-expecting pages) or (b)
pin en-US (silently changing display for locale-respecting pages). Different
null-placeholder strings (`"—"` vs `"N/A"` vs `""`) would also change UI.

**Verdict:** Leave as-is. A migration to `lib/i18n.ts` is a design task, not a
safe dedup — it changes user-visible output.

---

### F6 — `StatCard` component duplicated across 20 pages &nbsp;[LOW confidence · HIGH risk · **NOT consolidating**]

20 files define a `StatCard` local component. Only a couple of pairs
(`email-security.tsx` ↔ `dns-security.tsx`) are byte-identical. The others
differ in:

- Props: `label` vs `title`, optional `subtitle`, `variant`, `color`, `loading`.
- Styling: plain card vs glass card vs colored icon container.
- `data-testid` naming conventions.
- Icon element typing (`React.ElementType` vs `React.ComponentType<{ className?: string }>`).

**Why it's duplicated:** Parallel page development, no shared card primitive.

**Risk of consolidation:** The component has more than one true contract. A
unified `StatCard` that satisfies all 20 callers would be a large prop-union
that's harder to read than the local copies. This is a design-system task, not
a dedup.

**Verdict:** Leave as-is. If a shared `StatCard` is wanted, it should be
designed deliberately and rolled out deliberately.

---

### F7 — `apiFetch` duplicated across 13 pages &nbsp;[LOW confidence · HIGH risk · **NOT consolidating**]

13 pages define a local `async function apiFetch(url, options)`. The canonical
helper `apiRequest(method, url, data?)` already exists in
`client/src/lib/queryClient.ts` and handles CSRF, `X-Org-Id`, envelope
unwrapping, and error extraction.

**Variants observed:**

| Behavior                                                               | Pages                                                                                                               |
| ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| CSRF + `X-Org-Id` + envelope unwrap (≈ `apiRequest`)                   | `email-security`, `dns-security`, `ueba`, `ransomware-defense`, `agent-response`, `community-intel`, `api-security` |
| No CSRF, no org header, basic error extraction                         | `vuln-scanner`, `supply-chain`, `posture-trust-center`                                                              |
| CSRF from cookie (`XSRF-TOKEN`) — not from `/api/csrf-token`           | `security-chaos-engineering`, `privacy-engineering`                                                                 |
| Different error-body keys (`body.error` vs `body.message` vs envelope) | varies                                                                                                              |

**Why it's duplicated:** Parallel development + unfamiliarity with the shared
`apiRequest`. A few pages (cookie-CSRF variant) appear to pre-date the
`/api/csrf-token` endpoint.

**Risk of consolidation:** Changing `apiFetch` call sites to `apiRequest` would
change:

- The signature (options object → `(method, url, data?)`).
- CSRF behavior for the cookie-CSRF pages (they may silently regress if
  `/api/csrf-token` doesn't work in their auth context).
- Error messages (different envelope-vs-plain-JSON extraction).
- The return type (`Response` vs parsed JSON).

**Verdict:** Leave as-is. Migrating pages to `apiRequest` is a careful
per-page change that requires verifying each page still renders correctly.
Not safe in a batch dedup.

---

### F8 — `unwrap` helper duplicated across 3 pages &nbsp;[MEDIUM confidence · LOW–MEDIUM risk · **NOT consolidating**]

**Instances:**

- `client/src/pages/trust-center.tsx:131` — returns `any`.
- `client/src/pages/policy-packs.tsx:40` — returns `any`, same logic.
- `client/src/pages/executive-risk.tsx:31` — returns `unknown`, slightly stricter.

Logic is effectively identical: "if the value looks like `{ data: ... }`,
return `.data`, else return the value as-is."

The canonical helper `unwrapEnvelope<T>()` already exists in
`client/src/lib/queryClient.ts` but is **module-private** (not exported).

**Why it's duplicated:** The existing `unwrapEnvelope` isn't exported, so each
page re-rolled it.

**Risk of consolidation:** Exporting `unwrapEnvelope` is safe. However, the
three callers use it as a narrow one-liner on pre-typed data from
TanStack-Query — this is already handled globally by the `Response.json`
override in `apiRequest`. These three pages use it defensively against
already-unwrapped data; removing/centralizing has subtle interaction with
specific query shapes.

**Verdict:** Leave as-is — the juice isn't worth the squeeze for 3 short
helpers. A broader refactor to fully lean on the global envelope-unwrap
behavior is the right long-term fix.

---

### F9 — `(req as any).user?.orgId` inlined in ~200 server route handlers &nbsp;[LOW confidence · HIGH risk · **NOT consolidating**]

`getOrgId(req)` already exists in `server/routes/shared.ts`:

```ts
export function getOrgId(req: Request): string {
  const orgId = (req as any).orgId || (req as any).user?.orgId;
  if (!orgId || typeof orgId !== "string") {
    throw new Error("ORG_CONTEXT_MISSING");
  }
  return orgId;
}
```

103 files already use `getOrgId(req)`, but ~200 other call sites inline
`(req as any).user?.orgId`. They are **semantically different**:

- `getOrgId` throws on missing org → caller's `try/catch` returns 500.
- Inline `(req as any).user?.orgId` yields `undefined` → downstream query
  silently returns an empty list (or worse, leaks cross-tenant data if the
  query doesn't enforce the filter strictly).

**Why it's duplicated:** Copy-paste. `getOrgId` was introduced later than many
routes.

**Risk of consolidation:** Swapping to `getOrgId(req)` in every inline site
would change error semantics on every affected endpoint, potentially turning
silent empty responses into 500s — a real behavior change that needs
per-endpoint review. The correct path is a route-level middleware that rejects
missing orgs (effectively `requireOrgId`), combined with the existing
`resolveOrgContext`, applied surgically.

**Verdict:** Leave as-is for this pass. This should be a dedicated cleanup of
its own, with per-endpoint verification and test coverage. Flagging for a
future track.

---

### F10 — `res.status(500).json({ message: "..." })` in ~200 catch blocks &nbsp;[LOW confidence · MEDIUM risk · **NOT consolidating**]

Older route files fall back to the raw express `res.status(500).json(...)`
pattern instead of `replyInternal(res, ...)` from `api-response.ts`.

**Why it's duplicated:** Legacy — pre-dates the envelope helpers.

**Risk of consolidation:** Switching to `replyInternal` would wrap responses in
`{ data: null, meta: {}, errors: [{ code: "INTERNAL_ERROR", message }] }`
instead of `{ message }`. **That IS the correct canonical shape**, and the
client's `apiRequest` handles both — but any out-of-band consumer (integration
tests, external scripts, monitoring probes) that parses the raw `message` would
break.

**Verdict:** Leave as-is. This is a separate hygiene track
("canonicalize all error responses to `ApiEnvelope`") that should be done route
file by route file with grep/replace + test verification, not in a dedup pass.

---

## Implementation plan (this branch)

Two consolidations only:

1. **`formatBytes`** — add to `client/src/lib/utils.ts`; remove 7 local copies.
2. **`truncateHash`** — add to `client/src/lib/utils.ts`; remove 2 local copies.

Everything else documented above is intentionally left unchanged because
safer/clearer analysis did not support a drive-by refactor.

### Verification

- `npm run typecheck`
- `npm run lint`

Both must pass after the changes.

### Branch / PR policy

Per standing instruction: commit to `devin/cleanup-track1-dedup`, push, **do
NOT open a PR.**
