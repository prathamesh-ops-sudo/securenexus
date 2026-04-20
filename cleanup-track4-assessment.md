# Cleanup Track 4 — Circular Dependencies Assessment

**Repository:** `prathamesh-ops-sudo/securenexus`
**Base branch:** `devin/1775462796-platform-seed`
**Work branch:** `devin/cleanup-track4-circular`
**Tool:** [`madge`](https://github.com/pahen/madge) v8.x
**Scope:** `server/` (428 TS files) and `client/` (247 TS/TSX files)
**Date:** 2026-04-20

---

## 1. Raw Results

### `npx madge --circular --extensions ts,tsx server/`

```
Processed 428 files (6.4s) (2 warnings)

✖ Found 2 circular dependencies!

1) normalizer.ts > ocsf.ts
2) job-queue.ts > routes/ai/triage.ts
```

### `npx madge --circular --extensions ts,tsx client/`

```
Processed 247 files (6.4s) (228 warnings)

✔ No circular dependency found!
```

### Baseline state before any fixes

| Check               | Result                                                                                                     |
| ------------------- | ---------------------------------------------------------------------------------------------------------- |
| madge server        | **2 cycles** (both 2-node)                                                                                 |
| madge client        | **0 cycles**                                                                                               |
| `npm run typecheck` | 3 pre-existing errors (unrelated — in `server/routes/connectors.ts` and `server/routes/security-graph.ts`) |
| `npm run lint`      | 2 pre-existing errors, 3367 warnings                                                                       |

Pre-existing typecheck and lint errors are **out of scope** for this track. They belong to other cleanup tracks and are not introduced or exacerbated here.

---

## 2. Cycle-by-Cycle Assessment

### Cycle #1 — `server/normalizer.ts` ↔ `server/ocsf.ts`

**Edges:**

| From                     | To                     | Import kind                                                           | Purpose                                                                                                                                          |
| ------------------------ | ---------------------- | --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `server/normalizer.ts:2` | `server/ocsf.ts`       | `import { toOCSFSecurityFinding } from "./ocsf"` — **value**          | Calls `toOCSFSecurityFinding(normalized)` at line 1050 of `toInsertAlert` to attach OCSF payload to every normalized alert.                      |
| `server/ocsf.ts:1`       | `server/normalizer.ts` | `import type { NormalizedAlert } from "./normalizer"` — **type-only** | Uses `NormalizedAlert` as a parameter/argument type in `extractObservables`, `toOCSFSecurityFinding`, etc. Erased at compile time by TypeScript. |

**Runtime impact:** None. Because `ocsf.ts`'s back-edge is `import type`, TypeScript erases it during emit (`verbatimModuleSyntax`-safe). The compiled JavaScript has **one-way** dependency: `normalizer.js → ocsf.js`. There is no initialization ordering hazard, no TDZ risk, no module-hoisting ambiguity.

**Why madge still reports it:** madge's AST parser treats `import type` as a graph edge regardless of whether TypeScript erases it.

**Problem category:** Cosmetic — structural/tooling only. The type definition `NormalizedAlert` (26 fields, pure data) logically belongs next to the normalizers that produce it, but is also consumed by the OCSF mapper. Owning it in `normalizer.ts` creates a structural cycle at the module-graph level even though the runtime graph is acyclic.

**Impact on maintainability:** LOW. The cycle obscures the "types-vs-impl" boundary: a reader has to know the type re-exports come from the larger file. No measurable impact on testability (both files are unit-tested independently) or correctness.

**Priority:** **LOW** (reported by tools, but TypeScript/Node already handle it correctly).

**Proposed resolution:** Extract the `NormalizedAlert` interface into a thin, type-only neutral module `server/normalizer-types.ts`. Re-export it from `server/normalizer.ts` to preserve the existing public surface for all downstream consumers (`connector-engine.ts`, `routes/ingestion.ts`, `routes/alerts.ts`, `__tests__/*`). `ocsf.ts` imports the type from the new neutral module instead of `normalizer.ts`.

This is **not** a new abstraction (no interface/adapter/mediator added); it is a **file-organization** move — purely moving an `export interface` to its own file. No logic changes.

**Confidence:** HIGH — types are erased at compile time; the move is mechanical.
**Risk:** LOW — no runtime behavior changes; re-exports keep all existing imports working; covered by the existing `server/__tests__/normalizer.test.ts` suite which imports `NormalizedAlert` from the old location (the re-export keeps that path valid).

**Decision:** **FIX.** Applied.

---

### Cycle #2 — `server/job-queue.ts` ↔ `server/routes/ai/triage.ts`

**Edges:**

| From                           | To                           | Import kind                                                                       | Purpose                                                                                                                          |
| ------------------------------ | ---------------------------- | --------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `server/routes/ai/triage.ts:8` | `server/job-queue.ts`        | `import { enqueueJob } from "../../job-queue"` — **value (static)**               | `POST /api/ai/triage` enqueues an `ai_triage` background job via `enqueueJob(...)`.                                              |
| `server/job-queue.ts:25`       | `server/routes/ai/triage.ts` | `const { getAiTriageHandler } = await import("./routes/ai/triage")` — **dynamic** | Inside the `ai_triage` worker handler, the job queue lazily resolves the handler function registered by the triage route module. |

**Runtime impact:** None. The back-edge from `job-queue.ts` into `triage.ts` is a **dynamic `await import(...)`** placed inside the body of an async handler. It is not evaluated at module load time — only when an `ai_triage` job actually runs. This is the standard, idiomatic pattern for breaking initialization-order cycles between a job infrastructure module and domain handlers that want to both enqueue and be invoked by the queue.

**Why madge still reports it:** madge detects string-literal dynamic `import(...)` specifiers as edges in the module graph. They are real edges at runtime — but they are **deferred** and do not participate in module initialization.

**Problem category:** **Intentional, already mitigated.** The existing dynamic import is the canonical fix for this class of cycle. Further identical dynamic imports exist in `job-queue.ts` for the same reason:

```ts
// server/job-queue.ts
  34:  const { syncConnectorWithRetry } = await import("./connector-engine");
  121: const { enrichEntity } = await import("./threat-enrichment");
  130: const { generateReportData } = await import("./report-engine");
  218: const { evaluateSlos } = await import("./sli-middleware");
```

This is a deliberate architectural choice: `job-queue.ts` is a low-level infrastructure module (loaded near the root of the app graph), and domain handlers depend on it for enqueueing — so handler modules must be resolved lazily. Inverting the dependency (e.g., handler registration via a side-effect-free registry) **would** be "introducing a new abstraction just to break a cycle," which this track explicitly excludes.

**Impact on maintainability:** NONE. The pattern is consistent across five handlers in `job-queue.ts`; a reader familiar with the queue conventions sees the dynamic import and immediately understands why.

**Impact on testability:** NONE. Triage route tests mock `enqueueJob`; job-queue tests (if any) would mock handler modules independently.

**Impact on correctness:** NONE. The dynamic import has been in production since before this track.

**Priority:** **LOW** (cosmetic tool warning — architecture is correct).

**Proposed resolution:** **No change.** Replacing `await import(...)` with a static import would re-introduce the cycle as a real initialization-order hazard. Replacing with a handler registry (a new `job-handler-registry.ts`) would be a new abstraction solely to appease madge, which this track explicitly disallows.

**Confidence:** HIGH (that no change is correct).
**Risk:** N/A (no change proposed).

**Decision:** **DO NOT FIX.** Document as intentional mitigation. The madge warning is acceptable.

---

## 3. Priority Summary

| #   | Cycle                                  | Priority | Decision                                                 | Confidence | Risk |
| --- | -------------------------------------- | -------- | -------------------------------------------------------- | ---------- | ---- |
| 1   | `normalizer.ts` ↔ `ocsf.ts`            | LOW      | FIX — extract `NormalizedAlert` to `normalizer-types.ts` | HIGH       | LOW  |
| 2   | `job-queue.ts` ↔ `routes/ai/triage.ts` | LOW      | DO NOT FIX — dynamic import already mitigates            | HIGH       | N/A  |

No **CRITICAL**, **HIGH**, or **MEDIUM** priority cycles were found. Both detected cycles are cosmetic (one side is type-only, the other is dynamic-import). The codebase has **no real initialization-order, test-isolation, or correctness hazards** from circular dependencies.

---

## 4. Cycles Explicitly Scoped Out

- Cycle #2 (job-queue ↔ triage): Already mitigated via dynamic import. Restructuring would require introducing a new registry abstraction, which violates this track's "no new abstractions" rule.
- Any cycle that TypeScript compiles and Node runs without warning: scoped out by the track's explicit guidance to ignore cosmetic cycles TypeScript handles fine.

---

## 5. Implementation Record

### Fix applied for Cycle #1

1. Created `server/normalizer-types.ts` containing only the `NormalizedAlert` interface.
2. Updated `server/normalizer.ts`:
   - Import `NormalizedAlert` from `./normalizer-types`.
   - Re-export it (`export type { NormalizedAlert } from "./normalizer-types"`) so all existing consumers (`connector-engine.ts`, `routes/ingestion.ts`, `routes/alerts.ts`, `__tests__/normalizer.test.ts`, `__tests__/connectors.integration.test.ts`) continue to resolve `import { NormalizedAlert } from "../normalizer"` unchanged.
3. Updated `server/ocsf.ts`:
   - Changed `import type { NormalizedAlert } from "./normalizer"` → `import type { NormalizedAlert } from "./normalizer-types"`.

### Verification

- `npx madge --circular --extensions ts,tsx server/` → **1 cycle remaining** (Cycle #2, intentional per §2).
- `npx madge --circular --extensions ts,tsx client/` → **0 cycles**.
- `npm run typecheck` → **No new errors introduced** (3 pre-existing errors unchanged).
- `npm run lint` → **No new errors introduced** (baseline warnings/errors unchanged).

---

## 6. Recommendations for Future Work (Out of Scope for This Track)

- **Pre-existing typecheck errors** (`updateConnectorSyncStatus` signature mismatch in `server/routes/connectors.ts:442,463`; unknown `type` property in `server/routes/security-graph.ts:618`) should be addressed in the typechecking cleanup track.
- **Lint noise** (3367 warnings, mostly `@typescript-eslint/no-explicit-any`) should be addressed in the linting cleanup track.
- If a future refactor wants to also eliminate Cycle #2 at the module-graph level (for stricter architectural linting), the right approach is a dedicated handler-registry module where domain modules call `registerJobHandler("ai_triage", handler)` at app boot, and `job-queue.ts` looks up handlers via the registry. This is a real abstraction, requires careful lifecycle ordering, and is out of scope here.
