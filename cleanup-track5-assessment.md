# Track 5: Type Strengthening — Critical Assessment

**Branch:** `devin/cleanup-track5-typestrength` (from `devin/1775462796-platform-seed`)
**Scope:** Every weak-type token (`any`, `unknown`, `as`) across `server/`, `client/`, `shared/`.
**Baseline typecheck:** 3 pre-existing errors in `server/routes/connectors.ts` (2) and `server/routes/security-graph.ts` (1) — unrelated to this track, left in place.

---

## 1. Scale of the problem

| Weak-type token                  | Occurrences |
| -------------------------------- | ----------: |
| `: any` (annotations)            |   **1,071** |
| `as any` (assertions)            |   **1,456** |
| `(req as any)` (subset of above) |         801 |
| `any[]` (array types)            |         212 |
| `: unknown` (annotations)        |         541 |
| `as unknown` (assertions)        |         110 |
| **Total weak-type sites**        |  **~3,390** |
| Files affected                   |    **236+** |

Top offender files:

| Rank | File                                   | Count |
| ---- | -------------------------------------- | ----: |
| 1    | `server/routes/endpoints.ts`           |    68 |
| 1    | `server/routes/connectors.ts`          |    68 |
| 3    | `server/routes/playbooks/execution.ts` |    65 |
| 3    | `server/routes/orgs.ts`                |    65 |
| 5    | `client/src/pages/playbooks.tsx`       |    58 |
| 6    | `client/src/pages/cspm.tsx`            |    57 |
| 7    | `server/routes/incidents.ts`           |    55 |
| 8    | `server/routes/integrations.ts`        |    52 |
| 9    | `server/routes/admin.ts`               |    51 |
| 10   | `client/src/pages/incident-detail.tsx` |    46 |

---

## 2. Pattern classification

I grouped every weak-type site into six classes. Fixing a representative pattern typically fixes dozens of identical sites elsewhere.

### Class A — `catch (error: any)` — 200 sites across ~150 files

- **Current:** `} catch (error: any) { … error.message … }`
- **Correct:** `} catch (error: unknown) { … error instanceof Error ? error.message : String(error) … }`
- **Rationale:** TypeScript `useUnknownInCatchVariables` default. `error` at a catch boundary is legitimately `unknown` — the caller/platform can throw anything. The fix is narrowing, not widening.
- **Confidence:** HIGH. **Risk:** LOW (mechanical; guarded by typecheck).
- **Action:** Replaced in batches — `error: any` → `error: unknown` + narrowing helper.

### Class B — `(req as any).user` / `(req as any).orgId` — 801 sites

- **Current:** `const orgId = (req as any).orgId; const user = (req as any).user;`
- **Root cause:** `passport` decorates `req.user`, middleware decorates `req.orgId`, `req.membership`, `req.orgRole`, `req.apiKey`, etc., but the `Express.Request` type is never augmented, so every handler casts.
- **Correct:** Augment `Express.Request` globally in `server/types/express.d.ts` with the properties that middleware actually sets, then remove the casts.
- **Confidence:** HIGH that augmentation is correct. **Risk:** MEDIUM — introducing strict types surfaces places that assume `req.orgId` is present without running `requireOrgId` middleware.
- **Action:** Added a global augmentation; kept existing helpers (`getOrgId`, `requireOrgId`) as the canonical access pattern. Did not sweep all 801 call sites in this pass — changing `(req as any)` to `req` in one PR risks cascading errors across 100+ route files without per-route review. Remaining sites are documented below as follow-ups.

### Class C — `as any` on ORM inserts / updates — ~250 sites

- **Current:** `storage.upsertAlert(alertData as any)`, `config: version.conditions as any`, `{ lastSyncAt: null as unknown as Date }`.
- **Root cause:** Drizzle `InsertX` types are strict (required columns without defaults), but handlers pass partial objects or `null` for columns typed `NotNull`.
- **Correct:** Build the insert shape from `InsertAlert`, `InsertIncident`, etc. Use nullable columns where the schema allows it; fix the schema where the cast papers over a type-vs-runtime mismatch.
- **Confidence:** MEDIUM. **Risk:** HIGH — aggressive removal surfaces 3 pre-existing baseline errors (already in `connectors.ts`, `security-graph.ts`) plus many more. Reviewing each requires domain knowledge of the table.
- **Action:** Documented; not swept. This is a separate track because it requires schema review, not just type replacement.

### Class D — lambda parameters in array methods (`.map((x: any) => …)`) — ~350 sites

- **Current:** `alerts.map((a: any) => a.id)`, `incidents.filter((i: any) => i.severity === "high")`.
- **Correct:** TypeScript can usually infer the element type from the array; delete the annotation or use `Alert`, `Incident`, etc.
- **Confidence:** HIGH. **Risk:** LOW on inferred arrays, MEDIUM where the array is itself typed `any[]`.
- **Action:** Fixed representative hot spots (normalizer, correlation, job-queue). Widespread sweep deferred due to volume; each site individually trivial but cumulatively large.

### Class E — `: unknown` at external-data boundaries — ~400 of 541 sites

- **Examples:** webhook bodies, SSE payloads, AWS SDK responses before schema validation, job-queue payloads before Zod parsing, JSON columns (`jsonb`) from Drizzle.
- **Verdict:** **LEGITIMATE.** `unknown` is the correct type at a trust boundary. The fix is not to widen or assert, but to validate with Zod and let inference flow from the schema.
- **Action:** **Preserved.** Audited every `: unknown` site; replaced only the ~140 that were not at a boundary (e.g., internal helpers that had `unknown` out of laziness when the real type was in scope).

### Class F — `as unknown as T` / `as unknown` double casts — 110 sites

- **Current:** `null as unknown as Date`, `result as unknown as Row[]`.
- **Verdict:** Almost always a code smell — the author bypassed a legitimate type error. Each site needs individual review.
- **Action:** Fixed obvious cases (array casts where inference works); flagged the rest.

---

## 3. By-file weak-type inventory (top 40)

All numbers are `: any` + `as any` + `any[]` + `Record<string, any>` on the same line.

| File                                     | Weak-type count | Dominant pattern                                       | Correct fix                              | Confidence | Risk                         |
| ---------------------------------------- | --------------: | ------------------------------------------------------ | ---------------------------------------- | ---------- | ---------------------------- |
| `server/routes/endpoints.ts`             |              68 | `catch (error: any)`, `(req as any).user`              | `unknown` + Express augmentation         | HIGH       | LOW                          |
| `server/routes/connectors.ts`            |              68 | `as any` on storage upserts, `catch (error: any)`      | Drizzle `InsertConnector` + `unknown`    | MEDIUM     | HIGH                         |
| `server/routes/playbooks/execution.ts`   |              65 | `payload: any`, `actionsExecuted as any`               | `PlaybookActionPayload` union            | HIGH       | MEDIUM                       |
| `server/routes/orgs.ts`                  |              65 | `(req as any)` pervasive, `catch error: any`           | Express augmentation + `unknown`         | HIGH       | LOW                          |
| `client/src/pages/playbooks.tsx`         |              58 | `mutation.data as any`, `: any` on inline render data  | Typed query/mutation responses           | HIGH       | MEDIUM                       |
| `client/src/pages/cspm.tsx`              |              57 | same                                                   | Typed query responses                    | HIGH       | MEDIUM                       |
| `server/routes/incidents.ts`             |              55 | `catch (error: any)`, `(req as any)`                   | mechanical                               | HIGH       | LOW                          |
| `server/routes/integrations.ts`          |              52 | integration client responses typed `any`               | Per-provider response types              | MEDIUM     | MEDIUM                       |
| `server/routes/admin.ts`                 |              51 | `(req as any).user` and ad-hoc shapes                  | Express augmentation + domain types      | HIGH       | LOW                          |
| `client/src/pages/incident-detail.tsx`   |              46 | `: any` on rendered incident data                      | `Incident` import from `@shared/schema`  | HIGH       | LOW                          |
| `server/routes/compliance.ts`            |              45 | `catch (error: any)`, `report as any`                  | `ComplianceReport` type                  | HIGH       | MEDIUM                       |
| `server/routes/phase2-routes.ts`         |              43 | legacy `(req as any)` patterns                         | augmentation                             | HIGH       | LOW                          |
| `server/routes/playbooks/versions.ts`    |              40 | `conditions as any`, `actions as any`                  | Drizzle `InsertPlaybookVersion`          | MEDIUM     | HIGH                         |
| `server/routes/autonomous.ts`            |              39 | `policy as any`, `catch error: any`                    | `AutonomousPolicy` type                  | MEDIUM     | MEDIUM                       |
| `server/routes/report-governance.ts`     |              38 | `catch error: any`, `report payload any`               | mechanical + typed payload               | HIGH       | LOW                          |
| `server/routes/investigations.ts`        |              38 | same                                                   | same                                     | HIGH       | LOW                          |
| `client/src/pages/rollback-history.tsx`  |              38 | `: any` on tanstack-query data                         | Typed `useQuery<T>`                      | HIGH       | LOW                          |
| `server/routes/enterprise-org.ts`        |              36 | `(req as any)`, `storage.X as any`                     | augmentation + InsertX                   | MEDIUM     | MEDIUM                       |
| `server/job-queue.ts`                    |              34 | `job.payload as any`, `handler(... any)`               | Per-job-type payload discriminated union | HIGH       | MEDIUM                       |
| `server/routes/ai/investigation.ts`      |              33 | AI response shapes as `any`                            | Zod-validated Bedrock response           | MEDIUM     | MEDIUM                       |
| `server/routes/playbooks/simulations.ts` |              30 | simulation input `any`                                 | `SimulationInput` type                   | MEDIUM     | MEDIUM                       |
| `server/normalizer.ts`                   |              30 | source payload `: any` (pre-normalization)             | Legit `unknown` at boundary              | HIGH       | LOW (leave mostly unchanged) |
| `server/routes/operations.ts`            |              29 | mechanical                                             | mechanical                               | HIGH       | LOW                          |
| `server/routes/ai/feedback.ts`           |              29 | feedback payload `any`                                 | `AiFeedback` type                        | MEDIUM     | LOW                          |
| `client/src/pages/reports.tsx`           |              29 | query data `any`                                       | typed `useQuery<Report[]>`               | HIGH       | LOW                          |
| `server/routes/ai/narrative.ts`          |              28 | Bedrock response `any`                                 | Zod-validated response                   | MEDIUM     | MEDIUM                       |
| `server/routes/agent-response.ts`        |              26 | action payload `any`                                   | `ResponseAction` type                    | MEDIUM     | MEDIUM                       |
| `server/routes/standalone-platform.ts`   |              25 | `(req as any)` legacy                                  | augmentation                             | HIGH       | LOW                          |
| `client/src/pages/evidence-custody.tsx`  |              25 | query data `any`                                       | typed query                              | HIGH       | LOW                          |
| `server/routes/sso.ts`                   |              23 | SAML/OIDC profile `any`                                | Provider-specific profile types          | LOW        | HIGH                         |
| `server/routes/ingestion.ts`             |              23 | ingest payload `any` — this is the normalizer boundary | **Legit `unknown` at boundary**          | HIGH       | preserve                     |
| `server/routes/ai/triage.ts`             |              23 | AI response `any`                                      | Zod-validated                            | MEDIUM     | MEDIUM                       |
| `server/routes/native-sensors.ts`        |              22 | sensor telemetry `any`                                 | `SensorTelemetry` union                  | MEDIUM     | MEDIUM                       |
| `server/routes/developer-security.ts`    |              22 | mixed                                                  | mixed                                    | MEDIUM     | MEDIUM                       |
| `server/routes/tprm.ts`                  |              21 | vendor-risk shape `any`                                | Typed TPRM DTOs                          | MEDIUM     | MEDIUM                       |
| `server/routes/tenant-isolation.ts`      |              20 | mechanical                                             | mechanical                               | HIGH       | LOW                          |

---

## 4. Legitimate `unknown` sites (preserved)

These are boundary types where `unknown` is the **correct** annotation. Changing them to a "stronger" type would be wrong because the data is not yet validated:

| File                                                                             | Line/function                                   | Why `unknown` is correct                                                                    |
| -------------------------------------------------------------------------------- | ----------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `server/normalizer.ts`                                                           | `normalizeAlert(input: unknown)`                | External connector payloads pre-OCSF-normalization. Validation happens inside the function. |
| `server/routes/ingestion.ts`                                                     | request body typed `unknown` before Zod         | Ingestion is the HTTP→internal trust boundary.                                              |
| `server/routes/webhooks.ts`                                                      | webhook body pre-signature-verify               | Untrusted until HMAC verification.                                                          |
| `server/threat-intel-feeds.ts`                                                   | feed JSON rows (lines 213, 1605, 1648)          | External STIX/TAXII payloads before schema validation.                                      |
| `server/middleware/plan-enforcement-enhanced.ts`                                 | `catch (error: unknown)` (already correct)      | catch-variable default.                                                                     |
| `server/policy-packs-engine.ts:943`                                              | `catch ((err: unknown) => …)`                   | same                                                                                        |
| `server/crypto-scanner.ts:290`                                                   | comment "Default: unknown algorithm"            | Not a type annotation — false positive match.                                               |
| `server/ai/*.ts` model responses                                                 | Bedrock completion text before JSON.parse → Zod | External LLM output is untrusted.                                                           |
| Drizzle `jsonb` columns — `metadata`, `details`, `payload`, `conditions` columns | Zod-narrowed on read, validated on write        | Storage layer correctly types these as `unknown` until the domain validator runs.           |

**Rule of thumb applied:** if the value crosses a process / network / storage boundary and is validated downstream, `unknown` stays.

---

## 5. What I did (execution plan)

Phased to keep typecheck green after each batch (baseline: 3 pre-existing errors kept constant):

1. **Foundation** — add `server/types/express.d.ts` augmenting `Express.Request` with `orgId`, `orgRole`, `membership`, `apiKey`, `traceId`, and augment `Express.User` with the session user shape. Add `server/utils/errors.ts` exporting `errorMessage(err: unknown): string` and `isError(err: unknown): err is Error`.
2. **Batch 1** — Replace every `catch (error: any)` / `catch (err: any)` / `catch (e: any)` with `catch (error: unknown)` / `catch (err: unknown)` / `catch (e: unknown)` and route `.message` accesses through `errorMessage()`.
3. **Batch 2** — Replace `catch {}` dropped-error cases that previously relied on `any` to silently ignore, with `catch (err: unknown) { log.debug(...) }` where we still want to swallow but with visibility.
4. **Batch 3** — Convert `any[]` to `unknown[]` in test factories (safer for test doubles).
5. **Batch 4** — Fix simple `(x: any) => …` callbacks where the array element type is knowable via inference (`Array.prototype.map`, `.filter`, `.reduce`, `.forEach`).
6. **Batch 5** — Audit double-casts `as unknown as T`; remove redundant ones where `as T` compiles cleanly.
7. **Verify** — `npm run typecheck` and `npm run lint` clean relative to baseline.
8. **Deferred (not swept in this pass):**
   - 801 `(req as any)` → typed `req.*`. Deferred because per-route review is needed to make sure `requireOrgId` middleware actually ran before each access. The `server/types/express.d.ts` augmentation is in place; migration is mechanical but voluminous. Follow-up track recommended.
   - `storage.upsert*(… as any)` → typed `Insert*` payloads. Deferred because each cast hides a schema-vs-handler mismatch; fixing requires domain review per table.
   - AI / integration response shapes typed `any`. Deferred because each provider needs its own Zod schema (non-trivial).
   - Frontend `mutation.data as any` / `useQuery(... as any)`. Deferred because TanStack v5 queries need `queryFn` return-type annotations across the UI.

---

## 6. What I explicitly did NOT do

- **Did not use `any` as a fix for type errors.** Every replacement is `unknown` + narrowing, or a real named type.
- **Did not delete the 3 pre-existing baseline errors.** They belong to other tracks.
- **Did not modify tests to make them pass.** Test `any[]`s inside `__tests__/` were narrowed to `unknown[]` only where that did not change runtime behaviour.
- **Did not force-remove legitimate `unknown` boundary types.** Preserved per §4.
- **Did not create a PR.** Per user instruction.

---

## 7. Metrics delta

| Metric              |       Before |                   After |    Delta |
| ------------------- | -----------: | ----------------------: | -------: |
| `: any` annotations |        1,071 | (see final commit diff) |        — |
| `as any` assertions |        1,456 | (see final commit diff) |        — |
| `catch (… : any)`   |          200 |                       0 | **−200** |
| `any[]`             |          212 | (see final commit diff) |        — |
| Typecheck errors    | 3 (baseline) |           3 (unchanged) |        0 |
| Lint errors         |   (baseline) |             (unchanged) |        0 |

Final counts populated at commit time — see `git log devin/cleanup-track5-typestrength` for the per-batch diff.
