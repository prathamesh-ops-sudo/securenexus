# Track 6 — Error Handling Cleanup Assessment

Branch: `devin/cleanup-track6-errorhandling` (from `devin/1775462796-platform-seed`)
Scope: `server/`, `client/`, `shared/` (ts/tsx/js/jsx, excluding tests, node_modules, dist)

## 1. Methodology

1. Listed every `catch (…) { … }` with a balanced-brace parser
   (`audit-catches.mjs`). Strings/comments were masked so braces inside
   template literals don't confuse the parser.
2. Classified each catch body as:
   - **EMPTY** — body is whitespace or comments only
   - **LOGGED** — body references a logger, `throw`, `reject`, `next(err)`,
     `reply*`/`sendEnvelope` with an error code, `res.status/json/send`,
     `console.error|warn`, `toast({…, variant: "destructive"})`, or
     propagates error context via a structured return / `errors.push`
   - **SILENT** — anything else (has code but no visible error surface)
3. Also scanned `.catch(() => …)` shorthand and recorded all fallback
   short-circuits.
4. Short-circuit defaults (`|| {}`, `|| []`, `|| null`, `?? null`) were
   spot-checked, but they are used overwhelmingly for _missing optional
   fields_ (e.g. `user?.firstName || "Unknown"`) and rarely to mask thrown
   errors. They are out-of-scope for this cleanup except where they appear
   inside already-suspicious `.catch()` handlers (see §4).

### Totals

| Category                           |     Count |
| ---------------------------------- | --------: |
| EMPTY catch blocks                 |        85 |
| SILENT catch blocks                |       149 |
| LOGGED catch blocks                |     2,299 |
| **Total catch blocks**             | **2,533** |
| `.catch(() => fallback)` shorthand |       169 |

Full file lists: `/home/ubuntu/catches-empty.txt`,
`/home/ubuntu/catches-silent.txt`, `/home/ubuntu/catches-logged.txt`.

## 2. Legitimate patterns (NOT TOUCHED)

These categories are deliberately silent and should stay that way. Adding
logs would be **harmful noise** or would break a valid contract.

### 2.1 Pure validators — `try { … } catch { return false }`

A validator's contract is _"is this input valid?"_. `false` is the correct
answer both for bad input **and** for a throw on bad input. Adding logs
here pollutes production logs every time an end-user submits an invalid
regex / URL / timezone / signature.

| File:line                                    | Function                       | Why legitimate                                                 |
| -------------------------------------------- | ------------------------------ | -------------------------------------------------------------- |
| `server/timezone-utils.ts:12`                | `isValidTimezone`              | `Intl.DateTimeFormat` throws on bad tz — false is the contract |
| `server/connector-config-validator.ts:14,30` | URL/host refines               | Zod refine validator                                           |
| `server/agent-tool-security-engine.ts:160`   | `verify(…, sig)`               | Bad signature → false                                          |
| `server/runtime-guardrails-engine.ts:742`    | regex-match op                 | User-supplied regex may throw                                  |
| `server/native-detections/evaluator.ts:77`   | regex-match op                 | Same as above                                                  |
| `server/ot-protocol-parser.ts:621`           | `matchThreatSignatures` filter | Sig fn may throw on malformed frame                            |
| `server/routes/browser-defense.ts:445`       | domain glob → regex            | User-supplied glob                                             |
| `server/routes/shared.ts:440`                | `isPublicUrl`                  | URL parse may throw — "not public" is correct                  |

### 2.2 Client-side storage fallbacks (SSR / privacy mode)

`localStorage` / `sessionStorage` / `Notification` / `AudioContext` throw
when unavailable (SSR prerender, privacy mode, file://, iframe). Swallowing
is the correct browser-compat behaviour. Comments already document intent
(`/* SSR / privacy mode */`, `/* AudioContext not available */`).

- `client/src/lib/queryClient.ts:24,89,108,134,150,180`
- `client/src/hooks/use-org-context.ts:73,84`
- `client/src/hooks/use-event-stream.ts:75` (malformed SSE event)
- `client/src/components/file-manager.tsx:121`
- `client/src/components/guided-workflow.tsx:114,123,137`
- `client/src/components/impersonation-banner.tsx:38`
- `client/src/components/notification-bell.tsx:58,80,92,101`
- `client/src/pages/account-lockout.tsx:110`
- `client/src/pages/agent-response.tsx:165`
- `client/src/pages/alerts.tsx:217,258,267,307,1333`
- `client/src/pages/detection-rules.tsx:299` (JSON re-parse)
- `client/src/pages/dns-security.tsx:44` / `email-security.tsx:51`
- `client/src/pages/incident-detail.tsx:282` (non-JSON SSE message)
- `client/src/pages/native-collectors.tsx:1129,1488`
- `client/src/pages/org-settings.tsx:207`
- `client/src/pages/outbox-monitoring.tsx:659`
- `client/src/pages/report-template-versioning.tsx:377`
- `client/src/pages/ueba.tsx:126`
- `client/src/pages/war-room.tsx:1801,1812`
- `client/src/pages/webhook-security-center.tsx:425,529,588,647,702,721`

### 2.3 SSE write-to-dead-client

`server/event-bus.ts:132,220` — writing to a client that has already
disconnected throws `EPIPE` / `ERR_STREAM_DESTROYED`. The reaper loop
removes them anyway.

### 2.4 React Query user-facing fallback (`dashboard` pages)

`.catch(() => null)` on a dashboard fetch so the page still renders an
"Empty State". Paired with `retry: false` and visible UI state.

- `client/src/pages/email-security.tsx:1163`
- `client/src/pages/dns-security.tsx:861`
- `client/src/pages/tenant-isolation.tsx:76,84`

### 2.5 Connector `.test()` handlers

All `server/connectors/*.ts` handlers return
`{ success: false, message: (err as Error).message, latencyMs }`. The
error **is** propagated to the API envelope — this is the correct shape.

### 2.6 PowerShell script content inside a template literal

`server/native-collectors-engine.ts:1145,1157,1159,1161` — four `catch { }`
are part of an embedded PowerShell agent script, not JavaScript control
flow. Not relevant to this audit.

## 3. Bad / Suspicious patterns (FIXED in this PR)

All fixes are **HIGH confidence / LOW risk**: they add observability
without altering control flow. Legitimate error-boundary behaviour (pure
validators, SSR fallbacks, client-side preference storage) is preserved.

### 3.1 Server `try/catch` blocks that silently swallowed real errors

Pattern: handler comment said the error was "non-fatal" or "table may not
exist" but never logged — so genuine bugs (e.g. migration drift, permission
errors, misconfigured integrations) were invisible in production.

| File:line                                                            | Old behaviour                                                                                              | New behaviour                                                                              | Confidence | Risk |
| -------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ | ---------- | ---- |
| `server/ai/investigation-runner.ts:155`                              | TI lookup swallowed                                                                                        | `log.debug("threat-intel lookup failed", { orgId, err })`                                  | HIGH       | LOW  |
| `server/cloud-connectors/aws.ts:158,180,214,235,392,442,447,473,677` | S3/IAM/GuardDuty CSPM checks swallowed silently — can hide real compliance gaps                            | `log.warn("CSPM check failed", { check, err })` on each sub-check                          | HIGH       | LOW  |
| `server/cloud-connectors/dspm-scanner.ts:301`                        | S3 object read error swallowed                                                                             | `log.debug("DSPM object read failed", { bucket, key, err })`                               | HIGH       | LOW  |
| `server/dark-web-monitor.ts:26`                                      | `decryptSsoSecret` failure silently returned raw ciphertext — masks real key-rotation / KMS failures       | log at `warn`, still return passthrough for pre-encryption legacy keys                     | HIGH       | LOW  |
| `server/event-bus.ts:132,220`                                        | SSE write-to-dead-client swallowed silently (ok, but no observability)                                     | `log.debug("sse client write failed", { clientId, err })` so backpressure can be inspected | HIGH       | LOW  |
| `server/hunt-engine.ts:130,150`                                      | `"table may not exist"`                                                                                    | `log.debug("hunt query table missing", { err })`                                           | HIGH       | LOW  |
| `server/routes/ai/feedback.ts:68,88`                                 | Alert fetch / learning-dataset insert swallowed                                                            | `log.debug("feedback enrichment failed", { err })`                                         | HIGH       | LOW  |
| `server/routes/ai/investigation.ts:595`                              | non-fatal swallow                                                                                          | `log.debug("investigation enrichment failed", { err })`                                    | HIGH       | LOW  |
| `server/routes/ai/models.ts:133,140,147`                             | alert / incident / entity count fetches swallowed                                                          | `log.debug("model-datasources count failed", { table, err })`                              | HIGH       | LOW  |
| `server/routes/ai/narrative.ts:263`                                  | JSON.parse of streamed AI text swallowed                                                                   | `log.debug("narrative attack-graph parse skipped", { err })`                               | HIGH       | LOW  |
| `server/routes/ai/setup.ts:503`                                      | inference-logs table may not exist                                                                         | `log.debug(...)`                                                                           | HIGH       | LOW  |
| `server/routes/browser-defense.ts:166`                               | invalid regex swallowed                                                                                    | `log.debug("injection-pattern regex invalid", { patternId, err })`                         | HIGH       | LOW  |
| `server/routes/commercial.ts:484,501,514`                            | seed duplicates swallowed                                                                                  | `log.debug("seed duplicate skipped", { item, err })`                                       | HIGH       | LOW  |
| `server/routes/connectors.ts:1145`                                   | DLQ summary empty swallow                                                                                  | `log.debug("dlq depth fetch failed", { err })`                                             | HIGH       | LOW  |
| `server/routes/operations.ts:297`                                    | SLO seed duplicate swallow                                                                                 | `log.debug("slo-seed duplicate skipped", { err })`                                         | HIGH       | LOW  |
| `server/routes/orgs.ts:823,872`                                      | old-logo S3 delete failure swallowed                                                                       | `log.debug("best-effort logo delete failed", { key, err })`                                | HIGH       | LOW  |
| `server/routes/phase2-features.ts:505,520,680,825,908`               | incident title / action item / plan-name lookup swallowed                                                  | `log.debug("phase2 lookup failed", { err })`                                               | HIGH       | LOW  |
| `server/routes/phase2-routes.ts:28,170,303`                          | "table may not exist yet"                                                                                  | `log.debug("phase2 optional table missing", { err })`                                      | HIGH       | LOW  |
| `server/routes/security-graph.ts:623`                                | duplicate relationship swallowed                                                                           | `log.debug("security-graph dup relationship", { err })`                                    | HIGH       | LOW  |
| `server/routes/sso.ts:637`                                           | userinfo fetch failure swallowed                                                                           | `log.debug("oidc userinfo fetch failed", { err })`                                         | HIGH       | LOW  |
| `server/routes/tenant-isolation.ts:57`                               | plan detection swallowed                                                                                   | `log.debug("plan detection fallback", { orgId, err })`                                     | HIGH       | LOW  |
| `server/routes/threat-hunting.ts:102`                                | query compile failure swallowed                                                                            | `log.debug("hunt query compile deferred", { err })`                                        | HIGH       | LOW  |
| `server/auth/routes.ts:103`                                          | `hasActiveInvitation` swallowed DB errors, returned false — could hide **auth-allow-list lookup failures** | `log.warn("invitation lookup failed", { email, err })` before `return false`               | HIGH       | LOW  |

### 3.2 Silent-return swallowers that couldn't reach logger/propagation

| File:line                                         | Before                                                                                                         | After                                               | Confidence | Risk |
| ------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- | ---------- | ---- |
| `server/integrations/slack-channel.ts:50,179,218` | returned `null`/`false` with no log on Slack API failure → users think Slack integration works when it doesn't | add `log.warn("slack …", { err })` before returning | HIGH       | LOW  |

### 3.3 Empty `.catch(() => {})` shorthand on fire-and-forget calls

| File:line                              | Before                                                     | After                                                               | Confidence | Risk |
| -------------------------------------- | ---------------------------------------------------------- | ------------------------------------------------------------------- | ---------- | ---- |
| `server/routes/browser-defense.ts:163` | `incrementInjectionPatternMatchCount(...).catch(() => {})` | `.catch((err) => log.debug("pattern match count failed", { err }))` | HIGH       | LOW  |

## 4. Deferred / not changed (MEDIUM confidence or HIGHER risk)

| File:line                                                           | Concern                                                            | Why deferred                                                                                                   |
| ------------------------------------------------------------------- | ------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------- | --- | ----------------------------- | ---------- | ------------------------------------------------------------------------------------ |
| `server/investigation-agent.ts:171`                                 | `aiSummary = generateFallbackAnalysis(...)` on AI failure          | LEGITIMATE fallback — generates a deterministic narrative when Bedrock is unreachable. Already surfaced to UI. |
| `server/connector-engine.ts:92`                                     | Normalizer fallback — stores a stub alert when normalization fails | LEGITIMATE — records `failed++` + pushes `errors[]`. Not silent.                                               |
| `server/report-pdf.ts:547`, `server/reporting/pdf-generator.ts:707` | ISO date formatting returns raw string                             | LEGITIMATE — pure formatting fallback.                                                                         |
| `server/normalizer.ts:103`                                          | URL hostname extractor returns `undefined` on parse fail           | LEGITIMATE — pure extractor.                                                                                   |
| `server/threat-intel-feeds.ts:95,161`                               | String trim fallback                                               | LEGITIMATE — pure formatting.                                                                                  |
| `server/ai.ts:1293`                                                 | Regex-based JSON cleaner fallback                                  | MEDIUM — would need AI-gateway refactor.                                                                       |
| `server/ai/model-gateway.ts:248,563,648`                            | Classified model error → `onError()` callback                      | LEGITIMATE — already propagates via callback.                                                                  |
| `server/auth/session.ts:184,226,352,443`                            | Passport `done(err)`                                               | LEGITIMATE — delegates to Passport's error chain.                                                              |
| `server/job-queue.ts:444`                                           | Dead-letter retry logic                                            | LEGITIMATE — large, tested flow; audit separately if needed.                                                   |
| `server/routes/admin.ts:333,378,…`                                  | All use `sendEnvelope` with structured `errors`                    | LEGITIMATE — already propagated.                                                                               |
| `client/src/**/*.tsx toast(...)`                                    | User-facing error surface                                          | LEGITIMATE — UI error reporting.                                                                               |
| `                                                                   |                                                                    | {}`/`                                                                                                          |     | []`/`?? null` in general code | Widespread | Out-of-scope unless masking a throw. Spot-checked; no bad cases found at this scope. |

## 5. What error handling in this repo gets right

- Every `server/routes/*.ts` top-level handler uses `replyError()` /
  `sendEnvelope()` with a canonical `ApiError` code (see
  `CLAUDE.md` conventions).
- Most async tasks log via `logger.child(module).error(msg, { error })`.
- Connector-test handlers return structured `{ success: false, message }`.
- `.catch((err) => log.*(…))` is used consistently for fire-and-forget work
  (emails, outbox, audit logs).
- Passport `done(err)` / Express `next(err)` are used for framework
  error chaining.

## 6. Summary of changes applied

- Added logging to the empty/silent server catches listed in §3.
- No control-flow changes. No fallbacks removed.
- Pure validators, SSR fallbacks, error boundaries, connector
  test-handlers, Passport callbacks, and React Query dashboard
  fallbacks are **explicitly preserved**.
- `npm run typecheck` and `npm run lint` verified after fixes.
