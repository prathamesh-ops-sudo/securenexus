# Track 7: Deprecated Code & AI Slop Removal — Assessment

## Executive Summary

Audited `server/`, `client/`, and `shared/` directories for deprecated/legacy code paths and AI-generated artifacts. The dominant issue is **~300+ AI narration comments** across **81 files** following a sprint-numbering pattern (`// XX.Y — Description` or `{/* XX.Y — Description */}`), plus a commented-out analytics snippet in `landing.tsx`. Legacy/deprecated code paths are almost entirely **active production code** (API versioning, AI fallback resilience, domain-model statuses) and should NOT be removed.

---

## 1. Deprecated / Legacy Code Paths

### 1.1 `legacyHeaders: false` in helmet/rate-limit configs

- **Files**: `server/security-middleware.ts:172`, `server/routes/shared.ts:46,55,63`, `server/routes/entities.ts:257`, `server/index.ts:101`
- **What**: helmet/express-rate-limit option disabling legacy headers
- **Safe to remove?** NO — current library best practice, not deprecated code
- **Confidence**: HIGH | **Risk**: HIGH
- **Action**: KEEP

### 1.2 `legacyEndpoint()` middleware + legacy API routes

- **Files**: `server/api-response.ts:167-185`, `server/openapi.ts:296,401,474,1268,1518`, `server/routes/api-versioning.ts`
- **What**: Backward-compatibility layer for pre-v1 API consumers. Returns `Deprecation`/`Sunset` headers pointing to v1 successors.
- **Safe to remove?** NO — external consumers depend on `/api/alerts`, `/api/incidents`, etc.
- **Confidence**: HIGH | **Risk**: HIGH (breaks API consumers)
- **Action**: KEEP

### 1.3 `legacySimulateEdrAction()` in action-dispatcher.ts

- **Files**: `server/action-dispatcher.ts:493-654`
- **What**: Fallback when no native sensor is deployed — simulates EDR response action
- **Safe to remove?** NO — actively used for orgs without agents
- **Confidence**: HIGH | **Risk**: HIGH
- **Action**: KEEP

### 1.4 AI heuristic fallback handlers

- **Files**: `server/ai.ts` (6 fallback paths), `server/ai/fallback.ts`, `server/ai/model-gateway.ts`, `server/routes/ai/{investigation,triage,narrative,feedback}.ts`
- **What**: When Bedrock fails/times-out, returns heuristic/cached responses instead of crashing
- **Safe to remove?** NO — critical resilience pattern
- **Confidence**: HIGH | **Risk**: HIGH
- **Action**: KEEP

### 1.5 `deprecated` as a domain concept (not dead code)

- **Files**: `shared/schema.ts` (12 refs), `server/ai/prompt-registry.ts` (26 refs), `server/event-catalog.ts`, `server/routes/model-gateway.ts`, `server/routes/api-security.ts`, `server/routes/ai-detection-rules.ts`, `server/policy-packs-engine.ts`, several `client/src/pages/*`
- **What**: "deprecated" is a valid status/enum in the data model (prompts, playbook versions, report templates, API endpoints, marketplace items, data flows). Users mark items as deprecated through the UI.
- **Safe to remove?** NO — active domain status, not dead code
- **Confidence**: HIGH | **Risk**: HIGH
- **Action**: KEEP

### 1.6 `backwards-compat` comment in war-room.ts

- **File**: `server/routes/war-room.ts:136`
- **What**: JSDoc explaining the response shape preserves the old in-memory format for existing clients
- **Safe to remove?** NO — comment explains genuine intent (client API contract)
- **Confidence**: HIGH | **Risk**: MEDIUM
- **Action**: KEEP

### 1.7 UEBA off-hours fallback comment

- **File**: `server/routes/ueba.ts:268`
- **What**: Comment documents the exact UTC hour boundaries to match legacy 2–5 AM behavior. Valid intent documentation.
- **Safe to remove?** NO — valuable business-rule note
- **Action**: KEEP

### 1.8 TODO stubs in mssp-portal.ts

- **File**: `server/routes/mssp-portal.ts:579, 581`
- **What**: `const aiAnalyses = 0; // TODO: integrate with AI usage tracking` and `const storageGb = 0; // TODO: integrate with storage metering` — hardcoded zeros used in MSSP markup billing calc
- **Safe to remove?** NO — removing the constants would break the billing subtotal calculation. These are placeholders feeding real math.
- **Confidence**: MEDIUM (constants are used) | **Risk**: HIGH (breaking billing)
- **Action**: KEEP (both constant and comment) — documents real unfinished feature work

### 1.9 Feature flags (`server/feature-flags.ts`)

- **Finding**: No always-on/always-off dead flags detected during audit — all flag callsites appear to drive real branching.
- **Action**: KEEP

---

## 2. AI-Generated Artifacts

### 2.1 Sprint/epic version-numbered narration comments (MAIN ISSUE)

- **Pattern**: `// XX.Y — Description` (TS) and `{/* XX.Y — Description */}` (TSX), where `XX.Y` is a sprint/epic identifier that maps to nothing in the codebase
- **Scale**: ~300+ occurrences across 81 files (complete list below)
- **Examples**:
  - `// 40.1 — Delivery history with filtering` above `/api/v1/webhooks/:id/delivery-history` route
  - `// 8.2 — Incident Response Lifecycle` as section header in schema.ts
  - `{/* 71.2 — DGA Detection Visualization */}` in DNS security page
  - `{/* 94.8 — Google Analytics / Mixpanel integration hints */}` in landing page
- **Why AI slop?** No human would prefix comments with "XX.Y —" — this is roadmap/PR tracking that leaked from sprint-planning docs (enterprise.md, ultimate.md) into code
- **Safe to remove?** YES — pure narration, code is self-documenting
- **Confidence**: HIGH | **Risk**: LOW
- **Action**: **STRIP the `XX.Y — ` prefix**. Keep the descriptive text only if it adds steady-state intent beyond what the code says; otherwise remove the whole comment.

**Affected files** (81 total):

- `shared/schema.ts` (4)
- `server/storage/{incidents,compliance,organizations,reports,playbooks,evidence}.ts` (10)
- `server/routes/{webhooks,tprm,ransomware-defense,security-awareness,threat-hunting,quantum-readiness,standalone-platform,physical-security,posture-trust,operations,ot-security,mobile-security,mssp,email-security,ingestion,incidents,api-security,developer-security,autonomous-soc,community-intel,dark-web,autonomous,data-lake,dns-security,deception,ai-detection-rules,agent-response,admin}.ts` (~130)
- `server/{soc-copilot-engine,data-discovery}.ts` (10)
- `client/src/pages/{email-security,dns-security,usage-metering-analytics,tprm,tiered-packaging,threat-reports,trust-center,team-management,security-chaos-engineering,security-assessments,security-awareness,settings,quantum-readiness,ransomware-defense,reports,privacy-engineering,outbox-monitoring,policy-packs,posture-trust-center,ot-security,physical-security,mssp-partner-portal,org-settings,mobile-security,onboarding-wizard,mfa-setup,landing,mssp-dashboard,job-queue-dashboard,gap-analysis,developer-portal,developer-security,data-residency,dark-web-monitoring,deception,community-intel,compliance,board-dashboard,billing,audit-log,autonomous-soc,asset-inventory,ai-detection-rules,advanced-reporting,soc-copilot,ai-engine,connectors}.tsx` (~150)

### 2.2 Commented-out Google Analytics code

- **File**: `client/src/pages/landing.tsx:404-406`
- **What**: Dead HTML/JS for Google Analytics / Mixpanel integration, commented out, with `{/* 94.8 — ... */}` narration header
- **Safe to remove?** YES — dead code, not imported or toggled anywhere
- **Confidence**: HIGH | **Risk**: LOW
- **Action**: REMOVE

### 2.3 Obvious JSX section comments (`{/* Header */}`, `{/* Stats */}`, `{/* Tabs */}`)

- **Scope**: ~100+ single-word JSX comments that describe the immediately-following JSX
- **Examples**: `{/* Header */}`, `{/* Tabs */}`, `{/* Stats */}`, `{/* Messages */}`, `{/* Input */}`, `{/* Footer */}`
- **Safe to remove?** AMBIGUOUS — some are useful (e.g., `{/* Auth Modal */}` before a 100-line modal block), some are noise (e.g., `{/* Header */}` before `<Header />`)
- **Confidence**: MEDIUM | **Risk**: LOW
- **Action**: **KEEP** — too subjective; would create large diff without clear value. These are standard React-convention breadcrumbs, not AI-specific.

### 2.4 Verbose narration comments in route handlers

- **Examples**:
  - `// Would track retries in production` (webhooks.ts:386)
  - `// Placeholder — actual response time would come from delivery tracking` (webhooks.ts:387)
  - `// placeholder — real implementation would check CA support` (admin.ts:154)
- **Safe to remove?** These flag genuinely-unfinished features. Removing would hide that the values are stubs.
- **Confidence**: MEDIUM | **Risk**: MEDIUM
- **Action**: KEEP — they correctly mark stub values

### 2.5 Debug `console.log` statements

- **Scope audited**: `server/`, `client/`, `shared/`
- **Finding**: ZERO debug `console.log` in production code. Only match is inside a code-example string literal in `client/src/pages/developer-portal.tsx:853` (it's documentation shown to users, not actual code). ESLint already enforces `no-console` with `warn`/`error` allowed.
- **Action**: NONE — already clean

### 2.6 Commented-out code blocks

- **Finding**: Only one material block found (`landing.tsx:404-406`, covered in 2.2). No other significant dead-code blocks detected in a repo of this size.
- **Action**: Covered by 2.2

### 2.7 Edit-narration comments (`// Added by PR #X`, `// Fixed in commit abc`)

- **Finding**: ZERO matches for patterns like `// Added by`, `// Fixed in`, `// Updated to`, `// Previously`, `// Now we`, `// PR #`, `// commit <sha>`
- **Action**: NONE — already clean

---

## 3. Summary of Planned Removals

| Category                                                    | Confidence | Risk   | Count                | Action                                                 |
| ----------------------------------------------------------- | ---------- | ------ | -------------------- | ------------------------------------------------------ |
| Version-numbered narration (`// XX.Y —` / `{/* XX.Y — */}`) | HIGH       | LOW    | ~300 across 81 files | **Strip prefix**; drop comment if remainder is obvious |
| Commented-out GA snippet in `landing.tsx`                   | HIGH       | LOW    | 1 block (3 lines)    | **Remove**                                             |
| Deprecated code paths (§1.1–§1.9)                           | —          | HIGH   | N/A                  | **KEEP** (active code)                                 |
| Obvious JSX section markers (`{/* Header */}`)              | MEDIUM     | LOW    | ~100+                | KEEP (not AI-specific)                                 |
| Stub/placeholder comments on unfinished features            | MEDIUM     | MEDIUM | ~5                   | KEEP (correctly flag work)                             |
| Debug `console.log`                                         | —          | —      | 0                    | None found                                             |
| Edit-history comments                                       | —          | —      | 0                    | None found                                             |

---

## 4. Implementation Results

Two passes were executed over `server/`, `client/`, and `shared/` (`*.ts` and `*.tsx` files):

**Round 1** (`/tmp/strip-ai-slop.mjs`): stripped `XX.Y —` / `XX.Y:` prefixes from `//` and `{/* */}` single-line comments, including box-drawing decorated variants (`// ── 37.5: Foo ──`). Preserved indentation; dropped comments that became empty.

- **Result**: 766 comments rewritten across 114 files, zero failures.

**Round 2** (`/tmp/strip-ai-slop-round2.mjs`): targeted patterns round 1 missed:

- Block `/* XX.Y — text */` comments (non-JSX)
- JSX comments with stray leading punctuation: `{/* , 73.2 — ... */}`
- Inline version numbers inside existing JSX comments: `{/* Navigation — 94.3: responsive, 94.4: aria roles */}` → `{/* Navigation — responsive, aria roles */}`
- User-visible JSX text that accidentally kept a version prefix: `62.1 — Describe your detection intent…` → `Describe your detection intent…`
- Intentionally restricted separators to `[—–:]` (no ASCII hyphen) to avoid damaging divider comments like `// ---------- mocks ----------`.
- **Result**: 56 more lines rewritten across 16 files.

**Manual edits**:

- `client/src/pages/landing.tsx`: removed the dead Google Analytics / Mixpanel commented-out `<script>` block (3 lines) and its now-empty `handleContactSubmit` comment + two commented-out `window.gtag` / `window.mixpanel` placeholders inside the handler.

**Total**: 822 comment/text lines rewritten or removed across 115 files. Zero runtime/logic changes — all modifications are to comments, JSX copy prefixes, and one dead commented-out script block.

## 5. Verification

- `npm run typecheck` → 3 errors, all pre-existing on base (`server/routes/connectors.ts:442,463` + `server/routes/security-graph.ts:618`). Zero new errors introduced.
- `npm run lint` → 2 errors, both pre-existing on base (`commitlint.config.js`, `scripts/migrate.ts`). Zero new errors introduced.
- Divider comments (`// ---------- mocks ----------`, `// --- Mocks ---`, etc.) verified intact across `server/__tests__/`.

Final totals: **822 lines rewritten/removed across 115 files** (766 round 1 + 56 round 2). Zero new typecheck or lint errors; zero runtime impact.
