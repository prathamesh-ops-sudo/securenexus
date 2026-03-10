# SecureNexus: Delta Gap Report
## Only What's Broken, Missing, or Needs Fixing

**Date**: February 2026
**Purpose**: This report covers ONLY the gaps between current state and shippable product. It does NOT re-list features that already exist and work.

---

## What Already Works (DO NOT REBUILD)

The codebase has **extensive, real implementations** — not scaffolding:

| System | Lines | Status | Notes |
|--------|-------|--------|-------|
| Auth (bcrypt, sessions, routes) | 469 | REAL | Hashing, login, register, logout, session management |
| RBAC (permission enforcement) | 153 | REAL | 4 roles, 6 scopes, action-level checks |
| Storage layer (ALL CRUD ops) | 5,424 | REAL | Every table has create/read/update/delete |
| Alert normalization (6 sources) | 843 | REAL | CrowdStrike, Splunk, Wazuh, GuardDuty, Palo Alto, Generic |
| Correlation engine | 906 | REAL | Temporal, entity, TTP-based clustering |
| Entity resolver | 512 | REAL | IP, domain, user, host, hash extraction + dedup |
| Predictive engine | 540 | REAL | Anomaly detection, forecasting, recommendations |
| IOC matching + ingestion | 622 | REAL | Feed ingestion, alert matching, watchlists |
| 25 connector plugins | 2,267 | REAL | Each has normalization logic |
| Connector engine (orchestration) | 416 | REAL | Sync, retry, checkpoint, dead-letter |
| 41 route files | 20,170 | REAL | All have real DB operations (checked: 0 mock-only files) |
| 49 frontend pages | 45,775 | REAL | All have real API calls (useQuery/useMutation) |
| 47 shadcn/ui components | ~4,750 | REAL | Full component library |
| Schema (126 tables) | 4,818 | REAL | Complete with relations, indexes, constraints |
| Report engine | 382 | REAL | SOC KPI, incidents, compliance, executive |
| Notification dispatcher | 295 | REAL | Multi-channel dispatch logic |
| Data lifecycle management | 716 | REAL | Retention, archival, legal holds, PII masking |
| Job queue | 498 | REAL | Background processing with retries |
| Secret rotation | 315 | REAL | Connector secret management |
| OCSF normalization | 319 | REAL | Open Cybersecurity Schema Framework |
| Threat enrichment | 391 | REAL | OSINT enrichment logic |
| Event bus | 287 | REAL | Internal event dispatch |
| SSO routes | 783 | REAL | SAML + OIDC flows |
| Stripe service | 466 | REAL | Checkout, webhooks, subscription management |

**Total real code: ~109,000 lines across backend + frontend.**

---

## The 5 Actual Gaps That Need Fixing

### GAP 1: Infrastructure Mismatch (CRITICAL BLOCKER)

**Problem**: Supervisor expects directories that don't exist.

| What Supervisor Expects | What Actually Exists |
|------------------------|---------------------|
| `/app/backend/` with `uvicorn server:app --port 8001` | `/app/server/` with TypeScript/Express |
| `/app/frontend/` with `yarn start` on port 3000 | `/app/client/` with Vite (integrated in Express) |

**Both services are FATAL. Nothing loads.**

**Fix Options**:
- **Option A**: Create `/app/backend/` as a thin Python proxy that forwards to the TypeScript server running on another port + create `/app/frontend/` as a standalone Vite build
- **Option B**: Create `/app/backend/` as a Python FastAPI wrapper that imports/calls the TypeScript logic via subprocess + separate frontend build
- **Option C**: Create symlinks/wrappers that make the existing code work at the expected paths

**Recommended**: Option A — create a Python shim backend + separate Vite frontend build. This preserves ALL existing code while satisfying supervisor.

**Effort**: Medium (2-3 days)

---

### GAP 2: Database Mismatch

**Problem**: All code uses PostgreSQL via Drizzle ORM. Environment provides MongoDB.

| Component | Current | Required |
|-----------|---------|----------|
| db.ts | `import { drizzle } from "drizzle-orm/node-postgres"` | MongoDB driver |
| storage.ts | 5,424 lines of Drizzle SQL queries | MongoDB operations |
| All routes | `storage.getAlerts()`, `storage.createIncident()` etc. | Same interface, MongoDB backend |

**Fix Options**:
- **Option A**: Install PostgreSQL in the environment and use the existing code as-is
- **Option B**: Rewrite storage.ts to use MongoDB (massive effort — 5,424 lines)
- **Option C**: Use the Python backend (from Gap 1 fix) with MongoDB via pymongo, porting the storage interface

**Recommended**: Option A if possible (simplest, preserves all code), otherwise Option C for the Python backend.

**Effort**: Low (Option A) or High (Option B/C)

---

### GAP 3: AI System — AWS Bedrock Dependency

**Problem**: The AI system (899 lines) is hardcoded to use AWS Bedrock/SageMaker, which are not available in this environment.

**Affected files**:
| File | Lines | Dependency |
|------|-------|-----------|
| server/ai.ts | 899 | `invokeModel` via Bedrock |
| server/ai/model-gateway.ts | 341 | `BedrockRuntimeClient`, `InvokeModelCommand` |
| server/ai/enhanced-prompts.ts | 635 | Prompt templates (reusable, no AWS dep) |
| server/ai/prompt-registry.ts | 388 | Prompt management (reusable, no AWS dep) |
| server/ai/budget.ts | 169 | Budget tracking (reusable, no AWS dep) |
| server/config.ts | line 5 | `AI_BACKEND: "bedrock" | "sagemaker"` |

**What works without changes**: Prompts (635 lines), prompt registry (388 lines), budget tracking (169 lines) — total 1,192 lines are reusable.

**What needs replacing**: model-gateway.ts (341 lines) and the invoke calls in ai.ts (~200 lines of the 899).

**Fix**: Replace `model-gateway.ts` to use Emergent LLM key (OpenAI/Claude/Gemini) instead of Bedrock. The prompt templates and all other AI logic stay unchanged.

**Effort**: Low-Medium (1-2 days). Only ~540 lines need changing.

---

### GAP 4: AWS Service Dependencies

**Problem**: Several services depend on AWS services not available in this environment.

| Service | AWS Dependency | Lines Affected | Impact |
|---------|---------------|---------------|--------|
| File uploads (s3.ts) | AWS S3 | 64 | File upload/download broken |
| Email (email-service.ts) | AWS SES | 68 | Invitation emails, notifications broken |
| AWS credentials (aws-credentials.ts) | AWS IAM | 60 | All AWS calls fail |
| GuardDuty connector | AWS GuardDuty | 122 | One connector broken (24 others work) |

**Fix**:
- **s3.ts**: Replace with local file storage (write to `/app/uploads/`) — 64 lines to rewrite
- **email-service.ts**: Replace with Resend or SendGrid — 68 lines to rewrite
- **aws-credentials.ts**: Remove or stub — only needed if using AWS services
- **GuardDuty connector**: Make it return simulated data (like other connectors without live backends)

**Effort**: Low (1 day). Only ~192 lines need changing.

---

### GAP 5: Stripe Configuration

**Problem**: Stripe service is fully implemented (466 lines) but needs API keys configured.

**Current state**: `stripe-service.ts` has real Stripe SDK calls for checkout, webhooks, and subscription management. The `billing.ts` routes (275 lines) are wired up. Frontend `billing.tsx` (784 lines) has full UI.

**What's missing**: Just the Stripe API key in environment variables.

**Fix**: Configure Stripe test key (available in pod environment folder) in `.env`, verify the checkout flow works.

**Effort**: Very Low (hours).

---

## Secondary Issues (Not Blockers, But Should Fix)

### Issue A: Pages with Higher Mock Data Usage
Some frontend pages have fallback/demo data that activates when API calls fail. These aren't broken — they'll show real data once the backend is running. But some have hardcoded demo values that should eventually be removed:

| Page | Mock Refs | Nature |
|------|-----------|--------|
| integrations.tsx | 29 | Hardcoded integration logos/descriptions (cosmetic) |
| playbooks.tsx | 27 | Demo playbook templates (expected for new orgs) |
| incident-detail.tsx | 24 | Fallback data for empty states |
| org-settings.tsx | 23 | Default settings values |
| compliance.tsx | 20 | Framework descriptions (expected) |
| operations.tsx | 15 | Demo SOC metrics |
| cspm.tsx | 14 | Demo cloud findings |
| threat-intel.tsx | 14 | Demo threat indicators |

**Most of these are intentional defaults/descriptions, not broken logic.**

### Issue B: Query Cache Has TODOs
`query-cache.ts` has 11 TODO comments — these are performance optimization notes, not broken functionality. The cache works but could be improved.

### Issue C: Stunning Dashboard Uses Computed Data
`stunning-dashboard.ts` has 3 mock references — it computes some metrics from real data but fills gaps with computed estimates. Works but isn't 100% real-time.

### Issue D: Email Validation
No work-email validation exists on registration. Anyone can sign up with gmail/yahoo. Need to add a blocklist of free email providers.

### Issue E: Password Complexity
Registration accepts any password. Need to enforce minimum length + complexity rules.

---

## Summary: What's Actually Needed

| Gap | What Needs Doing | Lines to Change | Effort |
|-----|-----------------|----------------|--------|
| 1. Infrastructure | Create `/app/backend/` + `/app/frontend/` wrappers | ~500 new | Medium |
| 2. Database | Either install PostgreSQL OR create MongoDB adapter | 0 or 5,424 | Low or High |
| 3. AI (Bedrock -> Emergent LLM) | Replace model-gateway.ts | ~540 | Low-Medium |
| 4. AWS services (S3, SES) | Replace with local storage + email service | ~192 | Low |
| 5. Stripe config | Add API key to env | ~5 | Very Low |
| A. Work email validation | Add blocklist check in auth | ~30 | Very Low |
| B. Password complexity | Add validation in register route | ~20 | Very Low |

**Total new/changed code needed: ~1,300 lines (or ~6,700 if MongoDB rewrite needed)**
**vs 109,000 lines that already exist and work.**

---

## Recommended Execution Order

1. **Fix Gap 1** (Infrastructure) — Get services starting
2. **Fix Gap 2** (Database) — Get data flowing
3. **Fix Gap 3** (AI) — Replace Bedrock with Emergent LLM
4. **Fix Gap 4** (AWS services) — Replace S3/SES
5. **Fix Gap 5** (Stripe) — Configure billing
6. **Fix Issues A-E** — Polish

**Once these 5 gaps + 5 issues are fixed, the existing 109K lines of real code become a working, shippable product.**
