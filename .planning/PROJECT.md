# SecureNexus — Production Hardening

## What This Is

SecureNexus is an AI-powered Security Orchestration & Intelligence Platform that unifies alerts from 24+ cybersecurity tools, correlates them into incidents using AI, and enables automated response. This milestone takes the platform from prototype to production-grade — every feature works for real, code is solid, tests prove it, nothing is faked.

## Core Value

Every feature that exists in the UI must actually work end-to-end with real data — no stubs, no hardcoded returns, no demo-quality shortcuts.

## Requirements

### Validated

- ✓ Multi-tenant org isolation with RBAC (owner/admin/analyst/read_only) — existing
- ✓ Session-based auth with Passport.js (local + Google/GitHub OAuth) — existing
- ✓ API key auth with SHA-256 hashing for programmatic ingestion — existing
- ✓ Alert ingestion (single + bulk) with OCSF normalization — existing
- ✓ Alert deduplication by orgId+source+sourceEventId — existing
- ✓ 8 pull-based connectors (Splunk, CrowdStrike, etc.) — existing
- ✓ AI-driven alert triage and incident narrative via AWS Bedrock — existing
- ✓ Correlation engine (AI semantic + graph-based + rule-based) — existing
- ✓ Entity graph with user/host/IP/domain nodes — existing
- ✓ Playbook definitions and response actions — existing
- ✓ IOC feed management and threat intel — existing
- ✓ CSPM accounts and findings — existing
- ✓ Audit log with tamper-evident chain hashing — existing
- ✓ Dashboard with stats and analytics charts — existing
- ✓ SSE real-time event stream — existing
- ✓ Canonical API envelope (data/meta/errors) on all endpoints — existing
- ✓ 28 frontend pages with routing and lazy loading — existing

### Active

- [ ] Kill all stub/hardcoded endpoints — every API returns real data
- [ ] Fix correlation engine fragility — transaction isolation, conflict resolution, type safety
- [ ] Add action dispatcher safety — Zod validation, dry-run mode, rollback on failure
- [ ] Replace all `any[]` types with proper TypeScript interfaces (41 files)
- [ ] Replace 238 console.log/error calls with structured logger
- [ ] Split god files (ai.ts, playbooks.ts, storage.ts) into domain modules
- [ ] Add correlation engine test suite (integration + unit)
- [ ] Add playbook/action dispatcher tests (safety-critical)
- [ ] Add OAuth flow tests (security boundary)
- [ ] Add connector integration tests (data integrity)
- [ ] Implement incident rollback mechanism for false positives
- [ ] Implement temporal alert deduplication (time-window suppression)
- [ ] Implement connector health checks and auto-failover
- [ ] Fix AI usage tracking for MSSP billing (currently hardcoded $0)
- [ ] Move runtime CREATE TABLE from ai.ts to proper Drizzle migrations
- [ ] Upgrade vulnerable dependencies (@xmldom, passport-github2, passport-google-oauth20, Stripe SDK)
- [ ] Add connection pool management (read replicas, circuit breaker)
- [ ] Implement async PDF generation via job queue
- [ ] Add entity graph caching (LRU with TTL)
- [ ] Token budget enforcement for AI context windows
- [ ] Sanitize dangerouslySetInnerHTML patterns (defense-in-depth)
- [ ] Add API key rotation mechanism
- [ ] Connector failover with health check loop

### Out of Scope

- Multi-region deployment — infrastructure concern, not code quality (defer to ops milestone)
- Mobile app — web-first platform
- New connector types — existing 8 connectors need to work reliably first
- New AI models — Bedrock/Mistral stack is sufficient, focus on making it reliable
- UI redesign — pages exist, focus on making the backend real
- Kubernetes/EKS configuration changes — infrastructure milestone

## Context

SecureNexus has a large existing codebase (~110 route files, 6200-line storage.ts, 12800-line schema.ts) that covers the full feature surface of a security platform. However, many features are prototype-quality: stub endpoints, hardcoded data, no tests for critical paths, `any` types everywhere, and fragile core engines. The correlation engine — the platform's core value — has zero test coverage and three competing algorithms with no conflict resolution.

The codebase map at `.planning/codebase/` documents the full current state including specific file paths, line numbers, and severity ratings for all concerns.

Background services (report scheduler, job worker, SLI collection, SLO alerting) start on boot but their reliability under load is untested.

## Constraints

- **Tech stack**: Existing stack (React/Express/PostgreSQL/Drizzle/Bedrock) — no framework migrations
- **Database**: PostgreSQL with Drizzle ORM — all new queries through Drizzle, eliminate raw pool.query()
- **Testing**: Vitest for unit/integration, Playwright for E2E — already configured
- **AI**: AWS Bedrock with Mistral Large 2 — no model changes, focus on reliability
- **Backward compatibility**: API envelope format and existing endpoint contracts must not break

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Fix existing features before adding new ones | Platform feels fake — trust requires reliability | — Pending |
| Correlation engine gets tested first | Core platform value, currently zero coverage | — Pending |
| God files split into domain modules | 3500+ line files block maintainability | — Pending |
| All `any` types eliminated | Type safety prevents runtime crashes in production | — Pending |
| Structured logging replaces console.log | Production debugging requires searchable logs | — Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd:transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd:complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-03-25 after initialization*
