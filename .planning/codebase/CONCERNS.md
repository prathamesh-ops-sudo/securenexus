# Codebase Concerns

**Analysis Date:** 2026-03-25

## Tech Debt

**Route File Complexity:**
- Issue: Multiple route files exceed 3,500 lines with god-object antipattern
- Files:
  - `server/routes/ai.ts` (3,542 lines)
  - `server/routes/playbooks.ts` (3,541 lines)
  - `server/routes/standalone-platform.ts` (2,831 lines)
  - `server/routes/endpoints.ts` (2,576 lines)
  - `server/routes/entity-graph-advanced.ts` (2,286 lines)
- Impact: Difficult to test, maintain, and reason about. Single-responsibility violated. Refactoring blocked.
- Fix approach: Split each file into domain-specific subdirectories with separate handler modules. Example: `server/routes/ai/` containing `triage.ts`, `narrative.ts`, `correlation.ts`, etc. Update `server/routes/index.ts` barrel export accordingly.

**Unsafe Type Usage (any[]):**
- Issue: 41 files using `any[]` parameter types bypassing type safety
- Files:
  - `server/ai.ts` (multiple functions: buildThreatIntelContext, buildCorrelationUserMessage, buildNarrativeUserMessage, buildHeuristicInvestigation)
  - `server/action-dispatcher.ts` (config parameters as any)
  - `server/graph-correlation.ts` (alertDataList, entityDataList as any[])
  - `server/auth/routes.ts` (callback params as any)
  - `server/auth/session.ts` (profile and done callback as any)
- Impact: Runtime errors not caught at compile time. Prevents IDE autocomplete. Makes refactoring dangerous.
- Fix approach: Create explicit TypeScript interfaces for each function. Example: `interface ThreatIntelInput { sourceEventId: string; severity: AlertSeverity; ... }` and replace `alerts: any[]` with `alerts: Alert[]`. Use strict `noImplicitAny` in tsconfig.

**Console.log Statements in Production Code:**
- Issue: 238 console.log/console.error calls across 78 files
- Files: Most egregious in `server/routes/playbooks.ts` (21), `server/routes/native-sensors.ts` (9), `server/ai.ts` (5), `server/routes/agent-response.ts` (8)
- Impact: Console output not captured by structured logging. Makes production debugging impossible. Info mixed with errors.
- Fix approach: Replace all console calls with logger.child(). Already have `logger` imported in most files from `./logger`. Example: `console.log()` → `logger.child("playbooks").info()`. Add pre-commit hook to reject console calls.

**Incomplete AI Usage Tracking:**
- Issue: Hardcoded zeros for AI cost calculation in billing
- Files: `server/routes/mssp-portal.ts:579-581`
  - Line 579: `const aiAnalyses = 0; // TODO: integrate with AI usage tracking`
  - Line 581: `const storageGb = 0; // TODO: integrate with storage metering`
- Impact: MSSP billing calculations are incorrect. Revenue may be lost. Customers see $0 AI usage despite inference happening.
- Fix approach: Query `ai_inference_log` table (already exists in `server/ai.ts`) filtered by period dates and orgId. Sum token costs. For storage, query data lifecycle tables or estimate from S3.

**Raw SQL Queries in ai.ts:**
- Issue: Direct `pool.query()` calls with manual CREATE TABLE statements instead of Drizzle ORM
- Files: `server/ai.ts:61-82` (creating ai_inference_log table at runtime)
- Impact: Migrations bypassed. Table schema not versioned. Production deployments may fail if connections don't have DDL permissions.
- Fix approach: Move table creation to `migrations/` directory. Use Drizzle `push` or migrations CLI. Remove runtime CREATE TABLE. See `drizzle.config.ts` for existing migration setup.

---

## Known Bugs

**Missing AI Usage Attribution:**
- Symptoms: Billing records show $0 for AI analysis costs despite large inference volumes
- Files: `server/routes/mssp-portal.ts:577-587`
- Trigger: Any MSSP billing report generation with AI usage
- Workaround: Manually calculate from `ai_inference_log` table using adhoc SQL

**dangerouslySetInnerHTML in Landing Page:**
- Symptoms: Theoretical XSS vulnerability in JSON-LD structured data
- Files: `client/src/pages/content-layout.tsx:165-170` (structured data is JSON.stringify so safe, but pattern is dangerous if user data added)
- Trigger: If future code adds user-controlled data to JSON-LD schemas
- Current mitigation: Data is hardcoded JSON-LD, no user input. All schema data comes from constants.
- Fix approach: Even though safe now, wrap with `DOMPurify.sanitize()` for defense-in-depth on line 165-170.

**Chart UI Security:**
- Symptoms: dangerouslySetInnerHTML in Recharts wrapper
- Files: `client/src/components/ui/chart.tsx:72`
- Trigger: If Recharts HTML template contains dynamic data
- Current mitigation: Internal Recharts tooltip rendering, not user-supplied
- Fix approach: Audit Recharts version (`recharts@2.15.4`) for any known vulnerabilities. Consider wrapping with DOMPurify as defensive practice.

---

## Security Considerations

**API Key Storage:**
- Risk: Keys may be exposed if DATABASE_URL environment is compromised. SHA-256 hashing provides integrity but not confidentiality.
- Files: `shared/schema.ts` (apiKeys table definition), `server/storage.ts` (API key queries)
- Current mitigation: Keys hashed with SHA-256. Stored in PostgreSQL with no plaintext backup. Rate limiting on ingestion endpoints.
- Recommendations:
  1. Add key rotation mechanism (mark old keys deprecated, soft delete)
  2. Consider hardware-backed secrets manager (AWS Secrets Manager integration)
  3. Audit who has DATABASE_URL access in CI/CD

**Environment Variable Exposure:**
- Risk: `.env` files could leak in docker builds or git history
- Current mitigation: `.env` in `.gitignore`, `.env.example` provided, process runs with minimal ENV vars
- Recommendations:
  1. Use AWS EKS Secrets instead of env vars in production
  2. Rotate `AWS_SECRET_ACCESS_KEY` quarterly
  3. Add git pre-commit hook to prevent `.env` commits

**Dangerous Permissions Processing:**
- Risk: Mobile security analysis identifies dangerous app permissions but no remediation automation
- Files: `server/routes/mobile-security.ts:1400-1510` (DANGEROUS_PERMISSIONS list exists but only for detection)
- Impact: False positives if legitimate apps request camera/location
- Current mitigation: User can manually review results
- Recommendations: Add ML-based whitelist (trusted apps) to reduce false positives

**CSRF Protection:**
- Risk: Double-submit cookie relies on SameSite attribute working correctly
- Files: `server/security-middleware.ts` (applyCsrfProtection)
- Current mitigation: CSRF tokens generated per request, SameSite=Strict configured
- Recommendations: Add rate limiting on CSRF token generation to prevent brute-force

**Raw Pool Queries:**
- Risk: Direct `pool.query()` calls in `server/ai.ts:93-96` use parameterized queries so SQL injection prevented, but maintainability risk
- Files: `server/ai.ts:61-82`, `server/distributed-concurrency.ts`, `server/db-performance.ts`
- Current mitigation: All use prepared statements with $1, $2 placeholders
- Recommendations: Migrate to Drizzle ORM for consistency and IDE autocomplete

---

## Performance Bottlenecks

**Connection Pool Saturation:**
- Problem: Production pool set to max 20 connections. Concurrent AI inference + report generation can exhaust pool.
- Files: `server/db.ts:15` (pool max: 20)
- Cause: No connection queue shedding. Each inference tier holds connection during Bedrock roundtrip (2-5s latency)
- Current capacity: 20 concurrent connections × 5 requests/sec = 100 req/sec sustained
- Limit: At 500+ alert ingestion/sec, pool exhaustion causes queue backup
- Improvement path:
  1. Use read replicas for read-heavy operations (analytics, incident list pagination)
  2. Implement connection circuit breaker in `server/ai/model-gateway.ts` to fail-fast on Bedrock timeouts
  3. Consider pgBouncer for connection pooling multiplexing

**Large Alert Ingestion Payloads:**
- Problem: Bulk ingestion endpoint accepts 1MB payload limit (express.json limit 1MB)
- Files: `server/index.ts:106-111`
- Cause: No streaming upload support for multi-gigabyte log files
- Impact: Users cannot ingest archives > 1MB in single request
- Improvement path: Add chunked upload endpoint accepting multipart/form-data with resume capability

**AI Context Window Exhaustion:**
- Problem: Narrative generation with 100+ correlated alerts + RAG context can exceed token budget
- Files: `server/routes/ai.ts:2948-3030` (context-optimization endpoint is stub)
- Cause: No intelligent RAG selection (top-k similarity only, no token counting)
- Impact: Inference fails or truncates context. Quality degrades.
- Improvement path: Implement token budget enforcement using `js-tiktoken` to reserve space for response, then greedily select most-relevant RAG chunks

**Report PDF Generation Blocking:**
- Problem: PDF generation synchronously blocks request handling
- Files: `server/routes/advanced-reports.ts`, `server/report-pdf.ts`
- Cause: Single-threaded Node.js can't render PDFs in parallel
- Impact: Multiple report requests queue up. Users wait 10-30s.
- Improvement path: Move PDF generation to `job-queue` system. Return job ID immediately, notify user via WebSocket when ready.

**Entity Graph Query Complexity:**
- Problem: Computing attack paths with 1000+ entities requires nested graph traversal
- Files: `server/routes/entity-graph-advanced.ts:2286 lines` contains expensive queries
- Cause: No query result caching. Each page load re-computes full graph
- Impact: Dashboard load > 5s. Memory usage spikes.
- Improvement path: Cache entity relationships with TTL (5 min) using redis or in-memory LRU. Invalidate on entity change.

---

## Fragile Areas

**Correlation Engine Implementation:**
- Files:
  - `server/correlation-engine.ts`
  - `server/graph-correlation.ts`
  - `server/ai.ts` (AI correlation functions)
- Why fragile:
  1. Three separate correlation systems (AI semantic, graph-based, rule-based) can produce conflicting incident groups
  2. No consensus algorithm when they disagree
  3. `any[]` types prevent type-safe changes to alert/entity structures
  4. No transaction isolation — concurrent ingestion can corrupt correlation state
- Safe modification:
  1. Add integration tests that ingest 10 alerts across 3 sources and verify incident count
  2. Wrap correlation logic in database transaction with `BEGIN ... COMMIT`
  3. Add feature flag to enable/disable each correlation algorithm independently
- Test coverage: Only 15 test files in entire codebase. No correlation engine unit tests found.

**Action Dispatcher (Response Actions):**
- Files: `server/action-dispatcher.ts`
- Why fragile:
  1. `config: any` parameter means wrong action type can crash dispatcher at runtime
  2. No dry-run transaction — actions may partially execute then fail
  3. No rollback mechanism if action fails mid-execution
- Safe modification:
  1. Add Zod validation schema for each action type (IsolateHost, BlockIP, etc.)
  2. Wrap all actions in try-catch with `ResponseActionRollback` insertion on failure
  3. Test each action against sandbox environments
- Test coverage: No test files for action-dispatcher found

**Session Serialization (OAuth):**
- Files: `server/auth/session.ts:184-227` (OAuth profile callbacks use `any` types)
- Why fragile:
  1. profile object structure depends on provider (Google vs GitHub return different fields)
  2. No validation that required fields exist before accessing
  3. Deserialize function could fail on malformed session data
- Safe modification:
  1. Create Provider-specific profile types (GoogleProfile, GitHubProfile)
  2. Validate profile shape before accessing fields
  3. Add fallback for missing fields
- Test coverage: No session serialization tests found

**Schema Evolution (Drizzle):**
- Files: `shared/schema.ts` (6,000+ lines defining all tables)
- Why fragile:
  1. Adding column to frequently-queried table blocks production for duration of migration
  2. No feature flag system for schema changes
  3. Backwards compatibility not enforced (dropping columns)
- Safe modification:
  1. All schema changes through migrations (already using drizzle-kit)
  2. New columns default to NOT NULL only if safe default exists
  3. Deprecate columns before dropping (keep for 2 minor versions)
- Test coverage: No schema migration tests

---

## Scaling Limits

**Database Write Amplification:**
- Current capacity: 1,000 alerts/sec ingestion max
- Resource constraint: PostgreSQL WAL I/O becomes bottleneck at 5,000 inserts/sec
- Scaling path:
  1. Implement alert batching (accumulate 100 alerts, insert in single transaction)
  2. Add hot/cold storage (PostgreSQL for recent 30 days, S3 Parquet for archive)
  3. Consider TimescaleDB for better alert time-series performance

**Job Queue Backlog:**
- Current architecture: Single node processes jobs from queue serially
- Limit: ~100 jobs/sec (report generation, playbook execution)
- Scaling path:
  1. Deploy multiple job workers (horizontal scale)
  2. Use Redis for distributed job queue instead of PostgreSQL
  3. Add job priority tiers (incident response > reporting > archival)

**Real-time WebSocket Connections:**
- Limit: Node.js can handle ~10,000 concurrent WebSocket connections per pod
- Current deployment: Single pod → 10K user limit for real-time updates
- Scaling path:
  1. Deploy 3+ pods with sticky sessions
  2. Use Redis pub/sub to broadcast events across pods
  3. Implement user presence channel (who's viewing which incident)

**AI Inference Concurrency:**
- Limit: 5 concurrent Bedrock invocations per org (rate limit in model-gateway)
- Bottleneck: Queueing during peak hours. Users wait 30s+ for triage results
- Scaling path:
  1. Increase AWS Bedrock rate limits (quota increase request)
  2. Implement intelligent queue prioritization (incident triage > threat hunt)
  3. Add model fallback (Mistral → Claude → Llama)

**Prometheus Metrics Cardinality:**
- Problem: Alert and incident labels create unbounded metric dimensions
- Impact: Prometheus scrape grows unbounded, OOM risk
- Scaling path:
  1. Aggregate metrics by OrgID and source only (remove per-alert labels)
  2. Use custom metrics table in PostgreSQL for retention and aggregation

---

## Dependencies at Risk

**@xmldom/xmldom@0.8.11:**
- Risk: XML parsing library with historical vulnerabilities. Version 0.8.11 is old.
- Impact: XXE (XML External Entity) attacks if processing untrusted STIX/TAXII feeds
- Migration plan: Update to 1.0.0+, add XML validation with strict DTD disabling

**passport (OAuth libraries):**
- Risk: passport-github2@0.1.12 and passport-google-oauth20@2.0.0 are outdated. No recent security patches.
- Impact: OAuth token leakage, redirectURI validation bypass
- Migration plan: Upgrade to latest versions, test OAuth flow end-to-end with real providers

**pg@8.16.3:**
- Risk: Uses deprecated streaming APIs. No major version bump planned (v9 EOL)
- Impact: Potential buffer exhaustion with large result sets
- Migration plan: Evaluate node-postgres alternatives (node-sql-parser) or upgrade to pg@9 when available

**Stripe SDK@20.4.0:**
- Risk: Old SDK version. New charges API may not be supported.
- Impact: Recurring billing operations could fail if API changed
- Migration plan: Upgrade to Stripe SDK v15+ (latest stable)

---

## Missing Critical Features

**Incident Rollback Mechanism:**
- Problem: Response actions executed but incident is later dismissed as false positive
- Blocks: Automated remediation use cases. Users fear clicking "Execute Playbook"
- Workaround: Manual reversal (contact sysadmin to restore users/IPs)
- Implementation: `response_action_rollbacks` table exists but no API to trigger automatic rollback. Add `POST /api/incidents/{id}/rollback-actions` that:
  1. Fetches incident.executedActions
  2. For each action, generates reverse operation (restore user, unblock IP)
  3. Executes rollbacks with same audit trail
  4. Returns rollback summary

**Temporal Alert Deduplication:**
- Problem: Same alert from same source fires every 5 min. Creates 288 duplicates/day per source.
- Blocks: Alert fatigue. Correlation engine confused by duplicates.
- Workaround: Manual suppression rules
- Implementation: Add time-window deduplication config per source. If alert with same sourceEventId arrives within 10 min, update timestamp and increment counter rather than creating duplicate.

**Connector Failover:**
- Problem: If Splunk connector hangs, no alerts ingest from Splunk until manual intervention
- Blocks: Unattended monitoring
- Workaround: Manual connector restart
- Implementation: Add health check per connector. Auto-restart if failed 3 consecutive polls. Log rollover.

**AI Cost Attribution by User:**
- Problem: Billing tracks org-level AI costs but not user-level (who ran expensive hunts)
- Blocks: Chargeback models, user fairness
- Implementation: Add user_id column to `ai_inference_log`. Log Bedrock caller identity. Add audit endpoint to show per-user inference spend.

**Multi-Region Deployment:**
- Problem: All data in single AWS region (us-east-1). Regional outage = complete downtime.
- Blocks: SLA < 99.99%
- Implementation: RTO/RPO not yet defined. Would require read replicas, cross-region failover, database replication setup.

---

## Test Coverage Gaps

**Correlation Engine:**
- What's not tested:
  - Alert correlation with 50+ entities and temporal windows
  - Conflict resolution when multiple algorithms suggest different incidents
  - Rollback when correlated incident is dismissed
- Files: `server/correlation-engine.ts`, `server/graph-correlation.ts`
- Risk: False negatives (legitimate attack goes uncorrelated), false positives (unrelated alerts merged)
- Priority: **High** — correlation is core to platform value

**Action Dispatcher & Playbook Execution:**
- What's not tested:
  - Dry-run mode (should not execute actual actions)
  - Rollback on failure (should restore state)
  - Permission checks (analyst can't execute privileged actions)
  - Concurrency (two playbooks executing simultaneously on same incident)
- Files: `server/action-dispatcher.ts`, `server/routes/playbooks.ts`
- Risk: Unintended host isolation, IP blocks, user lockouts
- Priority: **Critical** — affects production systems

**OAuth Flow:**
- What's not tested:
  - Google OAuth token refresh
  - GitHub OAuth scope mismatches
  - OIDC/SAML with external IdP
  - Session fixation attacks
- Files: `server/auth/session.ts`, `server/auth/routes.ts`
- Risk: Authentication bypass, privilege escalation
- Priority: **High** — security boundary

**Connector Integration:**
- What's not tested:
  - End-to-end sync with real connector APIs (Splunk, CrowdStrike, etc.)
  - Connector failure modes (timeout, 401, 403, rate limit)
  - Large paginated result sets (10K+ alerts per poll)
  - Schema evolution (alert fields change over time)
- Files: `server/connectors/*.ts` (8 connectors total)
- Risk: Corrupted alert ingestion, lost data, infinite loops
- Priority: **High** — affects data integrity

**Billing & Metering:**
- What's not tested:
  - Org usage exceeds plan limits (should be throttled)
  - Stripe webhook handling (subscription created/cancelled)
  - MSSP parent-child billing split
  - Usage calculation accuracy (alerts counted correctly)
- Files: `server/routes/mssp-portal.ts`, `server/ai/budget.ts`
- Risk: Revenue loss, customer overage disputes
- Priority: **Medium** — impacts only billing

---

## Recommendations Priority

| Category | Severity | Item | Effort |
|----------|----------|------|--------|
| Code Quality | High | Split ai.ts and playbooks.ts into smaller files | 3 days |
| Security | High | Upgrade @xmldom and passport libraries | 2 days |
| Performance | High | Add connection pooling / read replicas | 1 week |
| Testing | Critical | Add correlation engine test suite | 5 days |
| Testing | Critical | Add playbook execution tests (safety) | 3 days |
| Testing | High | Add OAuth flow tests | 2 days |
| Testing | High | Add connector integration tests | 4 days |
| Bug | Medium | Implement AI usage tracking for billing | 3 days |
| Feature | Medium | Add incident rollback mechanism | 2 days |
| Debt | Low | Replace console.log with logger.child() | 1 day |

---

*Concerns audit: 2026-03-25*
