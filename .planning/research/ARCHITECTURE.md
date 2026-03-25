# Architecture Patterns: Production Hardening

**Domain:** Security platform production readiness
**Researched:** 2026-03-25

## Recommended Architecture

### Current State: Monolith with Emerging Domain Boundaries

The codebase already has partial domain separation (110+ route files in `server/routes/`) but consolidates all data access into a single 6222-line `DatabaseStorage` class in `server/storage.ts`. This creates a god object that 49+ files import directly. The route layer is well-factored; the storage layer is the bottleneck.

**Target state:** Domain-aligned modules where each domain owns its storage queries, with a thin re-export facade preserving backward compatibility during migration.

```
Before:                              After:

server/routes/alerts.ts              server/routes/alerts.ts
server/routes/incidents.ts           server/routes/incidents.ts
       |                                    |
       v                                    v
server/storage.ts (6222 lines)       server/storage/alerts.ts
  class DatabaseStorage {            server/storage/incidents.ts
    // ALL queries for ALL domains   server/storage/connectors.ts
  }                                  server/storage/compliance.ts
                                     server/storage/threat-intel.ts
                                     server/storage/index.ts (facade)
```

### Production Hardening Component Map

| Component | Responsibility | Changes Needed |
|-----------|---------------|----------------|
| `server/logger.ts` | Structured JSON logging with redaction | Add LOG_LEVEL env var, add sampling for high-volume paths |
| `server/db.ts` | Connection pool management | Adjust pool size for RDS Proxy, add read replica pool |
| `server/scaling-state.ts` | Multi-pod readiness tracking | Add Redis-backed implementations for 4 identified stores |
| `server/prometheus.ts` | Metrics endpoint | Add `process.memoryUsage()` and `process.cpuUsage()` metrics |
| `vitest.config.ts` | Test configuration | Raise coverage thresholds, add security test patterns |
| `eslint.config.js` | Lint rules | Escalate no-console, add security plugin, enable strict-type-checked |
| `Dockerfile` | Production image | Add NODE_OPTIONS for memory limits and source maps |
| `.github/workflows/` | CI pipeline | Add npm audit gate, license check, coverage enforcement |

### Data Flow

No changes to existing data flows. Production hardening is about reliability, not functionality. The alert ingestion, correlation, and incident management flows remain identical. Changes are:

1. Logs flow through existing stdout but with configurable level
2. Shared state flows through Redis instead of in-memory Maps (for 4 specific stores)
3. Read queries optionally route to replica instead of primary
4. CI pipeline adds audit/license gates before merge

## Patterns to Follow

### Pattern 1: Redis-Backed Shared State

**What:** Replace in-memory Maps with Redis for state that must be consistent across pods.
**When:** Any state identified as `needs-shared-store` in `scaling-state.ts`.

```typescript
// Current (in-memory, per-pod)
const circuitState = new Map<string, { failures: number; openUntil: number }>();

// Production (Redis-backed, shared across pods)
import Redis from "ioredis";
const redis = new Redis(process.env.REDIS_URL);

async function tripCircuit(key: string, ttlSeconds: number): Promise<void> {
  await redis.setex(`circuit:${key}`, ttlSeconds, "open");
}

async function isCircuitOpen(key: string): Promise<boolean> {
  return (await redis.get(`circuit:${key}`)) === "open";
}
```

**Key principle:** The existing `scaling-state.ts` registry already documents the upgrade path for each store. Follow its recommendations exactly. Only migrate the 4 `needs-shared-store` items.

### Pattern 2: Read Replica Routing

**What:** Separate read and write database connections.
**When:** Analytics queries, dashboard stats, entity graph traversal, audit log reads.

```typescript
// server/db.ts addition
export const readPool = new Pool({
  connectionString: config.databaseReadUrl || config.databaseUrl,
  max: isProd ? 10 : 3,
  min: 1,
  application_name: `securenexus-${config.nodeEnv}-read`,
});
export const readDb = drizzle(readPool, { schema });
```

### Pattern 3: Supertest API Contract Tests

**What:** Test Express routes with real middleware stack.
**When:** Testing auth, RBAC, rate limiting, validation, response format.

```typescript
import request from "supertest";

describe("GET /api/alerts", () => {
  it("returns 401 without session", async () => {
    const res = await request(app).get("/api/alerts");
    expect(res.status).toBe(401);
    expect(res.body.errors[0].code).toBe("UNAUTHENTICATED");
  });
});
```

**Requires:** App factory that creates Express app without calling `listen()`. May need extracting app setup from `server/index.ts`.

### Pattern 4: Layered Test Coverage

**What:** Different coverage expectations for different code categories.

```
Tier 1 (70%): auth/, rbac.ts, normalizer.ts, pii-engine.ts, correlation-engine.ts, tenant-isolation.ts
Tier 2 (50%): routes/, storage.ts, connector-engine.ts
Tier 3 (30%): Everything else
```

## Anti-Patterns to Avoid

### Anti-Pattern 1: Clustering Inside Kubernetes Pods
**What:** Using `node:cluster` to fork worker processes inside a container.
**Why bad:** K8s HPA already handles horizontal scaling. Clustering inside pods means health checks hit the master process, not workers. Graceful shutdown must coordinate with both cluster master and K8s SIGTERM.
**Instead:** One Node.js process per pod. Scale pods via HPA. Already implemented correctly.

### Anti-Pattern 2: Logger Library Churn
**What:** Replacing a working custom logger with Pino/Winston.
**Why bad:** The custom logger already handles AsyncLocalStorage propagation, deep redaction of 20+ sensitive patterns, JSON serialization. Pino's faster serialization is irrelevant at current scale.
**Instead:** Improve the existing logger incrementally.

### Anti-Pattern 3: Shared Redis for Everything
**What:** Moving ALL in-memory state to Redis.
**Why bad:** `scaling-state.ts` correctly identifies most stores as `local-ok`. Per-pod caches with DB fallback is the right pattern.
**Instead:** Only migrate the 4 stores tagged `needs-shared-store`.

### Anti-Pattern 4: Coverage Maximalism
**What:** Setting 80%+ overall coverage threshold immediately.
**Why bad:** Incentivizes testing trivial getters instead of security-critical paths.
**Instead:** High thresholds on security modules, moderate thresholds overall.

## Scalability Considerations

| Concern | At 1 Pod (Current) | At 3-5 Pods | At 10+ Pods |
|---------|---------------------|-------------|-------------|
| DB Connections | 20 per pod, fine | 60-100 total, needs RDS Proxy | RDS Proxy essential, read replicas needed |
| Shared State | In-memory works | Redis required for circuit breakers, rate limits | Redis cluster with replicas |
| Session Store | PostgreSQL (connect-pg-simple) | Works (DB-backed already) | Consider Redis sessions for lower latency |
| SSE Events | Direct to connected clients | Need Redis Pub/Sub for cross-pod broadcast | Redis Pub/Sub with partitioned channels |
| Job Queue | DB-based FOR UPDATE SKIP LOCKED | Works (already distributed) | May need dedicated worker pods |
| Log Volume | stdout to CloudWatch | Same pattern scales | Consider log sampling at high volume |

## Sources

- Direct codebase analysis of server/logger.ts, server/db.ts, server/scaling-state.ts, server/index.ts, server/config.ts
- Architecture analysis: `.planning/codebase/ARCHITECTURE.md`
- Confidence: HIGH (based on direct codebase analysis)
