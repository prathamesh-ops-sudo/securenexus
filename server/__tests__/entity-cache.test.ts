import { describe, it, expect, vi, beforeEach } from "vitest";
import { EventEmitter } from "events";

const { mockEventBus, dbQueryCounter } = vi.hoisted(() => {
  const { EventEmitter } = require("events");
  const bus = new EventEmitter();
  bus.setMaxListeners(100);
  return { mockEventBus: bus, dbQueryCounter: { count: 0 } };
});

vi.mock("../event-bus", () => ({
  eventBus: mockEventBus,
}));

vi.mock("../logger", () => ({
  logger: {
    child: () => ({
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    }),
  },
}));

vi.mock("../db", () => {
  const alertEntityResults = [
    {
      id: "ent-1",
      orgId: "org-1",
      type: "ip",
      value: "10.0.0.1",
      displayName: "10.0.0.1",
      metadata: {},
      firstSeenAt: new Date("2025-01-01"),
      lastSeenAt: new Date("2025-01-02"),
      alertCount: 5,
      riskScore: 0.8,
      createdAt: new Date("2025-01-01"),
      role: "source",
    },
  ];

  const db: any = {
    select: vi.fn(() => {
      dbQueryCounter.count++;
      const chain: any = {};
      chain.from = vi.fn().mockReturnValue(chain);
      chain.innerJoin = vi.fn().mockReturnValue(chain);
      chain.where = vi.fn().mockResolvedValue(alertEntityResults);
      return chain;
    }),
  };

  return {
    db,
    getPoolHealth: vi.fn(),
  };
});

vi.mock("drizzle-orm", () => ({
  eq: vi.fn((...args: any[]) => ({ _op: "eq", args })),
  and: vi.fn((...args: any[]) => ({ _op: "and", args })),
  sql: vi.fn(),
  inArray: vi.fn(),
  desc: vi.fn(),
}));

vi.mock("@shared/schema", () => ({
  entities: {
    id: "id", orgId: "orgId", type: "type", value: "value",
    displayName: "displayName", metadata: "metadata",
    firstSeenAt: "firstSeenAt", lastSeenAt: "lastSeenAt",
    alertCount: "alertCount", riskScore: "riskScore", createdAt: "createdAt",
  },
  entityAliases: { entityId: "entityId", aliasValue: "aliasValue", aliasType: "aliasType", createdAt: "createdAt" },
  entityMergeHistory: {},
  alertEntities: { alertId: "alertId", entityId: "entityId", role: "role" },
  alerts: { id: "id", incidentId: "incidentId", createdAt: "createdAt" },
  incidents: {},
  attackPaths: { id: "id", entityIds: "entityIds" },
}));

import { cacheInvalidateAll } from "../query-cache";
import { getEntitiesForAlert, getEntitiesForIncident } from "../entity-resolver";

describe("entity graph caching", () => {
  beforeEach(() => {
    dbQueryCounter.count = 0;
    cacheInvalidateAll();
  });

  it("returns cached result on second call to getEntitiesForAlert within TTL", async () => {
    const result1 = await getEntitiesForAlert("alert-1", "org-1");
    expect(result1).toBeDefined();
    expect(result1.length).toBeGreaterThan(0);
    const countAfterFirst = dbQueryCounter.count;

    const result2 = await getEntitiesForAlert("alert-1", "org-1");
    expect(result2).toEqual(result1);
    // Second call should NOT have triggered another DB query
    expect(dbQueryCounter.count).toBe(countAfterFirst);
  });

  it("returns cached result on second call to getEntitiesForIncident within TTL", async () => {
    const result1 = await getEntitiesForIncident("incident-1", "org-1");
    const countAfterFirst = dbQueryCounter.count;

    const result2 = await getEntitiesForIncident("incident-1", "org-1");
    // Second call should NOT have triggered another DB query
    expect(dbQueryCounter.count).toBe(countAfterFirst);
  });

  it("invalidates cache when entity:resolved event fires for matching orgId", async () => {
    // Populate cache
    await getEntitiesForAlert("alert-1", "org-1");
    const countAfterFirst = dbQueryCounter.count;

    // Fire entity:resolved event
    mockEventBus.emit("entity:resolved", {
      type: "entity:resolved",
      orgId: "org-1",
      timestamp: new Date().toISOString(),
      podId: "pod-1",
      data: {},
    });

    // Next call should hit DB again (cache was invalidated)
    await getEntitiesForAlert("alert-1", "org-1");
    expect(dbQueryCounter.count).toBeGreaterThan(countAfterFirst);
  });

  it("uses tenant-scoped cache keys (different orgId = different cache entry)", async () => {
    // Call for org-1
    await getEntitiesForAlert("alert-1", "org-1");
    const countAfterOrg1 = dbQueryCounter.count;

    // Call for org-2 with same alertId — should NOT be cached (different org)
    await getEntitiesForAlert("alert-1", "org-2");
    expect(dbQueryCounter.count).toBeGreaterThan(countAfterOrg1);
  });

  it("concurrent calls for same key only hit DB once (cacheGetOrLoad dedup)", async () => {
    // Fire two concurrent requests for the exact same key
    const [result1, result2] = await Promise.all([
      getEntitiesForAlert("alert-concurrent", "org-1"),
      getEntitiesForAlert("alert-concurrent", "org-1"),
    ]);

    // Both should return same data
    expect(result1).toEqual(result2);
    // Only one DB query should have been made (inflight dedup in cacheGetOrLoad)
    expect(dbQueryCounter.count).toBe(1);
  });
});
