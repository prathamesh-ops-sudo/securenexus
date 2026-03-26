import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type { Request, Response, NextFunction } from "express";

// Mock dependencies before importing the module under test
vi.mock("../storage", () => ({
  storage: {
    getOrganization: vi.fn(),
  },
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

vi.mock("../api-response", () => ({
  replyRateLimit: vi.fn().mockImplementation((res: any, message: string) => {
    res.status(429);
    res.json({ data: null, errors: [{ code: "RATE_LIMITED", message }] });
    return res;
  }),
  ERROR_CODES: { RATE_LIMITED: "RATE_LIMITED" },
}));

import { orgRateLimitMiddleware, getOrgRateLimitStats } from "../middleware/org-rate-limit";
import { storage } from "../storage";
import { replyRateLimit } from "../api-response";

function mockReq(overrides: Record<string, unknown> = {}): Request {
  return {
    path: "/api/alerts",
    method: "GET",
    socket: { remoteAddress: "127.0.0.1" },
    ip: "127.0.0.1",
    ...overrides,
  } as unknown as Request;
}

function mockRes(): Response {
  const res: any = {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
    setHeader: vi.fn(),
  };
  return res as Response;
}

describe("orgRateLimitMiddleware", () => {
  let uniqueCounter = 0;

  beforeEach(() => {
    vi.clearAllMocks();
    uniqueCounter++;
    // Default: resolve org plan to free
    vi.mocked(storage.getOrganization).mockResolvedValue({
      id: "org-1",
      name: "Test Org",
    } as any);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe("health check path exemptions", () => {
    it.each(["/ops/health", "/ops/ready", "/ops/live", "/health"])(
      "bypasses rate limiting for %s",
      async (path) => {
        const req = mockReq({ path });
        const res = mockRes();
        const next = vi.fn();

        await orgRateLimitMiddleware(req, res, next);

        expect(next).toHaveBeenCalled();
        expect(res.setHeader).not.toHaveBeenCalled();
      },
    );
  });

  describe("bucket creation", () => {
    it("creates a bucket and calls next for a new orgId", async () => {
      const orgId = `org-new-${uniqueCounter}`;
      const req = mockReq({ orgId });
      const res = mockRes();
      const next = vi.fn();

      await orgRateLimitMiddleware(req, res, next);

      expect(next).toHaveBeenCalled();
    });
  });

  describe("rate limit headers", () => {
    it("sets X-RateLimit-Limit header matching plan tier", async () => {
      const orgId = `org-header-limit-${uniqueCounter}`;
      vi.mocked(storage.getOrganization).mockResolvedValue({
        id: orgId,
        name: "Pro Org",
        plan: "pro",
      } as any);

      const req = mockReq({ orgId });
      const res = mockRes();
      const next = vi.fn();

      await orgRateLimitMiddleware(req, res, next);

      expect(res.setHeader).toHaveBeenCalledWith("X-RateLimit-Limit", "5000");
    });

    it("sets X-RateLimit-Remaining with correct count", async () => {
      const orgId = `org-header-remaining-${uniqueCounter}`;

      const req1 = mockReq({ orgId });
      const res1 = mockRes();
      await orgRateLimitMiddleware(req1, res1, vi.fn());

      // After 1 request, remaining = 1000 - 1 = 999
      expect(res1.setHeader).toHaveBeenCalledWith("X-RateLimit-Remaining", "999");

      const req2 = mockReq({ orgId });
      const res2 = mockRes();
      await orgRateLimitMiddleware(req2, res2, vi.fn());

      // After 2 requests, remaining = 1000 - 2 = 998
      expect(res2.setHeader).toHaveBeenCalledWith("X-RateLimit-Remaining", "998");
    });

    it("sets X-RateLimit-Reset with seconds until window reset", async () => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));

      const orgId = `org-header-reset-${uniqueCounter}`;
      const req = mockReq({ orgId });
      const res = mockRes();
      const next = vi.fn();

      await orgRateLimitMiddleware(req, res, next);

      // Window is 15 minutes = 900 seconds
      expect(res.setHeader).toHaveBeenCalledWith("X-RateLimit-Reset", "900");
    });
  });

  describe("plan tier limits", () => {
    it("free tier org is limited to 1000 requests", async () => {
      const orgId = `org-free-${uniqueCounter}`;
      vi.mocked(storage.getOrganization).mockResolvedValue({
        id: orgId,
        name: "Free Org",
        plan: "free",
      } as any);

      const req = mockReq({ orgId });
      const res = mockRes();
      await orgRateLimitMiddleware(req, res, vi.fn());

      expect(res.setHeader).toHaveBeenCalledWith("X-RateLimit-Limit", "1000");
    });

    it("pro tier org is limited to 5000 requests", async () => {
      const orgId = `org-pro-${uniqueCounter}`;
      vi.mocked(storage.getOrganization).mockResolvedValue({
        id: orgId,
        name: "Pro Org",
        plan: "pro",
      } as any);

      const req = mockReq({ orgId });
      const res = mockRes();
      await orgRateLimitMiddleware(req, res, vi.fn());

      expect(res.setHeader).toHaveBeenCalledWith("X-RateLimit-Limit", "5000");
    });

    it("enterprise tier org is limited to 10000 requests", async () => {
      const orgId = `org-enterprise-${uniqueCounter}`;
      vi.mocked(storage.getOrganization).mockResolvedValue({
        id: orgId,
        name: "Enterprise Org",
        plan: "enterprise",
      } as any);

      const req = mockReq({ orgId });
      const res = mockRes();
      await orgRateLimitMiddleware(req, res, vi.fn());

      expect(res.setHeader).toHaveBeenCalledWith("X-RateLimit-Limit", "10000");
    });
  });

  describe("rate limit exhaustion", () => {
    it("returns 429 when limit is exceeded", async () => {
      // Use a very small limit by testing with free tier (1000)
      // To avoid 1000 iterations, we manipulate the bucket directly
      // by sending requests and checking the final one
      const orgId = `org-exhaust-${uniqueCounter}`;

      // We need to exhaust the limit. Instead of 1000 requests,
      // we can test with a fresh module or manipulate internal state.
      // Since we can't access internals, we'll do a focused approach:
      // Send enough requests to hit the limit using a loop
      // For test performance, we'll use a helper that verifies the contract

      // First request should succeed
      const req1 = mockReq({ orgId });
      const res1 = mockRes();
      const next1 = vi.fn();
      await orgRateLimitMiddleware(req1, res1, next1);
      expect(next1).toHaveBeenCalled();

      // Now simulate hitting the limit by making many requests
      // For performance, we do this in a batch of 999 more (total 1000)
      for (let i = 1; i < 1000; i++) {
        const req = mockReq({ orgId });
        const res = mockRes();
        await orgRateLimitMiddleware(req, res, vi.fn());
      }

      // Request 1001 should be rate limited
      const reqOver = mockReq({ orgId });
      const resOver = mockRes();
      const nextOver = vi.fn();
      await orgRateLimitMiddleware(reqOver, resOver, nextOver);

      expect(nextOver).not.toHaveBeenCalled();
      expect(replyRateLimit).toHaveBeenCalled();
    });

    it("sets X-RateLimit-Remaining to 0 when limit exceeded", async () => {
      const orgId = `org-exhaust-remaining-${uniqueCounter}`;

      // Exhaust the free tier limit
      for (let i = 0; i < 1000; i++) {
        const req = mockReq({ orgId });
        const res = mockRes();
        await orgRateLimitMiddleware(req, res, vi.fn());
      }

      // Next request should show remaining = 0
      const reqOver = mockReq({ orgId });
      const resOver = mockRes();
      await orgRateLimitMiddleware(reqOver, resOver, vi.fn());

      expect(resOver.setHeader).toHaveBeenCalledWith("X-RateLimit-Remaining", "0");
    });
  });

  describe("bucket expiry", () => {
    it("resets bucket after 15-minute window expires", async () => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));

      const orgId = `org-expiry-${uniqueCounter}`;

      // Exhaust the limit
      for (let i = 0; i < 1000; i++) {
        const req = mockReq({ orgId });
        const res = mockRes();
        await orgRateLimitMiddleware(req, res, vi.fn());
      }

      // Verify exhausted
      const reqBlocked = mockReq({ orgId });
      const resBlocked = mockRes();
      const nextBlocked = vi.fn();
      await orgRateLimitMiddleware(reqBlocked, resBlocked, nextBlocked);
      expect(nextBlocked).not.toHaveBeenCalled();

      // Advance time past 15-minute window
      vi.advanceTimersByTime(15 * 60 * 1000 + 1);

      // New request should succeed
      const reqAfter = mockReq({ orgId });
      const resAfter = mockRes();
      const nextAfter = vi.fn();
      await orgRateLimitMiddleware(reqAfter, resAfter, nextAfter);

      expect(nextAfter).toHaveBeenCalled();
    });
  });

  describe("IP-based fallback", () => {
    it("falls back to IP-based bucketing when orgId is absent", async () => {
      const ip = `10.0.0.${uniqueCounter}`;
      const req = mockReq({ ip, socket: { remoteAddress: ip } });
      const res = mockRes();
      const next = vi.fn();

      await orgRateLimitMiddleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(res.setHeader).toHaveBeenCalledWith("X-RateLimit-Limit", "1000");
    });
  });

  describe("resolveOrgPlan fallback", () => {
    it("defaults to free when org lookup fails", async () => {
      vi.mocked(storage.getOrganization).mockRejectedValue(new Error("DB down"));

      const orgId = `org-plan-fail-${uniqueCounter}`;
      const req = mockReq({ orgId });
      const res = mockRes();
      const next = vi.fn();

      await orgRateLimitMiddleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(res.setHeader).toHaveBeenCalledWith("X-RateLimit-Limit", "1000");
    });
  });

  describe("getOrgRateLimitStats", () => {
    it("returns active bucket count and details", async () => {
      const orgId = `org-stats-${uniqueCounter}`;
      const req = mockReq({ orgId });
      const res = mockRes();
      await orgRateLimitMiddleware(req, res, vi.fn());

      const stats = getOrgRateLimitStats();

      expect(stats.activeBuckets).toBeGreaterThanOrEqual(1);
      expect(stats.bucketDetails).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            count: expect.any(Number),
            remaining: expect.any(Number),
            resetAt: expect.any(String),
          }),
        ]),
      );
    });
  });
});
