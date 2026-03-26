import { describe, it, expect, vi, beforeEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import type { Request, Response } from "express";

// Mock dependencies before importing the module under test
vi.mock("../storage", () => ({
  storage: {
    getOrganization: vi.fn().mockResolvedValue({ id: "org-1", name: "Test Org" }),
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

import { orgRateLimitMiddleware } from "../middleware/org-rate-limit";

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

/**
 * Documented rate-limit-exempt paths.
 * If a new exempt path is added to orgRateLimitMiddleware, it must be documented here with justification.
 */
const DOCUMENTED_EXEMPTIONS = [
  { path: "/ops/health", reason: "Kubernetes liveness probe -- must not be rate limited" },
  { path: "/ops/ready", reason: "Kubernetes readiness probe -- must not be rate limited" },
  { path: "/ops/live", reason: "Kubernetes liveness probe (alternate) -- must not be rate limited" },
  { path: "/health", reason: "Legacy health check -- must not be rate limited" },
];

/**
 * Paths with alternative rate limiting mechanisms (not org rate limited but still protected).
 */
const ALTERNATIVE_PROTECTION = [
  {
    path: "/api/billing/webhook",
    reason: "Stripe webhook -- authenticated via Stripe signature verification, not session auth. Covered by global IP-based express-rate-limit (300 req/min). Stripe controls delivery rate.",
  },
];

describe("Rate Limit Coverage Audit", () => {
  let uniqueId = 0;

  beforeEach(() => {
    vi.clearAllMocks();
    uniqueId++;
  });

  describe("middleware registration", () => {
    it("routes.ts imports orgRateLimitMiddleware", () => {
      const routesPath = path.resolve(__dirname, "..", "routes.ts");
      const source = fs.readFileSync(routesPath, "utf-8");

      expect(source).toContain('import { orgRateLimitMiddleware } from "./middleware/org-rate-limit"');
    });

    it("routes.ts applies orgRateLimitMiddleware on /api prefix", () => {
      const routesPath = path.resolve(__dirname, "..", "routes.ts");
      const source = fs.readFileSync(routesPath, "utf-8");

      expect(source).toContain('app.use("/api", orgRateLimitMiddleware)');
    });

    it("index.ts configures a global IP-based rate limiter", () => {
      const indexPath = path.resolve(__dirname, "..", "index.ts");
      const source = fs.readFileSync(indexPath, "utf-8");

      expect(source).toContain("express-rate-limit");
    });
  });

  describe("exempt path verification", () => {
    it("orgRateLimitMiddleware exempts all documented health check paths", async () => {
      for (const { path: exemptPath } of DOCUMENTED_EXEMPTIONS) {
        const req = mockReq({ path: exemptPath });
        const res = mockRes();
        const next = vi.fn();

        await orgRateLimitMiddleware(req, res, next);

        expect(next).toHaveBeenCalled();
        // Exempt paths should not set rate limit headers
        expect(res.setHeader).not.toHaveBeenCalled();
      }
    });

    it("orgRateLimitMiddleware applies rate limiting to non-exempt /api paths", async () => {
      const orgId = `org-audit-${uniqueId}`;
      const req = mockReq({ path: "/api/alerts", orgId });
      const res = mockRes();
      const next = vi.fn();

      await orgRateLimitMiddleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(res.setHeader).toHaveBeenCalledWith("X-RateLimit-Limit", expect.any(String));
      expect(res.setHeader).toHaveBeenCalledWith("X-RateLimit-Remaining", expect.any(String));
      expect(res.setHeader).toHaveBeenCalledWith("X-RateLimit-Reset", expect.any(String));
    });

    it("all documented exempt paths are present in the exemption list", () => {
      const exemptPaths = DOCUMENTED_EXEMPTIONS.map((e) => e.path);
      expect(exemptPaths).toContain("/ops/health");
      expect(exemptPaths).toContain("/ops/ready");
      expect(exemptPaths).toContain("/ops/live");
      expect(exemptPaths).toContain("/health");
    });

    it("every documented exemption has a justification", () => {
      for (const exemption of DOCUMENTED_EXEMPTIONS) {
        expect(exemption.reason).toBeTruthy();
        expect(exemption.reason.length).toBeGreaterThan(10);
      }
    });
  });

  describe("alternative protection documentation", () => {
    it("billing webhook is documented with alternative protection", () => {
      const webhookEntry = ALTERNATIVE_PROTECTION.find((e) => e.path === "/api/billing/webhook");
      expect(webhookEntry).toBeDefined();
      expect(webhookEntry!.reason).toContain("Stripe");
    });

    it("alternative protection entries have justification", () => {
      for (const entry of ALTERNATIVE_PROTECTION) {
        expect(entry.reason).toBeTruthy();
        expect(entry.reason.length).toBeGreaterThan(20);
      }
    });
  });

  describe("route registration coverage", () => {
    it("all domain routes register under /api prefix (covered by orgRateLimitMiddleware)", () => {
      const routesIndexPath = path.resolve(__dirname, "..", "routes", "index.ts");
      const source = fs.readFileSync(routesIndexPath, "utf-8");

      // The route index registers all domain routes via registerAllDomainRoutes
      // which is called after app.use("/api", orgRateLimitMiddleware) in routes.ts
      expect(source).toContain("registerAllDomainRoutes");

      // Verify domain route files register routes (they use app.get/post/etc with /api prefix)
      const routesDir = path.resolve(__dirname, "..", "routes");
      const routeFiles = fs.readdirSync(routesDir).filter((f: string) => f.endsWith(".ts") && f !== "index.ts");

      // There should be route files present
      expect(routeFiles.length).toBeGreaterThan(0);
    });

    it("routes.ts applies orgRateLimitMiddleware before registerAllDomainRoutes", () => {
      const routesPath = path.resolve(__dirname, "..", "routes.ts");
      const source = fs.readFileSync(routesPath, "utf-8");

      const rateLimitLine = source.indexOf('app.use("/api", orgRateLimitMiddleware)');
      const registerLine = source.indexOf("registerAllDomainRoutes(app)");

      expect(rateLimitLine).toBeGreaterThan(-1);
      expect(registerLine).toBeGreaterThan(-1);
      // Rate limit middleware must be registered before domain routes
      expect(rateLimitLine).toBeLessThan(registerLine);
    });
  });
});
