import { describe, expect, it, vi } from "vitest";
import type { Request, Response } from "express";

vi.mock("../storage", () => ({
  storage: {
    getSubscription: vi.fn().mockResolvedValue(null),
    getPlan: vi.fn(),
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
  replyRateLimit: vi.fn().mockImplementation((res: any, message: string, code: string) => {
    res.status(429);
    res.json({ data: null, errors: [{ code, message }] });
    return res;
  }),
}));

import {
  AUTHENTICATED_API_LIMIT,
  UNAUTHENTICATED_API_LIMIT,
  getApiRateLimit,
  getApiRateLimitKey,
} from "../routes/shared";
import { planAwareRateLimit } from "../middleware/plan-enforcement-enhanced";
import { storage } from "../storage";

function request(overrides: Record<string, unknown> = {}): Request {
  return {
    ip: "127.0.0.1",
    socket: { remoteAddress: "127.0.0.1" },
    isAuthenticated: () => false,
    ...overrides,
  } as unknown as Request;
}

function response(): Response {
  return {
    setHeader: vi.fn(),
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
  } as unknown as Response;
}

describe("API rate-limit classification", () => {
  it("uses an authenticated user key and interactive ceiling for session traffic", () => {
    const req = request({
      isAuthenticated: () => true,
      user: { id: "user-1" },
    });

    expect(getApiRateLimitKey(req)).toBe("user:user-1");
    expect(getApiRateLimit(req)).toBe(AUTHENTICATED_API_LIMIT);
    expect(AUTHENTICATED_API_LIMIT).toBe(600);
  });

  it("uses an IP key and the existing ceiling for unauthenticated traffic", () => {
    const req = request({ ip: "192.0.2.20" });

    expect(getApiRateLimitKey(req)).toBe("ip:192.0.2.20");
    expect(getApiRateLimit(req)).toBe(UNAUTHENTICATED_API_LIMIT);
    expect(UNAUTHENTICATED_API_LIMIT).toBe(200);
  });
});

describe("programmatic plan-aware API rate limit", () => {
  it("skips session-cookie traffic", async () => {
    const middleware = planAwareRateLimit();
    const req = request({ orgId: "org-session", user: { id: "user-1" } });
    const res = response();
    const next = vi.fn();

    await middleware(req, res, next);

    expect(next).toHaveBeenCalledOnce();
    expect(res.setHeader).not.toHaveBeenCalled();
  });

  it("enforces the plan quota for API-key traffic with retry headers", async () => {
    const middleware = planAwareRateLimit();
    const next = vi.fn();

    for (let i = 0; i < 100; i++) {
      await middleware(request({ apiKey: { id: "key-1" }, orgId: "org-api" }), response(), next);
    }

    const res = response();
    await middleware(request({ apiKey: { id: "key-1" }, orgId: "org-api" }), res, next);

    expect(next).toHaveBeenCalledTimes(100);
    expect(res.setHeader).toHaveBeenCalledWith("X-RateLimit-Limit", "100");
    expect(res.setHeader).toHaveBeenCalledWith("X-RateLimit-Remaining", "0");
    expect(res.setHeader).toHaveBeenCalledWith("Retry-After", expect.any(String));
    expect(res.status).toHaveBeenCalledWith(429);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        errors: [expect.objectContaining({ code: "RATE_LIMIT_EXCEEDED" })],
      }),
    );
  });

  it("keeps programmatic quota accounting isolated by organization", async () => {
    const middleware = planAwareRateLimit();
    const next = vi.fn();

    for (let i = 0; i < 100; i++) {
      await middleware(request({ apiKey: { id: "key-1" }, orgId: "org-a" }), response(), next);
    }

    const otherOrgResponse = response();
    await middleware(request({ apiKey: { id: "key-2" }, orgId: "org-b" }), otherOrgResponse, next);

    expect(next).toHaveBeenCalledTimes(101);
    expect(otherOrgResponse.status).not.toHaveBeenCalledWith(429);
  });

  it("does not count API-key traffic against session traffic", async () => {
    vi.mocked(storage.getSubscription).mockResolvedValue(null);
    const middleware = planAwareRateLimit();
    const next = vi.fn();

    await middleware(request({ apiKey: { id: "key-1" }, orgId: "org-a" }), response(), next);
    await middleware(request({ orgId: "org-a", user: { id: "user-1" } }), response(), next);

    expect(next).toHaveBeenCalledTimes(2);
  });
});
