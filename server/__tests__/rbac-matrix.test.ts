/* eslint-disable @typescript-eslint/no-explicit-any */
import fs from "node:fs";
import path from "node:path";
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { Request, Response } from "express";

vi.mock("../storage", () => ({
  storage: {
    getUserMemberships: vi.fn(),
    createAuditLog: vi.fn().mockResolvedValue({}),
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
  replyUnauthenticated: vi.fn().mockImplementation((res: any) => {
    res.status(401);
    res.json({ data: null, errors: [{ code: "UNAUTHENTICATED", message: "Authentication required" }] });
    return res;
  }),
  replyForbidden: vi.fn().mockImplementation((res: any, message: string) => {
    res.status(403);
    res.json({ data: null, errors: [{ code: "FORBIDDEN", message }] });
    return res;
  }),
  ERROR_CODES: {
    UNAUTHENTICATED: "UNAUTHENTICATED",
    FORBIDDEN: "FORBIDDEN",
    PERMISSION_DENIED: "PERMISSION_DENIED",
    ORG_ACCESS_DENIED: "ORG_ACCESS_DENIED",
    ORG_MEMBERSHIP_REQUIRED: "ORG_MEMBERSHIP_REQUIRED",
  },
}));

vi.mock("@shared/schema", () => ({
  ROLE_PERMISSIONS: {
    owner: {
      incidents: ["read", "write", "admin"],
      connectors: ["read", "write", "admin"],
      api_keys: ["read", "write", "admin"],
      response_actions: ["read", "write", "admin"],
      settings: ["read", "write", "admin"],
      team: ["read", "write", "admin"],
    },
    admin: {
      incidents: ["read", "write", "admin"],
      connectors: ["read", "write", "admin"],
      api_keys: ["read", "write", "admin"],
      response_actions: ["read", "write", "admin"],
      settings: ["read", "write"],
      team: ["read", "write"],
    },
    analyst: {
      incidents: ["read", "write"],
      connectors: ["read"],
      api_keys: ["read"],
      response_actions: ["read", "write"],
      settings: ["read"],
      team: ["read"],
    },
    read_only: {
      incidents: ["read"],
      connectors: ["read"],
      api_keys: [],
      response_actions: ["read"],
      settings: ["read"],
      team: ["read"],
    },
  },
}));

import { ROLE_PERMISSIONS } from "@shared/schema";
import { requirePermission, requireMinRole } from "../rbac";
import { requireSuperAdmin } from "../middleware/super-admin";

const ALL_ROLES = ["owner", "admin", "analyst", "read_only"];
const ALL_SCOPES = ["incidents", "connectors", "api_keys", "response_actions", "settings", "team"];
const ALL_ACTIONS = ["read", "write", "admin"];

function mockReq(overrides: Record<string, unknown> = {}): Request {
  return {
    headers: {},
    path: "/api/test",
    method: "GET",
    user: { id: "user-1", email: "test@example.com" },
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

describe("RBAC Permission Matrix - Exhaustive", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // Verify the matrix covers exactly 72 combinations
  it("covers exactly 72 role x scope x action combinations", () => {
    const count = ALL_ROLES.length * ALL_SCOPES.length * ALL_ACTIONS.length;
    expect(count).toBe(72);
  });

  // Generate parameterized tests for all 72 combinations
  for (const role of ALL_ROLES) {
    describe(`role: ${role}`, () => {
      for (const scope of ALL_SCOPES) {
        for (const action of ALL_ACTIONS) {
          const allowed = ROLE_PERMISSIONS[role]?.[scope]?.includes(action) ?? false;
          it(`${allowed ? "CAN" : "CANNOT"} ${action} ${scope}`, () => {
            const middleware = requirePermission(scope, action);
            const req = mockReq({ orgRole: role });
            const res = mockRes();
            const next = vi.fn();

            middleware(req, res, next);

            if (allowed) {
              expect(next).toHaveBeenCalled();
              expect(res.status).not.toHaveBeenCalled();
            } else {
              expect(next).not.toHaveBeenCalled();
              expect(res.status).toHaveBeenCalledWith(403);
            }
          });
        }
      }
    });
  }
});

describe("RBAC Edge Cases", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("unknown role", () => {
    for (const scope of ALL_SCOPES) {
      for (const action of ALL_ACTIONS) {
        it(`"hacker" CANNOT ${action} ${scope}`, () => {
          const middleware = requirePermission(scope, action);
          const req = mockReq({ orgRole: "hacker" });
          const res = mockRes();
          const next = vi.fn();

          middleware(req, res, next);

          expect(next).not.toHaveBeenCalled();
          expect(res.status).toHaveBeenCalledWith(403);
        });
      }
    }
  });

  describe("null/undefined role", () => {
    it("null role is denied for all scope x action combinations", () => {
      for (const scope of ALL_SCOPES) {
        for (const action of ALL_ACTIONS) {
          const middleware = requirePermission(scope, action);
          const req = mockReq({ orgRole: null });
          const res = mockRes();
          const next = vi.fn();

          middleware(req, res, next);

          expect(next).not.toHaveBeenCalled();
          expect(res.status).toHaveBeenCalledWith(403);
        }
      }
    });

    it("undefined role is denied for all scope x action combinations", () => {
      for (const scope of ALL_SCOPES) {
        for (const action of ALL_ACTIONS) {
          const middleware = requirePermission(scope, action);
          const req = mockReq({ orgRole: undefined });
          const res = mockRes();
          const next = vi.fn();

          middleware(req, res, next);

          expect(next).not.toHaveBeenCalled();
          expect(res.status).toHaveBeenCalledWith(403);
        }
      }
    });
  });

  describe("non-existent scope", () => {
    for (const role of ALL_ROLES) {
      it(`${role} CANNOT access non-existent scope "superpower"`, () => {
        const middleware = requirePermission("superpower", "read");
        const req = mockReq({ orgRole: role });
        const res = mockRes();
        const next = vi.fn();

        middleware(req, res, next);

        expect(next).not.toHaveBeenCalled();
        expect(res.status).toHaveBeenCalledWith(403);
      });
    }
  });
});

describe("requireMinRole - Hierarchy Matrix", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const ROLES_BY_LEVEL = [
    { role: "owner", level: 4 },
    { role: "admin", level: 3 },
    { role: "analyst", level: 2 },
    { role: "read_only", level: 1 },
  ];

  // Test all 16 combinations (4 user roles x 4 minimum roles)
  for (const userRole of ROLES_BY_LEVEL) {
    for (const minRole of ROLES_BY_LEVEL) {
      const shouldAllow = userRole.level >= minRole.level;
      it(`user "${userRole.role}" (level ${userRole.level}) ${shouldAllow ? "passes" : "fails"} requireMinRole("${minRole.role}") (level ${minRole.level})`, () => {
        const middleware = requireMinRole(minRole.role);
        const req = mockReq({ orgRole: userRole.role });
        const res = mockRes();
        const next = vi.fn();

        middleware(req, res, next);

        if (shouldAllow) {
          expect(next).toHaveBeenCalled();
        } else {
          expect(next).not.toHaveBeenCalled();
          expect(res.status).toHaveBeenCalledWith(403);
        }
      });
    }
  }

  describe("unknown role defaults to level 0 (denied)", () => {
    for (const minRole of ROLES_BY_LEVEL) {
      it(`unknown role "intern" fails requireMinRole("${minRole.role}")`, () => {
        const middleware = requireMinRole(minRole.role);
        const req = mockReq({ orgRole: "intern" });
        const res = mockRes();
        const next = vi.fn();

        middleware(req, res, next);

        expect(next).not.toHaveBeenCalled();
        expect(res.status).toHaveBeenCalledWith(403);
      });
    }
  });
});

describe("write-route authorization coverage", () => {
  const representativeRoutes = [
    { tier: "analyst", route: "POST /api/incidents/:id/comments", minimumRole: "analyst" },
    { tier: "admin", route: "POST /api/connectors", minimumRole: "admin" },
    { tier: "owner", route: "POST /api/jit-secrets/access-requests", minimumRole: "owner" },
  ] as const;

  for (const representative of representativeRoutes) {
    it(`rejects read_only on ${representative.tier} route ${representative.route}`, () => {
      const req = mockReq({ orgRole: "read_only" });
      const res = mockRes();
      const next = vi.fn();

      requireMinRole(representative.minimumRole)(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
    });
  }

  it("rejects read_only on a platform-operator route", () => {
    const req = mockReq({ user: { id: "user-1", isSuperAdmin: false } });
    const res = mockRes();
    const next = vi.fn();

    requireSuperAdmin(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
  });

  it("rejects analyst on an admin-tier route", () => {
    const req = mockReq({ orgRole: "analyst" });
    const res = mockRes();
    const next = vi.fn();

    requireMinRole("admin")(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
  });

  it("keeps every authenticated mutating API route behind authorization", () => {
    const serverRoot = path.resolve(process.cwd(), "server");
    const skipDirectories = new Set(["node_modules", "dist", ".git", "__tests__"]);
    const authzPattern =
      /requireMinRole|requirePermission|requireRole|requireSuperAdmin|requirePlatformAdmin|requireOwner|requireAdmin|requireScope|requireAnyPermission|requirePlanTier/;
    const authnPattern = /isAuthenticated|apiKeyAuth|sensorApiKeyAuth|agentAuth|requireAuth|passport\.authenticate/;
    const callPattern =
      /\bapp\.(post|put|patch|delete)\(\s*["'`]([^"'`]+)["'`]\s*,(.*?)(?:async\s*\(|\(\s*req\b|function\s*\()/gis;
    const arrayPattern = /const\s+(\w+)\s*(?::[^=]+)?=\s*\[([^\]]*)\]/gs;
    const knownGoodUnauthenticated = [
      ["POST", "server/finding-lineage-engine.ts", "/api/auth/login"],
      ["POST", "server/finding-lineage-engine.ts", "/api/auth/login"],
      ["POST", "server/remediation-engine.ts", "/api/auth/login"],
      ["POST", "server/remediation-engine.ts", "/api/auth/login"],
      ["POST", "server/remediation-engine.ts", "/api/auth/login"],
      ["POST", "server/remediation-engine.ts", "/api/auth/login"],
      ["POST", "server/remediation-engine.ts", "/api/auth/login"],
      ["POST", "server/middleware/plan-enforcement-enhanced.ts", "/api/alerts"],
      ["POST", "server/routes/billing.ts", "/api/billing/webhook"],
      ["POST", "server/routes/developer-security.ts", "/api/developer-security/webhooks/github"],
      ["POST", "server/routes/developer-security.ts", "/api/developer-security/webhooks/gitlab"],
      ["POST", "server/routes/log-sources.ts", "/api/native/log-sources/ingest/:token"],
      ["POST", "server/routes/native-sensors.ts", "/api/native-sensors/:id/action-result/:actionId"],
      ["POST", "server/routes/password-reset.ts", "/api/auth/forgot-password"],
      ["POST", "server/routes/password-reset.ts", "/api/auth/reset-password"],
      ["POST", "server/routes/sso.ts", "/api/sso/:slug/acs"],
      ["POST", "server/auth/routes.ts", "/api/register"],
      ["POST", "server/auth/routes.ts", "/api/login"],
      ["POST", "server/auth/routes.ts", "/api/logout"],
    ] as const;
    const failures: string[] = [];

    function walk(directory: string): string[] {
      return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
        const entryPath = path.join(directory, entry.name);
        if (entry.isDirectory()) {
          if (skipDirectories.has(entry.name)) return [];
          return walk(entryPath);
        }
        return entry.name.endsWith(".ts") ? [entryPath] : [];
      });
    }

    for (const filePath of walk(serverRoot)) {
      const relativeFile = path.relative(process.cwd(), filePath);
      const source = fs.readFileSync(filePath, "utf8");
      const localMiddleware = Object.fromEntries(
        [...source.matchAll(arrayPattern)].map((match) => [match[1], match[2]]),
      );

      for (const match of source.matchAll(callPattern)) {
        const verb = match[1].toUpperCase();
        const route = match[2];
        if (!route.startsWith("/api")) continue;

        let middleware = match[3];
        for (let pass = 0; pass < 3; pass += 1) {
          for (const [name, body] of Object.entries(localMiddleware)) {
            if (new RegExp(`\\b${name}\\b`).test(middleware)) middleware += ` ${body}`;
          }
        }

        const key = `${verb} ${relativeFile} ${route}`;
        const isKnownGoodUnauthenticated = knownGoodUnauthenticated.some(
          ([allowedVerb, allowedFile, allowedRoute]) => key === `${allowedVerb} ${allowedFile} ${allowedRoute}`,
        );
        if (!authnPattern.test(middleware) && !isKnownGoodUnauthenticated) {
          failures.push(`${key}: missing explicit allow-list entry`);
        }
        if (authnPattern.test(middleware) && !authzPattern.test(middleware)) {
          failures.push(`${key}: authenticated route has no authorization middleware`);
        }
      }
    }

    expect(failures).toEqual([]);
  });
});
