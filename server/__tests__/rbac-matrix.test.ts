/* eslint-disable @typescript-eslint/no-explicit-any */
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
