/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unused-vars */
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

import { storage } from "../storage";
import { resolveOrgContext, requireOrgId, requireOrgRole, requireMinRole, requirePermission } from "../rbac";

function mockReq(overrides: Record<string, unknown> = {}): Request {
  return {
    headers: {},
    path: "/api/alerts",
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

describe("RBAC", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("resolveOrgContext", () => {
    it("returns 401 when no user is present", async () => {
      const req = mockReq({ user: undefined });
      const res = mockRes();
      const next = vi.fn();

      await resolveOrgContext(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(401);
    });

    it("returns 401 when user has no id", async () => {
      const req = mockReq({ user: { email: "test@example.com" } });
      const res = mockRes();
      const next = vi.fn();

      await resolveOrgContext(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(401);
    });

    it("sets null org context when user has no memberships", async () => {
      (storage.getUserMemberships as any).mockResolvedValue([]);
      const req = mockReq();
      const res = mockRes();
      const next = vi.fn();

      await resolveOrgContext(req, res, next);

      expect(next).toHaveBeenCalled();
      expect((req as any).orgId).toBeNull();
      expect((req as any).orgRole).toBeNull();
      expect((req as any).membership).toBeNull();
    });

    it("uses first active membership when no x-org-id header", async () => {
      (storage.getUserMemberships as any).mockResolvedValue([
        { orgId: "org-1", role: "admin", status: "active" },
        { orgId: "org-2", role: "analyst", status: "active" },
      ]);
      const req = mockReq();
      const res = mockRes();
      const next = vi.fn();

      await resolveOrgContext(req, res, next);

      expect(next).toHaveBeenCalled();
      expect((req as any).orgId).toBe("org-1");
      expect((req as any).orgRole).toBe("admin");
    });

    it("selects org from x-org-id header when present", async () => {
      (storage.getUserMemberships as any).mockResolvedValue([
        { orgId: "org-1", role: "admin", status: "active" },
        { orgId: "org-2", role: "analyst", status: "active" },
      ]);
      const req = mockReq({ headers: { "x-org-id": "org-2" } });
      const res = mockRes();
      const next = vi.fn();

      await resolveOrgContext(req, res, next);

      expect(next).toHaveBeenCalled();
      expect((req as any).orgId).toBe("org-2");
      expect((req as any).orgRole).toBe("analyst");
    });

    it("returns 403 when x-org-id is not in memberships", async () => {
      (storage.getUserMemberships as any).mockResolvedValue([{ orgId: "org-1", role: "admin", status: "active" }]);
      const req = mockReq({ headers: { "x-org-id": "org-malicious" } });
      const res = mockRes();
      const next = vi.fn();

      await resolveOrgContext(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
    });

    it("filters out inactive memberships", async () => {
      (storage.getUserMemberships as any).mockResolvedValue([
        { orgId: "org-1", role: "admin", status: "suspended" },
        { orgId: "org-2", role: "analyst", status: "active" },
      ]);
      const req = mockReq();
      const res = mockRes();
      const next = vi.fn();

      await resolveOrgContext(req, res, next);

      expect(next).toHaveBeenCalled();
      expect((req as any).orgId).toBe("org-2");
      expect((req as any).orgRole).toBe("analyst");
    });

    it("audits cross-org access attempt", async () => {
      (storage.getUserMemberships as any).mockResolvedValue([{ orgId: "org-1", role: "admin", status: "active" }]);
      const req = mockReq({ headers: { "x-org-id": "org-other" } });
      const res = mockRes();
      const next = vi.fn();

      await resolveOrgContext(req, res, next);

      expect(storage.createAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          action: "org_access_denied",
          resourceId: "org-other",
        }),
      );
    });
  });

  describe("requireOrgId", () => {
    it("calls next when orgId is set", () => {
      const req = mockReq({ orgId: "org-1", user: { id: "u1" } });
      const res = mockRes();
      const next = vi.fn();

      requireOrgId(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    it("returns 403 when orgId is null", () => {
      const req = mockReq({ orgId: null, user: { id: "u1" } });
      const res = mockRes();
      const next = vi.fn();

      requireOrgId(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
    });

    it("returns 403 when orgId is undefined", () => {
      const req = mockReq({ user: { id: "u1" } });
      const res = mockRes();
      const next = vi.fn();

      requireOrgId(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
    });

    it("returns 403 when orgId is not a string", () => {
      const req = mockReq({ orgId: 123, user: { id: "u1" } });
      const res = mockRes();
      const next = vi.fn();

      requireOrgId(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
    });
  });

  describe("requireOrgRole", () => {
    it("allows matching role", () => {
      const middleware = requireOrgRole("admin", "owner");
      const req = mockReq({ orgRole: "admin" });
      const res = mockRes();
      const next = vi.fn();

      middleware(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    it("rejects non-matching role", () => {
      const middleware = requireOrgRole("admin", "owner");
      const req = mockReq({ orgRole: "analyst" });
      const res = mockRes();
      const next = vi.fn();

      middleware(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
    });

    it("rejects when no role is set", () => {
      const middleware = requireOrgRole("admin");
      const req = mockReq({ orgRole: null });
      const res = mockRes();
      const next = vi.fn();

      middleware(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
    });
  });

  describe("requireMinRole", () => {
    it("allows owner when minimum is admin", () => {
      const middleware = requireMinRole("admin");
      const req = mockReq({ orgRole: "owner" });
      const res = mockRes();
      const next = vi.fn();

      middleware(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    it("allows admin when minimum is admin", () => {
      const middleware = requireMinRole("admin");
      const req = mockReq({ orgRole: "admin" });
      const res = mockRes();
      const next = vi.fn();

      middleware(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    it("rejects analyst when minimum is admin", () => {
      const middleware = requireMinRole("admin");
      const req = mockReq({ orgRole: "analyst" });
      const res = mockRes();
      const next = vi.fn();

      middleware(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
    });

    it("rejects read_only when minimum is analyst", () => {
      const middleware = requireMinRole("analyst");
      const req = mockReq({ orgRole: "read_only" });
      const res = mockRes();
      const next = vi.fn();

      middleware(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
    });

    it("allows all roles when minimum is read_only", () => {
      const middleware = requireMinRole("read_only");

      for (const role of ["owner", "admin", "analyst", "read_only"]) {
        const req = mockReq({ orgRole: role });
        const res = mockRes();
        const next = vi.fn();

        middleware(req, res, next);

        expect(next).toHaveBeenCalled();
      }
    });

    it("rejects when no role is set", () => {
      const middleware = requireMinRole("read_only");
      const req = mockReq({ orgRole: null });
      const res = mockRes();
      const next = vi.fn();

      middleware(req, res, next);

      expect(next).not.toHaveBeenCalled();
    });
  });

  describe("requirePermission", () => {
    it("allows owner to access any scope:action", () => {
      const middleware = requirePermission("settings", "admin");
      const req = mockReq({ orgRole: "owner" });
      const res = mockRes();
      const next = vi.fn();

      middleware(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    it("allows admin to read/write incidents", () => {
      const middleware = requirePermission("incidents", "write");
      const req = mockReq({ orgRole: "admin" });
      const res = mockRes();
      const next = vi.fn();

      middleware(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    it("allows analyst to read connectors", () => {
      const middleware = requirePermission("connectors", "read");
      const req = mockReq({ orgRole: "analyst" });
      const res = mockRes();
      const next = vi.fn();

      middleware(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    it("rejects analyst from writing connectors", () => {
      const middleware = requirePermission("connectors", "write");
      const req = mockReq({ orgRole: "analyst" });
      const res = mockRes();
      const next = vi.fn();

      middleware(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
    });

    it("rejects read_only from writing incidents", () => {
      const middleware = requirePermission("incidents", "write");
      const req = mockReq({ orgRole: "read_only" });
      const res = mockRes();
      const next = vi.fn();

      middleware(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
    });

    it("rejects read_only from api_keys scope entirely", () => {
      const middleware = requirePermission("api_keys", "read");
      const req = mockReq({ orgRole: "read_only" });
      const res = mockRes();
      const next = vi.fn();

      middleware(req, res, next);

      expect(next).not.toHaveBeenCalled();
    });

    it("rejects when no role is set", () => {
      const middleware = requirePermission("incidents", "read");
      const req = mockReq({ orgRole: null });
      const res = mockRes();
      const next = vi.fn();

      middleware(req, res, next);

      expect(next).not.toHaveBeenCalled();
    });

    it("rejects for non-existent scope", () => {
      const middleware = requirePermission("nonexistent", "read");
      const req = mockReq({ orgRole: "owner" });
      const res = mockRes();
      const next = vi.fn();

      middleware(req, res, next);

      expect(next).not.toHaveBeenCalled();
    });
  });

  describe("role hierarchy enforcement", () => {
    it("enforces complete role hierarchy: owner > admin > analyst > read_only", () => {
      const roles = ["owner", "admin", "analyst", "read_only"];
      const expectedLevels = [4, 3, 2, 1];

      for (let i = 0; i < roles.length; i++) {
        for (let j = i; j < roles.length; j++) {
          const middleware = requireMinRole(roles[j]);
          const req = mockReq({ orgRole: roles[i] });
          const res = mockRes();
          const next = vi.fn();

          middleware(req, res, next);

          expect(next).toHaveBeenCalled();
        }
      }
    });

    it("rejects lower roles for higher requirements", () => {
      const middleware = requireMinRole("owner");

      for (const role of ["admin", "analyst", "read_only"]) {
        const req = mockReq({ orgRole: role });
        const res = mockRes();
        const next = vi.fn();

        middleware(req, res, next);

        expect(next).not.toHaveBeenCalled();
      }
    });
  });
});
