/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unused-vars */
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { Request, Response } from "express";

vi.mock("../storage", () => ({
  storage: {
    getUserMemberships: vi.fn(),
    getOrganization: vi.fn(),
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
  replyForbidden: vi.fn().mockImplementation((res: any, message: string, code = "FORBIDDEN") => {
    res.status(403);
    res.json({ data: null, errors: [{ code, message }] });
    return res;
  }),
  replyInternal: vi.fn().mockImplementation((res: any, message: string) => {
    res.status(500);
    res.json({ data: null, errors: [{ code: "INTERNAL_ERROR", message }] });
    return res;
  }),
  ERROR_CODES: {
    UNAUTHENTICATED: "UNAUTHENTICATED",
    FORBIDDEN: "FORBIDDEN",
    PERMISSION_DENIED: "PERMISSION_DENIED",
    ORG_ACCESS_DENIED: "ORG_ACCESS_DENIED",
    ORG_MEMBERSHIP_REQUIRED: "ORG_MEMBERSHIP_REQUIRED",
    READ_ONLY_CONTEXT: "READ_ONLY_CONTEXT",
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
      compliance: ["read", "write", "admin"],
      security_awareness: ["read", "write", "admin"],
      physical_security: ["read", "write", "admin"],
    },
    admin: {
      incidents: ["read", "write", "admin"],
      connectors: ["read", "write", "admin"],
      api_keys: ["read", "write", "admin"],
      response_actions: ["read", "write", "admin"],
      settings: ["read", "write"],
      team: ["read", "write"],
      compliance: ["read", "write", "admin"],
      security_awareness: ["read", "write", "admin"],
      physical_security: ["read", "write", "admin"],
    },
    analyst: {
      incidents: ["read", "write"],
      connectors: ["read"],
      api_keys: ["read"],
      response_actions: ["read", "write"],
      settings: ["read"],
      team: ["read"],
      compliance: ["read", "write"],
      security_awareness: ["read", "write"],
      physical_security: ["read", "write"],
    },
    read_only: {
      incidents: ["read"],
      connectors: ["read"],
      api_keys: [],
      response_actions: ["read"],
      settings: ["read"],
      team: ["read"],
      compliance: ["read"],
      security_awareness: ["read"],
      physical_security: ["read"],
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

    it("keeps the unambiguous fallback for a single active membership", async () => {
      (storage.getUserMemberships as any).mockResolvedValue([{ orgId: "org-member", role: "owner", status: "active" }]);
      const req = mockReq();
      const res = mockRes();
      const next = vi.fn();

      await resolveOrgContext(req, res, next);

      expect(next).toHaveBeenCalled();
      expect((req as any).orgId).toBe("org-member");
      expect((req as any).orgRole).toBe("owner");
    });

    it("requires an explicit organization for users with multiple active memberships", async () => {
      (storage.getUserMemberships as any).mockResolvedValue([
        { orgId: "org-one", role: "owner", status: "active" },
        { orgId: "org-two", role: "admin", status: "active" },
      ]);
      const req = mockReq();
      const res = mockRes();
      const next = vi.fn();

      await resolveOrgContext(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          errors: [expect.objectContaining({ code: "ORG_MEMBERSHIP_REQUIRED" })],
        }),
      );
      expect(storage.createAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          action: "org_access_denied",
          details: expect.objectContaining({ reason: "multiple_active_memberships" }),
        }),
      );
    });

    it("requires an explicit organization for platform admins", async () => {
      (storage.getUserMemberships as any).mockResolvedValue([{ orgId: "org-admin", role: "owner", status: "active" }]);
      const req = mockReq({
        user: { id: "super-admin", email: "admin@example.com", isSuperAdmin: true },
      });
      const res = mockRes();
      const next = vi.fn();

      await resolveOrgContext(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          errors: [expect.objectContaining({ code: "ORG_MEMBERSHIP_REQUIRED" })],
        }),
      );
      expect(storage.createAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          action: "org_access_denied",
          details: expect.objectContaining({ reason: "platform_admin_requires_explicit_org" }),
        }),
      );
    });

    it("rejects malformed organization selectors instead of falling back to another organization", async () => {
      (storage.getUserMemberships as any).mockResolvedValue([{ orgId: "org-member", role: "owner", status: "active" }]);
      const req = mockReq({
        headers: { "x-org-id": ["org-one", "org-two"] },
      });
      const res = mockRes();
      const next = vi.fn();

      await resolveOrgContext(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          errors: [expect.objectContaining({ code: "ORG_ACCESS_DENIED" })],
        }),
      );
      expect((storage.createAuditLog as any).mock.calls[0][0]).toEqual(
        expect.objectContaining({
          action: "org_access_denied",
          details: expect.objectContaining({ reason: "invalid_org_selector" }),
        }),
      );
    });

    it("resolves a selected organization for a membership-less super-admin as read-only and audits it", async () => {
      (storage.getUserMemberships as any).mockResolvedValue([]);
      (storage.getOrganization as any).mockResolvedValue({ id: "org-selected", name: "Selected Org", deletedAt: null });
      const req = mockReq({
        user: { id: "super-admin", email: "admin@example.com", isSuperAdmin: true },
        sessionID: "session-selected",
        headers: { "x-org-id": "org-selected" },
        path: "/api/alerts",
      });
      const res = mockRes();
      const next = vi.fn();

      await resolveOrgContext(req, res, next);

      expect(next).toHaveBeenCalled();
      expect((req as any).orgId).toBe("org-selected");
      expect((req as any).orgRole).toBe("read_only");
      expect((req as any).membership).toBeNull();
      expect((req as any).orgReadOnly).toBe(true);
      expect(storage.createAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          action: "platform_admin_read_only_org_context",
          userId: "super-admin",
          orgId: "org-selected",
          resourceId: "org-selected",
          details: expect.objectContaining({
            route: "/api/alerts",
            method: "GET",
            selectedWithoutMembership: true,
          }),
        }),
      );
    });

    it("audits a read-only tenant context once across repeated requests in one session", async () => {
      (storage.getUserMemberships as any).mockResolvedValue([]);
      (storage.getOrganization as any).mockResolvedValue({ id: "org-selected", deletedAt: null });
      const session = {};
      const firstReq = mockReq({
        user: { id: "super-admin", email: "admin@example.com", isSuperAdmin: true },
        sessionID: "session-repeated",
        session,
        headers: { "x-org-id": "org-selected" },
        path: "/api/alerts",
      });
      const secondReq = mockReq({
        user: { id: "super-admin", email: "admin@example.com", isSuperAdmin: true },
        sessionID: "session-repeated",
        session,
        headers: { "x-org-id": "org-selected" },
        path: "/api/incidents",
      });
      const firstRes = mockRes();
      const secondRes = mockRes();

      await resolveOrgContext(firstReq, firstRes, vi.fn());
      await resolveOrgContext(secondReq, secondRes, vi.fn());

      expect(storage.createAuditLog).toHaveBeenCalledTimes(1);
      expect(storage.createAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          details: expect.objectContaining({ route: "/api/alerts" }),
        }),
      );
      expect((session as any).platformAdminReadOnlyOrganizations).toEqual({ "org-selected": true });
    });

    it("audits each selected organization once within the same session", async () => {
      (storage.getUserMemberships as any).mockResolvedValue([]);
      (storage.getOrganization as any).mockImplementation(async (id: string) => ({ id, deletedAt: null }));
      const session = {};
      const firstReq = mockReq({
        user: { id: "super-admin", email: "admin@example.com", isSuperAdmin: true },
        sessionID: "session-multiple-orgs",
        session,
        headers: { "x-org-id": "org-one" },
      });
      const secondReq = mockReq({
        user: { id: "super-admin", email: "admin@example.com", isSuperAdmin: true },
        sessionID: "session-multiple-orgs",
        session,
        headers: { "x-org-id": "org-two" },
      });

      await resolveOrgContext(firstReq, mockRes(), vi.fn());
      await resolveOrgContext(secondReq, mockRes(), vi.fn());

      expect(storage.createAuditLog).toHaveBeenCalledTimes(2);
      expect((session as any).platformAdminReadOnlyOrganizations).toEqual({
        "org-one": true,
        "org-two": true,
      });
    });

    it("refuses writes in a membership-less super-admin read-only context", async () => {
      (storage.getUserMemberships as any).mockResolvedValue([]);
      (storage.getOrganization as any).mockResolvedValue({ id: "org-selected", deletedAt: null });
      const req = mockReq({
        user: { id: "super-admin", email: "admin@example.com", isSuperAdmin: true },
        sessionID: "session-write",
        headers: { "x-org-id": "org-selected" },
        method: "POST",
      });
      const res = mockRes();
      const next = vi.fn();

      await resolveOrgContext(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          errors: [expect.objectContaining({ code: "READ_ONLY_CONTEXT" })],
        }),
      );
    });

    it("fails closed when read-only context auditing fails", async () => {
      (storage.getUserMemberships as any).mockResolvedValue([]);
      (storage.getOrganization as any).mockResolvedValue({ id: "org-selected", deletedAt: null });
      (storage.createAuditLog as any).mockRejectedValueOnce(new Error("audit unavailable"));
      const req = mockReq({
        user: { id: "super-admin", email: "admin@example.com", isSuperAdmin: true },
        sessionID: "session-audit-failure",
        session: {},
        headers: { "x-org-id": "org-selected" },
      });
      const res = mockRes();
      const next = vi.fn();

      await resolveOrgContext(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          errors: [expect.objectContaining({ code: "INTERNAL_ERROR" })],
        }),
      );

      const retryReq = mockReq({
        user: { id: "super-admin", email: "admin@example.com", isSuperAdmin: true },
        sessionID: "session-audit-failure",
        session: (req as any).session,
        headers: { "x-org-id": "org-selected" },
      });
      const retryRes = mockRes();
      const retryNext = vi.fn();

      await resolveOrgContext(retryReq, retryRes, retryNext);

      expect(retryNext).toHaveBeenCalled();
      expect(storage.createAuditLog).toHaveBeenCalledTimes(2);
      expect((retryReq as any).orgReadOnly).toBe(true);
    });

    it("keeps owner role for a super-admin who is an active member", async () => {
      (storage.getUserMemberships as any).mockResolvedValue([
        { orgId: "org-member", role: "analyst", status: "active" },
      ]);
      const req = mockReq({
        user: { id: "super-admin", email: "admin@example.com", isSuperAdmin: true },
        headers: { "x-org-id": "org-member" },
      });
      const res = mockRes();
      const next = vi.fn();

      await resolveOrgContext(req, res, next);

      expect(next).toHaveBeenCalled();
      expect((req as any).orgRole).toBe("owner");
      expect((req as any).orgReadOnly).toBe(false);
    });

    it("denies membership-less non-super-admin access to a selected organization", async () => {
      (storage.getUserMemberships as any).mockResolvedValue([]);
      const req = mockReq({
        user: { id: "user-1", email: "user@example.com" },
        headers: { "x-org-id": "org-other" },
      });
      const res = mockRes();
      const next = vi.fn();

      await resolveOrgContext(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
      expect(storage.getOrganization).not.toHaveBeenCalled();
    });

    it("denies a super-admin selecting a missing or deleted organization", async () => {
      (storage.getUserMemberships as any).mockResolvedValue([]);
      (storage.getOrganization as any)
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce({ id: "org-deleted", deletedAt: new Date() });

      for (const orgId of ["org-missing", "org-deleted"]) {
        const req = mockReq({
          user: { id: "super-admin", email: "admin@example.com", isSuperAdmin: true },
          sessionID: `session-${orgId}`,
          headers: { "x-org-id": orgId },
        });
        const res = mockRes();
        const next = vi.fn();

        await resolveOrgContext(req, res, next);

        expect(next).not.toHaveBeenCalled();
        expect(res.status).toHaveBeenCalledWith(403);
      }
    });

    it("rejects multiple active memberships when no x-org-id header", async () => {
      (storage.getUserMemberships as any).mockResolvedValue([
        { orgId: "org-1", role: "admin", status: "active" },
        { orgId: "org-2", role: "analyst", status: "active" },
      ]);
      const req = mockReq();
      const res = mockRes();
      const next = vi.fn();

      await resolveOrgContext(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          errors: [expect.objectContaining({ code: "ORG_MEMBERSHIP_REQUIRED" })],
        }),
      );
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
    it("refuses writes when a read-only context reaches the request guard", () => {
      const req = mockReq({ orgId: "org-1", orgReadOnly: true, method: "PATCH" });
      const res = mockRes();
      const next = vi.fn();

      requireOrgId(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          errors: [expect.objectContaining({ code: "READ_ONLY_CONTEXT" })],
        }),
      );
    });

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
