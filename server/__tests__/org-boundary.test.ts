import { describe, it, expect, vi, beforeEach } from "vitest";
import type { Request, Response, NextFunction } from "express";
import { resolveOrgContext, requireOrgId } from "../rbac";

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

import { storage } from "../storage";

function mockReq(overrides: Record<string, unknown> = {}): Request {
  return {
    headers: {},
    path: "/api/alerts",
    method: "GET",
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

describe("Cross-tenant boundary enforcement", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("resolveOrgContext", () => {
    it("rejects unauthenticated requests", async () => {
      const req = mockReq({ user: null });
      const res = mockRes();
      const next = vi.fn();

      await resolveOrgContext(req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(next).not.toHaveBeenCalled();
    });

    it("rejects access to non-member org via x-org-id header", async () => {
      const userOrgA = "org-aaa-111";
      const targetOrgB = "org-bbb-222";

      (storage.getUserMemberships as any).mockResolvedValue([
        { orgId: userOrgA, role: "analyst", status: "active" },
      ]);

      const req = mockReq({
        user: { id: "user-1", email: "alice@example.com" },
        headers: { "x-org-id": targetOrgB },
      });
      const res = mockRes();
      const next = vi.fn();

      await resolveOrgContext(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(next).not.toHaveBeenCalled();

      expect(storage.createAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          action: "org_access_denied",
          resourceId: targetOrgB,
          userId: "user-1",
        }),
      );
    });

    it("allows access to member org via x-org-id header", async () => {
      const orgId = "org-aaa-111";

      (storage.getUserMemberships as any).mockResolvedValue([
        { orgId, role: "analyst", status: "active" },
      ]);

      const req = mockReq({
        user: { id: "user-1", email: "alice@example.com" },
        headers: { "x-org-id": orgId },
      });
      const res = mockRes();
      const next = vi.fn();

      await resolveOrgContext(req, res, next);

      expect(next).toHaveBeenCalled();
      expect((req as any).orgId).toBe(orgId);
    });

    it("uses first active membership when no x-org-id header", async () => {
      const orgId = "org-aaa-111";

      (storage.getUserMemberships as any).mockResolvedValue([
        { orgId, role: "admin", status: "active" },
        { orgId: "org-bbb-222", role: "analyst", status: "active" },
      ]);

      const req = mockReq({
        user: { id: "user-1", email: "alice@example.com" },
      });
      const res = mockRes();
      const next = vi.fn();

      await resolveOrgContext(req, res, next);

      expect(next).toHaveBeenCalled();
      expect((req as any).orgId).toBe(orgId);
    });

    it("sets null orgId when user has no active memberships", async () => {
      (storage.getUserMemberships as any).mockResolvedValue([
        { orgId: "org-aaa", role: "analyst", status: "suspended" },
      ]);

      const req = mockReq({
        user: { id: "user-1", email: "alice@example.com" },
      });
      const res = mockRes();
      const next = vi.fn();

      await resolveOrgContext(req, res, next);

      expect(next).toHaveBeenCalled();
      expect((req as any).orgId).toBeNull();
    });

    it("logs org context switch when user switches orgs", async () => {
      const orgA = "org-aaa-111";
      const orgB = "org-bbb-222";

      (storage.getUserMemberships as any).mockResolvedValue([
        { orgId: orgA, role: "analyst", status: "active" },
        { orgId: orgB, role: "admin", status: "active" },
      ]);

      const req = mockReq({
        user: { id: "user-1", email: "alice@example.com", orgId: orgA },
        headers: { "x-org-id": orgB },
      });
      const res = mockRes();
      const next = vi.fn();

      await resolveOrgContext(req, res, next);

      expect(next).toHaveBeenCalled();
      expect((req as any).orgId).toBe(orgB);

      expect(storage.createAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          action: "org_context_switch",
          details: expect.objectContaining({
            previousOrgId: orgA,
            newOrgId: orgB,
          }),
        }),
      );
    });

    it("ignores suspended memberships when resolving org context", async () => {
      const activeOrg = "org-active";
      const suspendedOrg = "org-suspended";

      (storage.getUserMemberships as any).mockResolvedValue([
        { orgId: suspendedOrg, role: "admin", status: "suspended" },
        { orgId: activeOrg, role: "analyst", status: "active" },
      ]);

      const req = mockReq({
        user: { id: "user-1", email: "alice@example.com" },
        headers: { "x-org-id": suspendedOrg },
      });
      const res = mockRes();
      const next = vi.fn();

      await resolveOrgContext(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(next).not.toHaveBeenCalled();
    });
  });

  describe("requireOrgId", () => {
    it("blocks requests without orgId", () => {
      const req = mockReq({ orgId: null, user: { id: "user-1", email: "a@b.com" } });
      const res = mockRes();
      const next = vi.fn();

      requireOrgId(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(next).not.toHaveBeenCalled();
    });

    it("blocks requests with empty string orgId", () => {
      const req = mockReq({ orgId: "", user: { id: "user-1", email: "a@b.com" } });
      const res = mockRes();
      const next = vi.fn();

      requireOrgId(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(next).not.toHaveBeenCalled();
    });

    it("blocks requests with non-string orgId", () => {
      const req = mockReq({ orgId: 12345, user: { id: "user-1", email: "a@b.com" } });
      const res = mockRes();
      const next = vi.fn();

      requireOrgId(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(next).not.toHaveBeenCalled();
    });

    it("allows requests with valid orgId", () => {
      const req = mockReq({ orgId: "org-valid-123" });
      const res = mockRes();
      const next = vi.fn();

      requireOrgId(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
    });

    it("creates audit log when org context is missing", () => {
      const req = mockReq({ orgId: null, user: { id: "user-1", email: "a@b.com" } });
      const res = mockRes();
      const next = vi.fn();

      requireOrgId(req, res, next);

      expect(storage.createAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          action: "org_context_missing",
          resourceType: "route",
        }),
      );
    });
  });

  describe("Cross-tenant data isolation", () => {
    it("prevents user from org A accessing org B alerts via header override", async () => {
      const orgA = "org-alpha";
      const orgB = "org-beta";

      (storage.getUserMemberships as any).mockResolvedValue([
        { orgId: orgA, role: "analyst", status: "active" },
      ]);

      const req = mockReq({
        user: { id: "user-orgA", email: "orgA@example.com" },
        headers: { "x-org-id": orgB },
        path: "/api/alerts",
        method: "GET",
      });
      const res = mockRes();
      const next = vi.fn();

      await resolveOrgContext(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(next).not.toHaveBeenCalled();
      expect((req as any).orgId).toBeUndefined();
    });

    it("prevents user from org A creating incidents in org B via header override", async () => {
      const orgA = "org-alpha";
      const orgB = "org-beta";

      (storage.getUserMemberships as any).mockResolvedValue([
        { orgId: orgA, role: "admin", status: "active" },
      ]);

      const req = mockReq({
        user: { id: "user-orgA", email: "orgA@example.com" },
        headers: { "x-org-id": orgB },
        path: "/api/incidents",
        method: "POST",
      });
      const res = mockRes();
      const next = vi.fn();

      await resolveOrgContext(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(next).not.toHaveBeenCalled();
    });

    it("prevents user from org A modifying org B connectors via header override", async () => {
      const orgA = "org-alpha";
      const orgB = "org-beta";

      (storage.getUserMemberships as any).mockResolvedValue([
        { orgId: orgA, role: "owner", status: "active" },
      ]);

      const req = mockReq({
        user: { id: "user-orgA", email: "orgA@example.com" },
        headers: { "x-org-id": orgB },
        path: "/api/connectors/conn-1",
        method: "PATCH",
      });
      const res = mockRes();
      const next = vi.fn();

      await resolveOrgContext(req, res, next);

      expect(res.status).toHaveBeenCalledWith(403);
      expect(next).not.toHaveBeenCalled();
    });

    it("all cross-tenant attempts generate audit logs", async () => {
      const orgA = "org-alpha";
      const orgB = "org-beta";

      (storage.getUserMemberships as any).mockResolvedValue([
        { orgId: orgA, role: "analyst", status: "active" },
      ]);

      const routes = [
        { path: "/api/alerts", method: "GET" },
        { path: "/api/incidents", method: "POST" },
        { path: "/api/connectors", method: "GET" },
        { path: "/api/api-keys", method: "POST" },
        { path: "/api/legal-holds", method: "GET" },
      ];

      for (const route of routes) {
        vi.clearAllMocks();
        (storage.getUserMemberships as any).mockResolvedValue([
          { orgId: orgA, role: "analyst", status: "active" },
        ]);

        const req = mockReq({
          user: { id: "user-orgA", email: "orgA@example.com" },
          headers: { "x-org-id": orgB },
          path: route.path,
          method: route.method,
        });
        const res = mockRes();
        const next = vi.fn();

        await resolveOrgContext(req, res, next);

        expect(res.status).toHaveBeenCalledWith(403);
        expect(storage.createAuditLog).toHaveBeenCalledWith(
          expect.objectContaining({
            action: "org_access_denied",
            resourceId: orgB,
            details: expect.objectContaining({
              route: route.path,
              method: route.method,
            }),
          }),
        );
      }
    });
  });
});
