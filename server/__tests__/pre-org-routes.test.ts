import { describe, expect, it, vi, beforeEach } from "vitest";

vi.mock("../storage", () => ({
  storage: {
    getUserMemberships: vi.fn(),
    getOrganization: vi.fn(),
    getOrgMemberships: vi.fn(),
    getPendingInvitationsByEmail: vi.fn(),
    getOrgInvitationByToken: vi.fn(),
    getOrgMembership: vi.fn(),
    createOrgMembership: vi.fn(),
    updateOrgInvitation: vi.fn(),
    createAuditLog: vi.fn().mockResolvedValue({}),
  },
}));

vi.mock("../auth", () => ({
  isAuthenticated: (_req: unknown, _res: unknown, next: () => void) => next(),
}));

vi.mock("../auth/session", () => ({
  invalidateDeserializeCache: vi.fn(),
  invalidateUserSessions: vi.fn(),
}));

vi.mock("../routes/shared", () => ({
  storage: {
    getUserMemberships: vi.fn(),
    getOrganization: vi.fn(),
    getOrgMemberships: vi.fn(),
    getPendingInvitationsByEmail: vi.fn(),
    getOrgInvitationByToken: vi.fn(),
    getOrgMembership: vi.fn(),
    createOrgMembership: vi.fn(),
    updateOrgInvitation: vi.fn(),
    createAuditLog: vi.fn().mockResolvedValue({}),
  },
  logger: { child: () => ({ error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() }) },
  p: (value: string | string[]) => (Array.isArray(value) ? value[0] : value),
  randomBytes: () => ({ toString: () => "token" }),
}));

vi.mock("../rbac", () => ({
  resolveOrgContext: (_req: unknown, _res: unknown, next: () => void) => next(),
  requireOrgId: (_req: unknown, _res: unknown, next: () => void) => next(),
  requireMinRole: () => (_req: unknown, _res: unknown, next: () => void) => next(),
  requireOrgRole: () => (_req: unknown, _res: unknown, next: () => void) => next(),
}));

vi.mock("../request-validator", () => ({
  bodySchemas: { invitationCreate: {} },
  validateBody: () => (_req: unknown, _res: unknown, next: () => void) => next(),
  validatePathId: () => (_req: unknown, _res: unknown, next: () => void) => next(),
}));

vi.mock("../s3", () => ({ uploadFile: vi.fn(), getSignedUrl: vi.fn(), deleteFile: vi.fn() }));
vi.mock("../email-service", () => ({ sendEmail: vi.fn() }));
vi.mock("../email-templates", () => ({ invitationEmail: vi.fn() }));
vi.mock("../auth/storage", () => ({ authStorage: { getUser: vi.fn() } }));
vi.mock("../logger", () => ({
  logger: { child: () => ({ error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() }) },
}));

import { storage } from "../routes/shared";
import { authStorage } from "../auth/storage";
import { registerOrgsRoutes } from "../routes/orgs";

type Handler = (req: any, res: any, next?: () => void) => Promise<unknown> | unknown;

function captureRoutes(): Map<string, Handler[]> {
  const routes = new Map<string, Handler[]>();
  const app = {
    get: (path: string, ...handlers: Handler[]) => routes.set(`GET ${path}`, handlers),
    post: (path: string, ...handlers: Handler[]) => routes.set(`POST ${path}`, handlers),
    patch: (path: string, ...handlers: Handler[]) => routes.set(`PATCH ${path}`, handlers),
    put: (path: string, ...handlers: Handler[]) => routes.set(`PUT ${path}`, handlers),
    delete: (path: string, ...handlers: Handler[]) => routes.set(`DELETE ${path}`, handlers),
  };
  registerOrgsRoutes(app as never);
  return routes;
}

function response() {
  return {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
  };
}

describe("pre-organization route authorization", () => {
  beforeEach(() => vi.clearAllMocks());

  it("does not put organization middleware in front of ensure-org or invitation acceptance", () => {
    const routes = captureRoutes();
    expect(routes.get("POST /api/auth/ensure-org")).toHaveLength(2);
    expect(routes.get("POST /api/invitations/accept")).toHaveLength(2);
  });

  it("allows an authenticated user with no memberships to accept a matching invitation", async () => {
    const routes = captureRoutes();
    const handlers = routes.get("POST /api/invitations/accept");
    expect(handlers).toBeDefined();

    (storage.getOrgInvitationByToken as any).mockResolvedValue({
      id: "invite-1",
      orgId: "org-1",
      email: "invitee@example.com",
      role: "owner",
      acceptedAt: null,
      expiresAt: new Date(Date.now() + 3600000),
    });
    (storage.getOrgMembership as any).mockResolvedValue(undefined);
    (storage.createOrgMembership as any).mockResolvedValue({
      id: "membership-1",
      orgId: "org-1",
      userId: "user-1",
      role: "owner",
    });
    (storage.getOrganization as any).mockResolvedValue({ id: "org-1", name: "Tenant One" });

    const res = response();
    await handlers![1]({ user: { id: "user-1", email: "INVITEE@example.com" }, body: { token: "token-1" } }, res);

    expect(storage.createOrgMembership).toHaveBeenCalledWith(
      expect.objectContaining({ orgId: "org-1", userId: "user-1", role: "owner", status: "active" }),
    );
    expect(storage.updateOrgInvitation).toHaveBeenCalledWith("invite-1", { acceptedAt: expect.any(Date) });
    expect(storage.createAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({ action: "invitation_accepted", resourceId: "membership-1" }),
    );
    expect(res.status).not.toHaveBeenCalledWith(403);
  });

  it("rejects invitation acceptance when the token email differs from the caller", async () => {
    const routes = captureRoutes();
    const handlers = routes.get("POST /api/invitations/accept");
    (storage.getOrgInvitationByToken as any).mockResolvedValue({
      id: "invite-1",
      orgId: "org-1",
      email: "intended@example.com",
      role: "owner",
      acceptedAt: null,
      expiresAt: new Date(Date.now() + 3600000),
    });

    const res = response();
    await handlers![1]({ user: { id: "user-1", email: "attacker@example.com" }, body: { token: "token-1" } }, res);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(storage.createOrgMembership).not.toHaveBeenCalled();
    expect(storage.createAuditLog).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "invitation_accept_denied",
        details: expect.objectContaining({ reason: "email_mismatch" }),
      }),
    );
  });

  it("keeps peer member listings limited to identity fields", async () => {
    const routes = captureRoutes();
    const handlers = routes.get("GET /api/orgs/:orgId/members");
    expect(handlers).toBeDefined();

    (storage.getOrgMemberships as any).mockResolvedValue([
      {
        id: "membership-1",
        orgId: "org-1",
        userId: "user-1",
        role: "analyst",
        status: "active",
      },
    ]);
    (authStorage.getUser as any).mockResolvedValue({
      id: "user-1",
      email: "member@example.com",
      firstName: "Member",
      lastName: "User",
      isSuperAdmin: true,
      lastLoginAt: new Date(),
      passwordChangeRequired: true,
      mfaEnabled: true,
      mfaVerifiedAt: new Date(),
      passwordHash: "password-hash",
      mfaSecret: "totp-secret",
      failedLoginCount: 4,
      lockedUntil: new Date(),
    });

    const res = response();
    await handlers![3]({ params: { orgId: "org-1" }, orgId: "org-1" }, res);

    expect(res.json).toHaveBeenCalledWith([
      {
        id: "membership-1",
        orgId: "org-1",
        userId: "user-1",
        role: "analyst",
        status: "active",
        user: {
          firstName: "Member",
          lastName: "User",
          email: "member@example.com",
        },
        email: "member@example.com",
      },
    ]);
    const member = res.json.mock.calls[0][0][0].user;
    expect(member).not.toHaveProperty("isSuperAdmin");
    expect(member).not.toHaveProperty("lastLoginAt");
    expect(member).not.toHaveProperty("passwordChangeRequired");
    expect(member).not.toHaveProperty("mfaEnabled");
    expect(member).not.toHaveProperty("mfaVerifiedAt");
    expect(member).not.toHaveProperty("hasLocalPassword");
  });
});
