/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type passport from "passport";

// Mock dependencies before imports
vi.mock("../auth/storage", () => ({
  authStorage: {
    getUserByEmail: vi.fn(),
    upsertUser: vi.fn(),
    getUser: vi.fn(),
  },
}));

vi.mock("../storage", () => ({
  storage: {
    getUserMemberships: vi.fn().mockResolvedValue([]),
    getPendingInvitationsByEmail: vi.fn(),
    createAuditLog: vi.fn().mockResolvedValue({}),
  },
}));

vi.mock("../bootstrap-super-admin", () => ({
  checkAndPromoteSuperAdmin: vi.fn().mockResolvedValue(false),
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

vi.mock("../config", () => ({
  config: {
    databaseUrl: "postgresql://localhost/test",
    nodeEnv: "test",
    session: { secret: "test-secret" },
    oauth: {
      google: {
        clientId: "google-id",
        clientSecret: "google-secret",
        callbackUrl: "/api/auth/google/callback",
      },
      github: {
        clientId: "github-id",
        clientSecret: "github-secret",
        callbackUrl: "/api/auth/github/callback",
      },
    },
  },
}));

vi.mock("../db", () => ({
  db: {},
  pool: { query: vi.fn() },
}));

vi.mock("connect-pg-simple", () => ({
  default: () =>
    class MockPgStore {
      constructor() {}
    },
}));

vi.mock("express-session", () => {
  const sessionFn = (_opts: any) => (_req: any, _res: any, next: any) => next();
  sessionFn.Store = class {};
  return { default: sessionFn };
});

import { authStorage } from "../auth/storage";
import { storage } from "../storage";
import { checkAndPromoteSuperAdmin } from "../bootstrap-super-admin";
import { googleVerifyCallback, githubVerifyCallback, resolveCallbackUrl, getSession } from "../auth/session";

// Helper to create a mock passport profile
function makeGoogleProfile(overrides: Partial<passport.Profile> = {}): passport.Profile {
  return {
    provider: "google",
    id: "google-123",
    displayName: "John Doe",
    name: { givenName: "John", familyName: "Doe" },
    emails: [{ value: "john@example.com" }],
    photos: [{ value: "https://example.com/photo.jpg" }],
    ...overrides,
  } as passport.Profile;
}

function makeGitHubProfile(overrides: Partial<passport.Profile> = {}): passport.Profile {
  return {
    provider: "github",
    id: "gh-456",
    displayName: "Jane Smith",
    username: "janesmith",
    emails: [{ value: "jane@example.com", primary: true, verified: true } as any],
    photos: [{ value: "https://github.com/avatar.jpg" }],
    ...overrides,
  } as passport.Profile;
}

function makeMockUser(overrides: Record<string, any> = {}) {
  return {
    id: "user-1",
    email: "john@example.com",
    firstName: "John",
    lastName: "Doe",
    role: "analyst",
    isSuperAdmin: false,
    disabledAt: null,
    profileImageUrl: null,
    ...overrides,
  };
}

describe("OAuth Flows", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (storage.getPendingInvitationsByEmail as any).mockImplementation(async (email: string) => [
      { id: "invite-1", email, acceptedAt: null, expiresAt: new Date(Date.now() + 3600000) },
    ]);
  });

  describe("Google verify callback", () => {
    it("creates user when email exists in profile and user is new", async () => {
      const newUser = makeMockUser();
      (authStorage.getUserByEmail as any).mockResolvedValue(undefined);
      (authStorage.upsertUser as any).mockResolvedValue(newUser);

      const done = vi.fn();
      const profile = makeGoogleProfile();

      await googleVerifyCallback("token", "refresh", profile, done);

      expect(authStorage.getUserByEmail).toHaveBeenCalledWith("john@example.com");
      expect(authStorage.upsertUser).toHaveBeenCalledWith({
        email: "john@example.com",
        firstName: "John",
        lastName: "Doe",
        profileImageUrl: "https://example.com/photo.jpg",
      });
      expect(done).toHaveBeenCalledWith(null, newUser);
    });

    it("returns existing user when email matches", async () => {
      const existingUser = makeMockUser({ passwordHash: "existing-local-password-hash" });
      (authStorage.getUserByEmail as any).mockResolvedValue(existingUser);

      const done = vi.fn();
      const profile = makeGoogleProfile();

      await googleVerifyCallback("token", "refresh", profile, done);

      expect(authStorage.upsertUser).not.toHaveBeenCalled();
      expect(done).toHaveBeenCalledWith(null, existingUser);
    });

    it("rejects an uninvited new OAuth email and audits the attempt", async () => {
      (authStorage.getUserByEmail as any).mockResolvedValue(undefined);
      (storage.getPendingInvitationsByEmail as any).mockResolvedValue([]);
      const done = vi.fn();

      await googleVerifyCallback("token", "refresh", makeGoogleProfile(), done);

      expect(authStorage.upsertUser).not.toHaveBeenCalled();
      expect(done).toHaveBeenCalledWith(null, false, {
        message: "Access is by invitation only. Please contact your platform administrator.",
      });
      expect(storage.createAuditLog).toHaveBeenCalledWith(
        expect.objectContaining({
          action: "oauth_login_rejected",
          details: expect.objectContaining({ provider: "google", reason: "invitation_required" }),
        }),
      );
    });

    it("bootstraps the configured platform super-admin with no users", async () => {
      const superAdmin = makeMockUser({ email: "prathamesh@aricatech.com", isSuperAdmin: true });
      (authStorage.getUserByEmail as any).mockResolvedValue(undefined);
      (authStorage.upsertUser as any).mockResolvedValue(superAdmin);
      const done = vi.fn();

      await googleVerifyCallback(
        "token",
        "refresh",
        makeGoogleProfile({ emails: [{ value: "PRATHAMESH@ARICATECH.COM" }] }),
        done,
      );

      expect(authStorage.upsertUser).toHaveBeenCalledWith(
        expect.objectContaining({ email: "prathamesh@aricatech.com" }),
      );
      expect(done).toHaveBeenCalledWith(null, superAdmin);
    });

    it("rejects when no email in profile (emails undefined)", async () => {
      const done = vi.fn();
      const profile = makeGoogleProfile({ emails: undefined });

      await googleVerifyCallback("token", "refresh", profile, done);

      expect(done).toHaveBeenCalledWith(null, false, { message: "No email from Google" });
    });

    it("rejects when no email in profile (emails array empty)", async () => {
      const done = vi.fn();
      const profile = makeGoogleProfile({ emails: [] });

      await googleVerifyCallback("token", "refresh", profile, done);

      expect(done).toHaveBeenCalledWith(null, false, { message: "No email from Google" });
    });

    it("rejects when account is disabled", async () => {
      const disabledUser = makeMockUser({ disabledAt: new Date() });
      (authStorage.getUserByEmail as any).mockResolvedValue(disabledUser);

      const done = vi.fn();
      const profile = makeGoogleProfile();

      await googleVerifyCallback("token", "refresh", profile, done);

      expect(done).toHaveBeenCalledWith(null, false, { message: "Account is disabled" });
    });

    it("extracts firstName/lastName from profile.name", async () => {
      const newUser = makeMockUser({ firstName: "Alice", lastName: "Wonderland" });
      (authStorage.getUserByEmail as any).mockResolvedValue(undefined);
      (authStorage.upsertUser as any).mockResolvedValue(newUser);

      const done = vi.fn();
      const profile = makeGoogleProfile({
        name: { givenName: "Alice", familyName: "Wonderland" },
      });

      await googleVerifyCallback("token", "refresh", profile, done);

      expect(authStorage.upsertUser).toHaveBeenCalledWith(
        expect.objectContaining({
          firstName: "Alice",
          lastName: "Wonderland",
        }),
      );
    });

    it("handles null profile.name gracefully", async () => {
      const newUser = makeMockUser({ firstName: null, lastName: null });
      (authStorage.getUserByEmail as any).mockResolvedValue(undefined);
      (authStorage.upsertUser as any).mockResolvedValue(newUser);

      const done = vi.fn();
      const profile = makeGoogleProfile({ name: undefined });

      await googleVerifyCallback("token", "refresh", profile, done);

      expect(authStorage.upsertUser).toHaveBeenCalledWith(
        expect.objectContaining({
          firstName: null,
          lastName: null,
        }),
      );
    });

    it("extracts profileImageUrl from profile.photos[0].value", async () => {
      const newUser = makeMockUser();
      (authStorage.getUserByEmail as any).mockResolvedValue(undefined);
      (authStorage.upsertUser as any).mockResolvedValue(newUser);

      const done = vi.fn();
      const profile = makeGoogleProfile({
        photos: [{ value: "https://img.example.com/pic.png" }],
      });

      await googleVerifyCallback("token", "refresh", profile, done);

      expect(authStorage.upsertUser).toHaveBeenCalledWith(
        expect.objectContaining({
          profileImageUrl: "https://img.example.com/pic.png",
        }),
      );
    });

    it("triggers super-admin promotion check on login", async () => {
      const user = makeMockUser({ isSuperAdmin: false, email: "admin@example.com" });
      (authStorage.getUserByEmail as any).mockResolvedValue(user);
      (checkAndPromoteSuperAdmin as any).mockResolvedValue(true);

      const done = vi.fn();
      const profile = makeGoogleProfile({ emails: [{ value: "admin@example.com" }] });

      await googleVerifyCallback("token", "refresh", profile, done);

      expect(checkAndPromoteSuperAdmin).toHaveBeenCalledWith(user.id, user.email);
      const returnedUser = done.mock.calls[0][1];
      expect(returnedUser.isSuperAdmin).toBe(true);
    });
  });

  describe("GitHub verify callback", () => {
    it("finds verified primary email from profile.emails array", async () => {
      const newUser = makeMockUser({ email: "jane@example.com" });
      (authStorage.getUserByEmail as any).mockResolvedValue(undefined);
      (authStorage.upsertUser as any).mockResolvedValue(newUser);

      const done = vi.fn();
      const profile = makeGitHubProfile({
        emails: [
          { value: "secondary@example.com", primary: false, verified: true } as any,
          { value: "jane@example.com", primary: true, verified: true } as any,
        ],
      });

      await githubVerifyCallback("token", "refresh", profile, done);

      expect(authStorage.getUserByEmail).toHaveBeenCalledWith("jane@example.com");
    });

    it("rejects when no verified primary email exists", async () => {
      const done = vi.fn();
      const profile = makeGitHubProfile({
        emails: [
          { value: "unverified@example.com", primary: true, verified: false } as any,
          { value: "notprimary@example.com", primary: false, verified: true } as any,
        ],
      });

      await githubVerifyCallback("token", "refresh", profile, done);

      expect(done).toHaveBeenCalledWith(null, false, {
        message: "No verified primary email from GitHub",
      });
    });

    it("rejects when profile.emails is empty", async () => {
      const done = vi.fn();
      const profile = makeGitHubProfile({ emails: [] });

      await githubVerifyCallback("token", "refresh", profile, done);

      expect(done).toHaveBeenCalledWith(null, false, {
        message: "No verified primary email from GitHub",
      });
    });

    it("splits displayName into firstName/lastName", async () => {
      const newUser = makeMockUser();
      (authStorage.getUserByEmail as any).mockResolvedValue(undefined);
      (authStorage.upsertUser as any).mockResolvedValue(newUser);

      const done = vi.fn();
      const profile = makeGitHubProfile({ displayName: "Jane Smith" });

      await githubVerifyCallback("token", "refresh", profile, done);

      expect(authStorage.upsertUser).toHaveBeenCalledWith(
        expect.objectContaining({
          firstName: "Jane",
          lastName: "Smith",
        }),
      );
    });

    it("handles single-word displayName (firstName only, empty lastName)", async () => {
      const newUser = makeMockUser();
      (authStorage.getUserByEmail as any).mockResolvedValue(undefined);
      (authStorage.upsertUser as any).mockResolvedValue(newUser);

      const done = vi.fn();
      const profile = makeGitHubProfile({ displayName: "Mononym" });

      await githubVerifyCallback("token", "refresh", profile, done);

      expect(authStorage.upsertUser).toHaveBeenCalledWith(
        expect.objectContaining({
          firstName: "Mononym",
          lastName: null,
        }),
      );
    });

    it("handles null displayName, falls back to username", async () => {
      const newUser = makeMockUser();
      (authStorage.getUserByEmail as any).mockResolvedValue(undefined);
      (authStorage.upsertUser as any).mockResolvedValue(newUser);

      const done = vi.fn();
      const profile = makeGitHubProfile({
        displayName: undefined as any,
        username: "janeuser",
      });

      await githubVerifyCallback("token", "refresh", profile, done);

      expect(authStorage.upsertUser).toHaveBeenCalledWith(
        expect.objectContaining({
          firstName: "janeuser",
          lastName: null,
        }),
      );
    });

    it("rejects disabled account", async () => {
      const disabledUser = makeMockUser({ disabledAt: new Date() });
      (authStorage.getUserByEmail as any).mockResolvedValue(disabledUser);

      const done = vi.fn();
      const profile = makeGitHubProfile();

      await githubVerifyCallback("token", "refresh", profile, done);

      expect(done).toHaveBeenCalledWith(null, false, { message: "Account is disabled" });
    });

    it("handles multi-part displayName (three words)", async () => {
      const newUser = makeMockUser();
      (authStorage.getUserByEmail as any).mockResolvedValue(undefined);
      (authStorage.upsertUser as any).mockResolvedValue(newUser);

      const done = vi.fn();
      const profile = makeGitHubProfile({ displayName: "Mary Jane Watson" });

      await githubVerifyCallback("token", "refresh", profile, done);

      expect(authStorage.upsertUser).toHaveBeenCalledWith(
        expect.objectContaining({
          firstName: "Mary",
          lastName: "Jane Watson",
        }),
      );
    });
  });

  describe("Session configuration", () => {
    it("getSession returns a function (middleware)", () => {
      const middleware = getSession();
      expect(typeof middleware).toBe("function");
    });
  });

  describe("resolveCallbackUrl", () => {
    const originalEnv = process.env.APP_BASE_URL;

    afterEach(() => {
      if (originalEnv === undefined) {
        delete process.env.APP_BASE_URL;
      } else {
        process.env.APP_BASE_URL = originalEnv;
      }
    });

    it("prefixes relative paths with APP_BASE_URL when set", () => {
      process.env.APP_BASE_URL = "https://app.example.com";
      const result = resolveCallbackUrl("/api/auth/google/callback");
      expect(result).toBe("https://app.example.com/api/auth/google/callback");
    });

    it("strips trailing slashes from APP_BASE_URL before concatenating", () => {
      process.env.APP_BASE_URL = "https://app.example.com///";
      const result = resolveCallbackUrl("/api/auth/callback");
      expect(result).toBe("https://app.example.com/api/auth/callback");
    });

    it("returns absolute URLs unchanged", () => {
      process.env.APP_BASE_URL = "https://app.example.com";
      const result = resolveCallbackUrl("https://other.example.com/callback");
      expect(result).toBe("https://other.example.com/callback");
    });

    it("returns relative path unchanged when APP_BASE_URL is not set", () => {
      delete process.env.APP_BASE_URL;
      const result = resolveCallbackUrl("/api/auth/callback");
      expect(result).toBe("/api/auth/callback");
    });
  });
});
