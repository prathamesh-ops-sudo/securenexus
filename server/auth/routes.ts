import type { Express } from "express";
import passport from "passport";
import { authStorage } from "./storage";
import { isAuthenticated, hashPassword } from "./session";
import { storage } from "../storage";
import {
  reply,
  replyUnauthenticated,
  replyNotFound,
  replyConflict,
  replyValidation,
  replyInternal,
  replyNotImplemented,
  ERROR_CODES,
} from "../api-response";

async function ensureOrgMembership(user: any) {
  try {
    const memberships = await storage.getUserMemberships(user.id);
    if (memberships.length > 0) return;

    const orgs = await storage.getOrganizations();
    if (orgs.length > 0) {
      await storage.createOrgMembership({
        orgId: orgs[0].id,
        userId: user.id,
        role: "owner",
        status: "active",
        joinedAt: new Date(),
      });
      return;
    }

    const newOrg = await storage.createOrganization({
      name: `${user.email ? user.email.split("@")[0] : "User"}'s Organization`,
      slug: `org-${Date.now()}`,
      contactEmail: user.email || undefined,
    });
    await storage.createOrgMembership({
      orgId: newOrg.id,
      userId: user.id,
      role: "owner",
      status: "active",
      joinedAt: new Date(),
    });
  } catch (err) {
    console.error("Error ensuring org membership:", err);
  }
}

export function registerAuthRoutes(app: Express): void {
  app.get("/api/auth/user", isAuthenticated, async (req: any, res) => {
    try {
      const user = await authStorage.getUser(req.user.id);
      if (!user) {
        return replyNotFound(res, "User not found");
      }
      const { passwordHash, ...safeUser } = user;
      return reply(res, safeUser);
    } catch (error) {
      console.error("Error fetching user:", error);
      return replyInternal(res, "Failed to fetch user");
    }
  });

  app.post("/api/register", async (req, res, next) => {
    try {
      const { email, password, firstName, lastName } = req.body;
      if (!email || !password) {
        return replyValidation(res, [
          { message: "Email and password are required", field: !email ? "email" : "password" },
        ]);
      }

      const existing = await authStorage.getUserByEmail(email);
      if (existing) {
        return replyConflict(res, "An account with this email already exists");
      }

      const hashedPw = await hashPassword(password);
      const user = await authStorage.upsertUser({
        email,
        passwordHash: hashedPw,
        firstName: firstName || null,
        lastName: lastName || null,
      });

      req.login(user, async (err) => {
        if (err) return next(err);
        await ensureOrgMembership(user);
        const { passwordHash: _, ...safeUser } = user;
        return reply(res, safeUser, {}, 201);
      });
    } catch (error) {
      console.error("Error registering user:", error);
      return replyInternal(res, "Registration failed");
    }
  });

  app.post("/api/login", (req, res, next) => {
    passport.authenticate(
      "local",
      (err: any, user: any, info: any) => {
        if (err) return next(err);
        if (!user) {
          return replyUnauthenticated(res, info?.message || "Invalid credentials");
        }
        req.login(user, async (loginErr) => {
          if (loginErr) return next(loginErr);
          await ensureOrgMembership(user);
          const { passwordHash, ...safeUser } = user;
          return reply(res, safeUser);
        });
      }
    )(req, res, next);
  });

  app.post("/api/logout", (req, res) => {
    req.logout(() => {
      req.session.destroy(() => {
        return reply(res, { message: "Logged out" });
      });
    });
  });

  app.get("/api/logout", (req, res) => {
    req.logout(() => {
      req.session.destroy(() => {
        res.redirect("/");
      });
    });
  });

  app.get("/api/auth/google", (req, res, next) => {
    if (!process.env.GOOGLE_CLIENT_ID) {
      return replyNotImplemented(res, "Google login not configured");
    }
    passport.authenticate("google", { scope: ["profile", "email"] })(req, res, next);
  });

  app.get("/api/auth/google/callback",
    (req, res, next) => {
      passport.authenticate("google", { failureRedirect: "/?error=google_auth_failed" })(req, res, next);
    },
    async (req: any, res) => {
      if (req.user) await ensureOrgMembership(req.user);
      res.redirect("/");
    }
  );

  app.get("/api/auth/github", (req, res, next) => {
    if (!process.env.GITHUB_CLIENT_ID) {
      return replyNotImplemented(res, "GitHub login not configured");
    }
    passport.authenticate("github", { scope: ["user:email"] })(req, res, next);
  });

  app.get("/api/auth/github/callback",
    (req, res, next) => {
      passport.authenticate("github", { failureRedirect: "/?error=github_auth_failed" })(req, res, next);
    },
    async (req: any, res) => {
      if (req.user) await ensureOrgMembership(req.user);
      res.redirect("/");
    }
  );

  app.get("/api/auth/providers", (_req, res) => {
    return reply(res, {
      email: true,
      google: !!process.env.GOOGLE_CLIENT_ID,
      github: !!process.env.GITHUB_CLIENT_ID,
      cognitoUserPoolId: process.env.COGNITO_USER_POOL_ID || null,
    });
  });
}
