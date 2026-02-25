import type { Express } from "express";
import passport from "passport";
import { authStorage } from "./storage";
import { isAuthenticated, hashPassword } from "./session";
import { storage } from "../storage";

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
        return res.status(404).json({ message: "User not found" });
      }
      const { passwordHash, ...safeUser } = user;
      res.json(safeUser);
    } catch (error) {
      console.error("Error fetching user:", error);
      res.status(500).json({ message: "Failed to fetch user" });
    }
  });

  app.post("/api/register", async (req, res, next) => {
    try {
      const { email, password, firstName, lastName } = req.body;
      if (!email || !password) {
        return res.status(400).json({ message: "Email and password are required" });
      }

      const existing = await authStorage.getUserByEmail(email);
      if (existing) {
        return res.status(409).json({ message: "An account with this email already exists" });
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
        res.status(201).json(safeUser);
      });
    } catch (error) {
      console.error("Error registering user:", error);
      res.status(500).json({ message: "Registration failed" });
    }
  });

  app.post("/api/login", (req, res, next) => {
    passport.authenticate(
      "local",
      (err: any, user: any, info: any) => {
        if (err) return next(err);
        if (!user) {
          return res.status(401).json({ message: info?.message || "Invalid credentials" });
        }
        req.login(user, async (loginErr) => {
          if (loginErr) return next(loginErr);
          await ensureOrgMembership(user);
          const { passwordHash, ...safeUser } = user;
          res.json(safeUser);
        });
      }
    )(req, res, next);
  });

  app.post("/api/logout", (req, res) => {
    req.logout(() => {
      req.session.destroy(() => {
        res.json({ message: "Logged out" });
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
      return res.status(501).json({ message: "Google login not configured" });
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
      return res.status(501).json({ message: "GitHub login not configured" });
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
    res.json({
      email: true,
      google: !!process.env.GOOGLE_CLIENT_ID,
      github: !!process.env.GITHUB_CLIENT_ID,
      cognitoUserPoolId: process.env.COGNITO_USER_POOL_ID || null,
    });
  });
}
