import type { Express, Request, Response, NextFunction } from "express";
import passport from "passport";
import { authStorage } from "./storage";
import { isAuthenticated, hashPassword, invalidateDeserializeCache, type SessionUser } from "./session";
import { checkAndPromoteSuperAdmin } from "../bootstrap-super-admin";
import { storage } from "../storage";
import { config } from "../config";
import {
  reply,
  replyUnauthenticated,
  replyForbidden,
  replyNotFound,
  replyConflict,
  replyValidation,
  replyInternal,
  replyNotImplemented,
  ERROR_CODES,
} from "../api-response";
import { logger } from "../logger";
import { sendEmail } from "../email-service";
import { welcomeEmail } from "../email-templates";
import {
  loginRateLimitPre,
  recordFailedLogin,
  clearLoginBuckets,
  clearLockout,
  registerRateLimit,
} from "../middleware/auth-rate-limit";
import {
  checkLoginPolicy,
  enforceMaxConcurrentSessions,
  validatePasswordComplexity,
} from "../middleware/security-policy-enforcement";

const log = logger.child("auth-routes");

async function ensureOrgMembership(user: SessionUser): Promise<boolean> {
  try {
    const memberships = await storage.getUserMemberships(user.id);
    if (memberships.length > 0) return true;

    // 1. Check pending invitations — join the invited org instead of creating a new one
    if (user.email) {
      const pendingInvitations = await storage.getPendingInvitationsByEmail(user.email.toLowerCase()).catch(() => []);
      const now = new Date();
      const validInvitation = pendingInvitations.find((inv) => new Date(inv.expiresAt) > now);
      if (validInvitation) {
        await storage.createOrgMembership({
          orgId: validInvitation.orgId,
          userId: user.id,
          role: validInvitation.role,
          status: "active",
          joinedAt: new Date(),
        });
        await storage.updateOrgInvitation(validInvitation.id, { acceptedAt: new Date() });
        storage
          .createAuditLog({
            userId: user.id,
            userName: user.email,
            action: "invitation_auto_accepted",
            resourceType: "membership",
            resourceId: user.id,
            details: {
              orgId: validInvitation.orgId,
              role: validInvitation.role,
              invitationId: validInvitation.id,
            },
          })
          .catch((err) => log.warn("Failed to record invitation audit", { error: String(err), userId: user.id }));
        logger.child("auth").info("User auto-joined org via pending invitation", {
          userId: user.id,
          email: user.email,
          orgId: validInvitation.orgId,
          role: validInvitation.role,
        });
        return true;
      }
    }

    // 2. Check domain auto-join
    if (user.email) {
      const emailDomain = user.email.split("@")[1]?.toLowerCase();
      if (emailDomain) {
        const domainMatch = await storage.getVerifiedAutoJoinDomain(emailDomain);
        if (domainMatch) {
          const org = await storage.getOrganization(domainMatch.orgId);
          const resolvedRole = domainMatch.defaultRole || org?.defaultMemberRole || "analyst";
          const needsApproval = org?.requireApproval ?? false;

          await storage.createOrgMembership({
            orgId: domainMatch.orgId,
            userId: user.id,
            role: resolvedRole,
            status: needsApproval ? "pending" : "active",
            joinedAt: needsApproval ? undefined : new Date(),
          });
          storage
            .createAuditLog({
              userId: user.id,
              userName: user.email,
              action: needsApproval ? "domain_auto_join_pending_approval" : "domain_auto_join",
              resourceType: "membership",
              resourceId: user.id,
              details: {
                domain: emailDomain,
                orgId: domainMatch.orgId,
                role: resolvedRole,
                pendingApproval: needsApproval,
              },
            })
            .catch((err) =>
              log.warn("Failed to record domain auto-join audit", { error: String(err), userId: user.id }),
            );
          logger
            .child("auth")
            .info(needsApproval ? "User pending approval via domain match" : "User auto-joined org via domain match", {
              userId: user.id,
              email: user.email,
              domain: emailDomain,
              orgId: domainMatch.orgId,
              pendingApproval: needsApproval,
            });
          return true;
        }
      }
    }

    // 3. No invitation, no domain match — user must go through onboarding wizard.
    //    Do NOT auto-create a new org. The frontend /ensure-org endpoint returns
    //    { needsOnboarding: true } and the onboarding wizard handles org creation.
    logger.child("auth").info("User has no org membership and no invitation — needs onboarding", {
      userId: user.id,
      email: user.email,
    });
    return false;
  } catch (err) {
    logger.child("auth").error("Failed to ensure org membership — user may lack org context", {
      userId: user.id,
      email: user.email,
      error: String(err),
    });
    storage
      .createAuditLog({
        userId: user.id,
        userName: user.email || "unknown",
        action: "org_membership_provision_failed",
        resourceType: "user",
        resourceId: user.id,
        details: { error: String(err) },
      })
      .catch((auditErr) =>
        logger.child("auth").warn("Failed to audit org membership failure", { error: String(auditErr) }),
      );
    return false;
  }
}

export function registerAuthRoutes(app: Express): void {
  const oauthCallback =
    (provider: "google" | "github", failureCode: string) =>
    (req: Request, res: Response, next: NextFunction): void => {
      passport.authenticate(provider, (err: Error | null, user: Express.User | false, info?: { message?: string }) => {
        if (err) return next(err);
        if (!user) {
          const code = info?.message?.startsWith("Access is by invitation only")
            ? "oauth_invitation_required"
            : failureCode;
          return res.redirect(`/?error=${code}`);
        }
        return req.logIn(user, (loginErr) => {
          if (loginErr) return next(loginErr);
          next();
        });
      })(req, res, next);
    };

  app.get("/api/auth/user", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const reqUser = req.user as SessionUser;
      const user = await authStorage.getUser(reqUser.id);
      if (!user) {
        return replyNotFound(res, "User not found");
      }
      // Belt-and-suspenders: auto-promote super-admin on every user fetch
      // so the panel appears immediately without requiring re-login
      if (!user.isSuperAdmin && user.email) {
        const promoted = await checkAndPromoteSuperAdmin(user.id, user.email);
        if (promoted) {
          user.isSuperAdmin = true;
          invalidateDeserializeCache(user.id);
        }
      }
      const { passwordHash, ...safeUser } = user;
      return reply(res, {
        ...safeUser,
        orgId: reqUser.orgId ?? null,
        role: reqUser.orgRole ?? null,
      });
    } catch (error) {
      logger.child("routes").error("Error fetching user", { error: String(error) });
      return replyInternal(res, "Failed to fetch user");
    }
  });

  // Self-service registration is disabled.
  // Only platform admins can create user accounts via the admin panel.
  app.post("/api/register", registerRateLimit, async (_req, res) => {
    return replyForbidden(
      res,
      "Registration is disabled. Please contact your platform administrator to get access.",
      "REGISTRATION_DISABLED",
    );
  });

  app.post("/api/login", loginRateLimitPre, (req, res, next) => {
    passport.authenticate(
      "local",
      (err: Error | null, user: SessionUser | false, info: { message: string } | undefined) => {
        if (err) return next(err);
        if (!user) {
          recordFailedLogin(req);
          const failEmail = req.body?.email?.toLowerCase?.();
          const failIp = (() => {
            const fwd = req.headers["x-forwarded-for"];
            if (typeof fwd === "string") return fwd.split(",")[0].trim();
            return req.socket.remoteAddress || "unknown";
          })();
          if (failEmail) {
            storage
              .createAuditLog({
                userId: undefined,
                userName: failEmail,
                action: "login_failed",
                resourceType: "auth",
                resourceId: failEmail,
                details: { ip: failIp, reason: info?.message || "invalid_credentials" },
                ipAddress: failIp,
              })
              .catch((err) =>
                log.warn("Failed to record login failure audit", { error: String(err), email: failEmail }),
              );
          }
          return replyUnauthenticated(res, info?.message || "Invalid credentials");
        }
        clearLoginBuckets(user.email!);
        clearLockout(user.email!).catch((err) =>
          log.warn("Failed to clear lockout", { error: String(err), email: user.email }),
        );
        req.login(user, async (loginErr) => {
          if (loginErr) return next(loginErr);
          await ensureOrgMembership(user);

          const memberships = await storage.getUserMemberships(user.id).catch(() => []);
          const userOrgId = memberships.length > 0 ? memberships[0].orgId : null;

          const clientIp = (() => {
            const fwd = req.headers["x-forwarded-for"];
            if (typeof fwd === "string") return fwd.split(",")[0].trim();
            return req.socket.remoteAddress || "unknown";
          })();

          const policyResult = await checkLoginPolicy(user, userOrgId, clientIp);
          if (!policyResult.allowed) {
            req.logout(() => {
              req.session.destroy(() => {
                return replyForbidden(res, policyResult.reason || "Access denied", policyResult.code || "FORBIDDEN");
              });
            });
            return;
          }

          if (userOrgId) {
            await enforceMaxConcurrentSessions(user.id, userOrgId);
          }

          const { passwordHash, ...safeUser } = user;
          return reply(res, {
            ...safeUser,
            mfaRequired: policyResult.mfaRequired || false,
            passwordExpired: policyResult.passwordExpired || false,
          });
        });
      },
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
    if (!config.oauth.google.clientId) {
      return replyNotImplemented(res, "Google login not configured");
    }
    passport.authenticate("google", { scope: ["profile", "email"] })(req, res, next);
  });

  app.get(
    "/api/auth/google/callback",
    oauthCallback("google", "google_auth_failed"),
    async (req: Request, res: Response) => {
      try {
        const reqUser = req.user as SessionUser | undefined;
        if (reqUser) {
          await ensureOrgMembership(reqUser);

          const oauthMemberships = await storage.getUserMemberships(reqUser.id).catch(() => []);
          const oauthOrgId = oauthMemberships.length > 0 ? oauthMemberships[0].orgId : null;
          const oauthIp = (() => {
            const fwd = req.headers["x-forwarded-for"];
            if (typeof fwd === "string") return fwd.split(",")[0].trim();
            return req.socket.remoteAddress || "unknown";
          })();
          const oauthPolicy = await checkLoginPolicy(reqUser, oauthOrgId, oauthIp);
          if (!oauthPolicy.allowed) {
            req.logout(() => {
              req.session.destroy(() => {
                return res.redirect("/?error=ip_not_allowed");
              });
            });
            return;
          }
          if (oauthOrgId) {
            await enforceMaxConcurrentSessions(reqUser.id, oauthOrgId);
          }
        }
        res.redirect("/");
      } catch (err) {
        logger.child("auth").error("Google OAuth callback error", {
          error: String(err),
          userId: (req.user as SessionUser | undefined)?.id,
          email: (req.user as SessionUser | undefined)?.email,
        });
        res.redirect("/?error=google_auth_failed");
      }
    },
  );

  app.get("/api/auth/github", (req, res, next) => {
    if (!config.oauth.github.clientId) {
      return replyNotImplemented(res, "GitHub login not configured");
    }
    passport.authenticate("github", { scope: ["user:email"] })(req, res, next);
  });

  app.get(
    "/api/auth/github/callback",
    oauthCallback("github", "github_auth_failed"),
    async (req: Request, res: Response) => {
      try {
        const reqUser = req.user as SessionUser | undefined;
        if (reqUser) {
          await ensureOrgMembership(reqUser);

          const ghMemberships = await storage.getUserMemberships(reqUser.id).catch(() => []);
          const ghOrgId = ghMemberships.length > 0 ? ghMemberships[0].orgId : null;
          const ghIp = (() => {
            const fwd = req.headers["x-forwarded-for"];
            if (typeof fwd === "string") return fwd.split(",")[0].trim();
            return req.socket.remoteAddress || "unknown";
          })();
          const ghPolicy = await checkLoginPolicy(reqUser, ghOrgId, ghIp);
          if (!ghPolicy.allowed) {
            req.logout(() => {
              req.session.destroy(() => {
                return res.redirect("/?error=ip_not_allowed");
              });
            });
            return;
          }
          if (ghOrgId) {
            await enforceMaxConcurrentSessions(reqUser.id, ghOrgId);
          }
        }
        res.redirect("/");
      } catch (err) {
        logger.child("auth").error("GitHub OAuth callback error", {
          error: String(err),
          userId: (req.user as SessionUser | undefined)?.id,
          email: (req.user as SessionUser | undefined)?.email,
        });
        res.redirect("/?error=github_auth_failed");
      }
    },
  );

  app.get("/api/auth/providers", (_req, res) => {
    return reply(res, {
      email: true,
      google: !!config.oauth.google.clientId,
      github: !!config.oauth.github.clientId,
      cognitoUserPoolId: config.oauth.cognitoUserPoolId || null,
    });
  });
}
