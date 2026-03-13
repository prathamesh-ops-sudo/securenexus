import type { Express } from "express";
import passport from "passport";
import { authStorage } from "./storage";
import { isAuthenticated, hashPassword } from "./session";
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

const CONSUMER_EMAIL_DOMAINS = new Set([
  "gmail.com",
  "googlemail.com",
  "yahoo.com",
  "yahoo.co.in",
  "yahoo.co.uk",
  "yahoo.co.jp",
  "yahoo.fr",
  "yahoo.de",
  "ymail.com",
  "hotmail.com",
  "hotmail.co.uk",
  "hotmail.fr",
  "hotmail.de",
  "outlook.com",
  "outlook.co.uk",
  "live.com",
  "live.co.uk",
  "msn.com",
  "icloud.com",
  "me.com",
  "mac.com",
  "aol.com",
  "protonmail.com",
  "proton.me",
  "zoho.com",
  "zohomail.com",
  "mail.com",
  "gmx.com",
  "gmx.net",
  "gmx.de",
  "yandex.com",
  "yandex.ru",
  "mail.ru",
  "inbox.com",
  "fastmail.com",
  "tutanota.com",
  "tuta.io",
  "hey.com",
  "pm.me",
  "163.com",
  "qq.com",
  "sina.com",
  "rediffmail.com",
  "cox.net",
  "sbcglobal.net",
  "att.net",
  "comcast.net",
  "verizon.net",
  "charter.net",
  "earthlink.net",
  "optonline.net",
  "rocketmail.com",
]);

function isConsumerEmailDomain(email: string): boolean {
  const domain = email.split("@")[1]?.toLowerCase();
  if (!domain) return false;
  return CONSUMER_EMAIL_DOMAINS.has(domain);
}

async function hasActiveInvitation(email: string): Promise<boolean> {
  try {
    const invitations = await storage.getPendingInvitationsByEmail(email.toLowerCase());
    const now = new Date();
    return invitations.some((inv) => new Date(inv.expiresAt) > now);
  } catch {
    return false;
  }
}

async function ensureOrgMembership(user: any): Promise<boolean> {
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
          .catch(() => {});
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
            .catch(() => {});
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
  app.get("/api/auth/user", isAuthenticated, async (req: any, res) => {
    try {
      const user = await authStorage.getUser(req.user.id);
      if (!user) {
        return replyNotFound(res, "User not found");
      }
      const { passwordHash, ...safeUser } = user;
      return reply(res, {
        ...safeUser,
        orgId: req.user.orgId ?? null,
        role: req.user.orgRole ?? null,
      });
    } catch (error) {
      logger.child("routes").error("Error fetching user", { error: String(error) });
      return replyInternal(res, "Failed to fetch user");
    }
  });

  app.post("/api/register", registerRateLimit, async (req, res, next) => {
    try {
      const { email, password, firstName, lastName } = req.body;
      if (!email || !password) {
        return replyValidation(res, [
          { message: "Email and password are required", field: !email ? "email" : "password" },
        ]);
      }

      const existing = await authStorage.getUserByEmail(email);
      if (existing) {
        await hashPassword("timing-safe-dummy-password");
        return replyConflict(res, "An account with this email already exists");
      }

      if (isConsumerEmailDomain(email)) {
        const invited = await hasActiveInvitation(email);
        if (!invited) {
          logger.child("auth").warn("Registration blocked: consumer email domain without invitation", {
            email,
            domain: email.split("@")[1]?.toLowerCase(),
          });
          return replyValidation(res, [
            {
              message:
                "Please use your corporate email address to register. Consumer email domains (gmail, yahoo, hotmail, etc.) are not permitted unless you have been invited by an organization admin.",
              field: "email",
            },
          ]);
        }
      }

      const pendingInvitations = await storage.getPendingInvitationsByEmail(email.toLowerCase()).catch(() => []);
      let registrationOrgId: string | null = null;
      if (pendingInvitations.length > 0) {
        registrationOrgId = pendingInvitations[0].orgId;
      } else {
        const emailDomain = email.split("@")[1]?.toLowerCase();
        if (emailDomain) {
          const domainMatch = await storage.getVerifiedAutoJoinDomain(emailDomain).catch(() => null);
          if (domainMatch) registrationOrgId = domainMatch.orgId;
        }
      }

      const complexity = await validatePasswordComplexity(password, registrationOrgId);
      if (!complexity.valid) {
        return replyValidation(
          res,
          complexity.errors.map((msg) => ({ message: msg, field: "password" })),
        );
      }

      const hashedPw = await hashPassword(password);
      const user = await authStorage.upsertUser({
        email,
        passwordHash: hashedPw,
        firstName: firstName || null,
        lastName: lastName || null,
        passwordChangedAt: new Date(),
      });

      req.login(user, async (err) => {
        if (err) return next(err);
        await ensureOrgMembership(user);

        const appBaseUrl = process.env.APP_BASE_URL || "https://nexus.aricatech.xyz";
        const emailContent = welcomeEmail({
          firstName: firstName || undefined,
          email,
          loginUrl: appBaseUrl,
        });
        sendEmail({
          to: email,
          subject: emailContent.subject,
          html: emailContent.html,
          text: emailContent.text,
        }).catch((emailErr) => {
          logger.child("auth").error("Failed to send welcome email", { error: String(emailErr), email });
        });

        const { passwordHash: _, ...safeUser } = user;
        return reply(res, safeUser, {}, 201);
      });
    } catch (error) {
      logger.child("routes").error("Error registering user", { error: String(error) });
      return replyInternal(res, "Registration failed");
    }
  });

  app.post("/api/login", loginRateLimitPre, (req, res, next) => {
    passport.authenticate("local", (err: any, user: any, info: any) => {
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
            .catch(() => {});
        }
        return replyUnauthenticated(res, info?.message || "Invalid credentials");
      }
      clearLoginBuckets(user.email);
      clearLockout(user.email).catch(() => {});
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
    })(req, res, next);
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
    (req, res, next) => {
      passport.authenticate("google", { failureRedirect: "/?error=google_auth_failed" })(req, res, next);
    },
    async (req: any, res) => {
      try {
        if (req.user) {
          if (req.user.email && isConsumerEmailDomain(req.user.email)) {
            const invited = await hasActiveInvitation(req.user.email);
            const memberships = await storage.getUserMemberships(req.user.id).catch(() => []);
            if (!invited && memberships.length === 0) {
              logger.child("auth").warn("OAuth login blocked: consumer email domain without invitation", {
                email: req.user.email,
                provider: "google",
              });
              req.logout(() => {
                req.session.destroy(() => {
                  return res.redirect("/?error=consumer_email_blocked");
                });
              });
              return;
            }
          }
          await ensureOrgMembership(req.user);

          const oauthMemberships = await storage.getUserMemberships(req.user.id).catch(() => []);
          const oauthOrgId = oauthMemberships.length > 0 ? oauthMemberships[0].orgId : null;
          const oauthIp = (() => {
            const fwd = req.headers["x-forwarded-for"];
            if (typeof fwd === "string") return fwd.split(",")[0].trim();
            return req.socket.remoteAddress || "unknown";
          })();
          const oauthPolicy = await checkLoginPolicy(req.user, oauthOrgId, oauthIp);
          if (!oauthPolicy.allowed) {
            req.logout(() => {
              req.session.destroy(() => {
                return res.redirect("/?error=ip_not_allowed");
              });
            });
            return;
          }
          if (oauthOrgId) {
            await enforceMaxConcurrentSessions(req.user.id, oauthOrgId);
          }
        }
        res.redirect("/");
      } catch (err) {
        logger.child("auth").error("Google OAuth callback error", {
          error: String(err),
          userId: req.user?.id,
          email: req.user?.email,
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
    (req, res, next) => {
      passport.authenticate("github", { failureRedirect: "/?error=github_auth_failed" })(req, res, next);
    },
    async (req: any, res) => {
      try {
        if (req.user) {
          if (req.user.email && isConsumerEmailDomain(req.user.email)) {
            const invited = await hasActiveInvitation(req.user.email);
            const memberships = await storage.getUserMemberships(req.user.id).catch(() => []);
            if (!invited && memberships.length === 0) {
              logger.child("auth").warn("OAuth login blocked: consumer email domain without invitation", {
                email: req.user.email,
                provider: "github",
              });
              req.logout(() => {
                req.session.destroy(() => {
                  return res.redirect("/?error=consumer_email_blocked");
                });
              });
              return;
            }
          }
          await ensureOrgMembership(req.user);

          const ghMemberships = await storage.getUserMemberships(req.user.id).catch(() => []);
          const ghOrgId = ghMemberships.length > 0 ? ghMemberships[0].orgId : null;
          const ghIp = (() => {
            const fwd = req.headers["x-forwarded-for"];
            if (typeof fwd === "string") return fwd.split(",")[0].trim();
            return req.socket.remoteAddress || "unknown";
          })();
          const ghPolicy = await checkLoginPolicy(req.user, ghOrgId, ghIp);
          if (!ghPolicy.allowed) {
            req.logout(() => {
              req.session.destroy(() => {
                return res.redirect("/?error=ip_not_allowed");
              });
            });
            return;
          }
          if (ghOrgId) {
            await enforceMaxConcurrentSessions(req.user.id, ghOrgId);
          }
        }
        res.redirect("/");
      } catch (err) {
        logger.child("auth").error("GitHub OAuth callback error", {
          error: String(err),
          userId: req.user?.id,
          email: req.user?.email,
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
