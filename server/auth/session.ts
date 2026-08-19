import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as GitHubStrategy } from "passport-github2";
import session from "express-session";
import type { Express, RequestHandler } from "express";
import connectPg from "connect-pg-simple";
import { authStorage } from "./storage";
import { storage } from "../storage";
import { db } from "../db";
import { eq, and } from "drizzle-orm";
import { users } from "@shared/models/auth";
import type { User } from "@shared/models/auth";
import { organizationMemberships } from "@shared/schema";
import { config } from "../config";
import { pool } from "../db";
import { scrypt, randomBytes, timingSafeEqual } from "crypto";
import { promisify } from "util";
import { replyUnauthenticated } from "../api-response";
import { logger } from "../logger";
import { checkAndPromoteSuperAdmin } from "../bootstrap-super-admin";

const INVITATION_ONLY_MESSAGE = "Access is by invitation only. Please contact your platform administrator.";

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function isPlatformSuperAdminEmail(email: string): boolean {
  const normalizedEmail = normalizeEmail(email);
  return (
    normalizedEmail === normalizeEmail(process.env.SUPER_ADMIN_EMAIL || "") ||
    normalizedEmail === "prathamesh@aricatech.com"
  );
}

async function hasValidPendingInvitation(email: string): Promise<boolean> {
  const invitations = await storage.getPendingInvitationsByEmail(normalizeEmail(email));
  const now = Date.now();
  return invitations.some((invitation) => !invitation.acceptedAt && new Date(invitation.expiresAt).getTime() > now);
}

async function auditRejectedOAuth(email: string, provider: string, reason: string): Promise<void> {
  await storage.createAuditLog({
    userId: undefined,
    userName: email,
    action: "oauth_login_rejected",
    resourceType: "auth",
    resourceId: email,
    details: { provider, reason },
  });
}

async function canAcceptOAuth(email: string, provider: string): Promise<boolean> {
  if (isPlatformSuperAdminEmail(email)) return true;
  if (await hasValidPendingInvitation(email)) return true;
  await auditRejectedOAuth(email, provider, "invitation_required");
  return false;
}

/**
 * Augmented user type that includes session-derived org membership fields.
 * These fields are added during deserialization (not on the DB schema User type).
 */
export interface SessionUser extends User {
  orgId?: string | null;
  orgRole?: string | null;
}

const scryptAsync = promisify(scrypt);

const DESERIALIZE_CACHE_TTL_MS = 30_000;
const DESERIALIZE_CACHE_MAX = 500;

interface CachedUser {
  user: SessionUser;
  expiresAt: number;
}

const deserializeCache = new Map<string, CachedUser>();

function pruneDeserializeCache() {
  if (deserializeCache.size <= DESERIALIZE_CACHE_MAX) return;
  const now = Date.now();
  const keys = Array.from(deserializeCache.keys());
  for (let i = 0; i < keys.length; i++) {
    const entry = deserializeCache.get(keys[i]);
    if (entry && entry.expiresAt <= now) deserializeCache.delete(keys[i]);
  }
  if (deserializeCache.size > DESERIALIZE_CACHE_MAX) {
    const oldest = Array.from(deserializeCache.entries()).sort((a, b) => a[1].expiresAt - b[1].expiresAt);
    const toRemove = oldest.slice(0, deserializeCache.size - DESERIALIZE_CACHE_MAX);
    for (let i = 0; i < toRemove.length; i++) deserializeCache.delete(toRemove[i][0]);
  }
}

export function invalidateDeserializeCache(userId?: string) {
  if (userId) {
    deserializeCache.delete(userId);
  } else {
    deserializeCache.clear();
  }
}

/**
 * Destroy all sessions for a given user by deleting rows from the sessions table
 * whose sess->passport->user matches the userId. This forces the user to re-login
 * after privilege escalation (role change, suspension, etc.).
 */
export async function invalidateUserSessions(userId: string): Promise<number> {
  try {
    const result = await pool.query(`DELETE FROM sessions WHERE sess->'passport'->>'user' = $1`, [userId]);
    const count = Number(result.rowCount) || 0;
    invalidateDeserializeCache(userId);
    if (count > 0) {
      logger.child("auth-session").info("Invalidated user sessions after privilege change", {
        userId,
        sessionsDestroyed: count,
      });
    }
    return count;
  } catch (err) {
    logger.child("auth-session").error("Failed to invalidate user sessions", {
      userId,
      error: String(err),
    });
    return 0;
  }
}

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16).toString("hex");
  const buf = (await scryptAsync(password, salt, 64)) as Buffer;
  return `${buf.toString("hex")}.${salt}`;
}

export async function comparePasswords(supplied: string, stored: string): Promise<boolean> {
  const [hashedPassword, salt] = stored.split(".");
  const buf = (await scryptAsync(supplied, salt, 64)) as Buffer;
  return timingSafeEqual(Buffer.from(hashedPassword, "hex"), buf);
}

export function getSession() {
  const sessionTtl = 7 * 24 * 60 * 60 * 1000;
  const pgStore = connectPg(session);
  const sessionStore = new pgStore({
    conString: config.databaseUrl,
    createTableIfMissing: true,
    ttl: sessionTtl,
    tableName: "sessions",
  });
  const isProduction = new Set(["production", "staging", "uat"]).has(config.nodeEnv);
  return session({
    secret: config.session.secret,
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: isProduction,
      maxAge: sessionTtl,
      sameSite: "lax",
    },
  });
}

/**
 * Resolve a callback URL to an absolute URL.
 * If APP_BASE_URL is set and the callback is a relative path, prefix it.
 * This prevents redirect_uri mismatch behind reverse proxies (App Runner, CloudFront)
 * where passport may reconstruct the wrong origin from request headers.
 */
export function resolveCallbackUrl(callbackUrl: string): string {
  if (callbackUrl.startsWith("http://") || callbackUrl.startsWith("https://")) {
    return callbackUrl;
  }
  const baseUrl = process.env.APP_BASE_URL;
  if (baseUrl) {
    const resolved = baseUrl.replace(/\/+$/, "") + callbackUrl;
    logger.child("auth-session").info("Resolved relative OAuth callback to absolute URL", {
      relative: callbackUrl,
      resolved,
    });
    return resolved;
  }
  return callbackUrl;
}

/**
 * Google OAuth verify callback. Extracted from setupAuth for testability.
 * Parses Google profile, upserts user, checks disabled status, promotes super-admin.
 */
export async function googleVerifyCallback(
  _accessToken: string,
  _refreshToken: string,
  profile: passport.Profile,
  done: (err: Error | null, user?: Express.User | false, info?: { message: string }) => void,
): Promise<void> {
  try {
    const email = profile.emails?.[0]?.value;
    if (!email) return done(null, false, { message: "No email from Google" });
    const normalizedEmail = normalizeEmail(email);
    let user = await authStorage.getUserByEmail(normalizedEmail);
    if (!user) {
      if (!(await canAcceptOAuth(normalizedEmail, "google"))) {
        return done(null, false, { message: INVITATION_ONLY_MESSAGE });
      }
      user = await authStorage.upsertUser({
        email: normalizedEmail,
        firstName: profile.name?.givenName || null,
        lastName: profile.name?.familyName || null,
        profileImageUrl: profile.photos?.[0]?.value || null,
      });
    }
    if (user.disabledAt) {
      return done(null, false, { message: "Account is disabled" });
    }
    // Auto-promote super-admin on login (not on every deserialize)
    if (!user.isSuperAdmin && user.email) {
      const promoted = await checkAndPromoteSuperAdmin(user.id, user.email);
      if (promoted) {
        (user as SessionUser).isSuperAdmin = true;
      }
    }
    return done(null, user);
  } catch (err) {
    return done(err as Error);
  }
}

/**
 * GitHub OAuth verify callback. Extracted from setupAuth for testability.
 * Finds verified primary email, splits displayName, upserts user, checks disabled status.
 */
export async function githubVerifyCallback(
  _accessToken: string,
  _refreshToken: string,
  profile: passport.Profile,
  done: (err: Error | null, user?: Express.User | false, info?: { message: string }) => void,
): Promise<void> {
  try {
    const emails: Array<{ value?: string; primary?: boolean; verified?: boolean }> = profile.emails || [];
    const verified = emails.find((e) => e.primary && e.verified && e.value);
    if (!verified?.value) {
      return done(null, false, { message: "No verified primary email from GitHub" });
    }
    const normalizedEmail = normalizeEmail(verified.value);
    let user = await authStorage.getUserByEmail(normalizedEmail);
    if (!user) {
      if (!(await canAcceptOAuth(normalizedEmail, "github"))) {
        return done(null, false, { message: INVITATION_ONLY_MESSAGE });
      }
      user = await authStorage.upsertUser({
        email: normalizedEmail,
        firstName: profile.displayName?.split(" ")[0] || profile.username || null,
        lastName: profile.displayName?.split(" ").slice(1).join(" ") || null,
        profileImageUrl: profile.photos?.[0]?.value || null,
      });
    }
    if (user.disabledAt) {
      return done(null, false, { message: "Account is disabled" });
    }
    // Auto-promote super-admin on login (not on every deserialize)
    if (!user.isSuperAdmin && user.email) {
      const promoted = await checkAndPromoteSuperAdmin(user.id, user.email);
      if (promoted) {
        (user as SessionUser).isSuperAdmin = true;
      }
    }
    return done(null, user);
  } catch (err) {
    return done(err as Error);
  }
}

/**
 * Patch an OAuth2 client instance to use Node.js built-in fetch() for the
 * access-token exchange instead of the legacy `oauth` npm package's HTTP client.
 *
 * The `oauth` library uses an ancient https.request() implementation that
 * encounters TLS socket errors inside AWS App Runner and similar managed
 * runtimes. Node.js 22's built-in fetch (based on undici) handles connection
 * pooling, TLS, and HTTP/2 correctly without these issues.
 */
/* eslint-disable @typescript-eslint/no-explicit-any --
 * We intentionally access protected/private members of the passport-oauth2
 * OAuth2 client to replace its broken HTTP transport with fetch. This is the
 * only viable approach short of forking the library. */
function patchOAuth2WithFetch(oauth2: any, provider: string): void {
  const log = logger.child("oauth2-fetch-patch");
  const clientId: string = oauth2._clientId;
  const clientSecret: string = oauth2._clientSecret;
  const tokenUrl: string = oauth2._getAccessTokenUrl();

  oauth2.getOAuthAccessToken = function (
    code: string,
    params: Record<string, string>,
    callback: (
      err: Error | null,
      accessToken?: string,
      refreshToken?: string,
      results?: Record<string, unknown>,
    ) => void,
  ) {
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: params.redirect_uri || "",
      client_id: clientId,
      client_secret: clientSecret,
    });

    log.info("Exchanging OAuth code for access token via fetch", {
      provider,
      tokenUrl,
      redirectUri: params.redirect_uri,
    });

    fetch(tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: body.toString(),
      signal: AbortSignal.timeout(15_000),
    })
      .then(async (res) => {
        const text = await res.text();
        let data: Record<string, unknown>;
        try {
          data = JSON.parse(text);
        } catch {
          log.error("Non-JSON response from token endpoint", {
            provider,
            status: res.status,
            body: text.slice(0, 500),
          });
          return callback(new Error(`OAuth token endpoint returned non-JSON (status ${res.status})`));
        }

        if (!res.ok || data.error) {
          log.error("OAuth token exchange failed", {
            provider,
            status: res.status,
            error: data.error,
            errorDescription: data.error_description,
          });
          return callback(
            new Error(String(data.error_description || data.error || `Token exchange failed (${res.status})`)),
          );
        }

        log.info("OAuth token exchange succeeded", { provider });
        return callback(null, String(data.access_token), data.refresh_token as string | undefined, data);
      })
      .catch((err: Error) => {
        log.error("OAuth token exchange network error", {
          provider,
          error: err.message,
          name: err.name,
          cause: String((err as NodeJS.ErrnoException).cause || ""),
        });
        return callback(err);
      });
  };
}

export async function setupAuth(app: Express) {
  app.set("trust proxy", 1);
  app.use(getSession());
  app.use(passport.initialize());
  app.use(passport.session());

  passport.use(
    new LocalStrategy({ usernameField: "email", passwordField: "password" }, async (email, password, done) => {
      try {
        const user = await authStorage.getUserByEmail(email);
        if (!user || !user.passwordHash) {
          return done(null, false, { message: "Invalid email or password" });
        }
        if (user.disabledAt) {
          return done(null, false, { message: "Invalid email or password" });
        }
        const isValid = await comparePasswords(password, user.passwordHash);
        if (!isValid) {
          return done(null, false, { message: "Invalid email or password" });
        }
        // Auto-promote super-admin on login (not on every deserialize)
        if (!user.isSuperAdmin && user.email) {
          const promoted = await checkAndPromoteSuperAdmin(user.id, user.email);
          if (promoted) {
            (user as SessionUser).isSuperAdmin = true;
          }
        }
        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }),
  );

  if (config.oauth.google.clientId && config.oauth.google.clientSecret) {
    const googleCallbackUrl = resolveCallbackUrl(config.oauth.google.callbackUrl);
    const googleStrategy = new GoogleStrategy(
      {
        clientID: config.oauth.google.clientId,
        clientSecret: config.oauth.google.clientSecret,
        callbackURL: googleCallbackUrl,
      },
      googleVerifyCallback,
    );
    // Patch the underlying OAuth2 client to use Node.js built-in fetch instead
    // of the legacy `oauth` npm package's HTTP client. The `oauth` library uses
    // an ancient https.request() implementation that fails with TLS socket errors
    // inside App Runner's network environment.
    patchOAuth2WithFetch((googleStrategy as any)._oauth2, "google");
    passport.use(googleStrategy);
    logger.child("auth-session").info("Google OAuth strategy configured", { callbackURL: googleCallbackUrl });
  }

  if (config.oauth.github.clientId && config.oauth.github.clientSecret) {
    const githubCallbackUrl = resolveCallbackUrl(config.oauth.github.callbackUrl);
    const githubStrategy = new GitHubStrategy(
      {
        clientID: config.oauth.github.clientId,
        clientSecret: config.oauth.github.clientSecret,
        callbackURL: githubCallbackUrl,
        scope: ["user:email"],
      },
      githubVerifyCallback,
    );
    patchOAuth2WithFetch((githubStrategy as any)._oauth2, "github");
    passport.use(githubStrategy);
    logger.child("auth-session").info("GitHub OAuth strategy configured", { callbackURL: githubCallbackUrl });
  }

  passport.serializeUser((user: Express.User, cb) => cb(null, (user as SessionUser).id));
  passport.deserializeUser(async (id: string, cb) => {
    try {
      const now = Date.now();
      const cached = deserializeCache.get(id);
      if (cached && cached.expiresAt > now) {
        return cb(null, cached.user);
      }

      const rows = await db
        .select({
          user: users,
          membershipOrgId: organizationMemberships.orgId,
          membershipRole: organizationMemberships.role,
          membershipStatus: organizationMemberships.status,
        })
        .from(users)
        .leftJoin(
          organizationMemberships,
          and(eq(organizationMemberships.userId, users.id), eq(organizationMemberships.status, "active")),
        )
        .where(eq(users.id, id))
        .limit(1);
      if (rows.length === 0) {
        deserializeCache.delete(id);
        return cb(null, null);
      }
      const row = rows[0];
      const user = row.user;
      if (user.disabledAt) {
        deserializeCache.delete(id);
        return cb(null, null);
      }

      const sessionUser = user as SessionUser;
      sessionUser.orgId = row.membershipOrgId || null;
      sessionUser.orgRole = row.membershipRole || null;

      // Safety-net: auto-promote super-admin on deserialize if DB flag is stale
      if (!sessionUser.isSuperAdmin && sessionUser.email) {
        const promoted = await checkAndPromoteSuperAdmin(sessionUser.id, sessionUser.email);
        if (promoted) {
          sessionUser.isSuperAdmin = true;
        }
      }

      deserializeCache.set(id, { user: sessionUser, expiresAt: now + DESERIALIZE_CACHE_TTL_MS });
      pruneDeserializeCache();

      cb(null, sessionUser);
    } catch (err) {
      cb(err);
    }
  });
}

export const isAuthenticated: RequestHandler = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  replyUnauthenticated(res);
};
