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
import { organizationMemberships } from "@shared/schema";
import { config } from "../config";
import { pool } from "../db";
import { scrypt, randomBytes, timingSafeEqual } from "crypto";
import { promisify } from "util";
import { replyUnauthenticated } from "../api-response";
import { logger } from "../logger";
import { checkAndPromoteSuperAdmin } from "../bootstrap-super-admin";

const scryptAsync = promisify(scrypt);

const DESERIALIZE_CACHE_TTL_MS = 30_000;
const DESERIALIZE_CACHE_MAX = 500;

interface CachedUser {
  user: any;
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
function resolveCallbackUrl(callbackUrl: string): string {
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
            (user as any).isSuperAdmin = true;
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
    passport.use(
      new GoogleStrategy(
        {
          clientID: config.oauth.google.clientId,
          clientSecret: config.oauth.google.clientSecret,
          callbackURL: googleCallbackUrl,
        },
        async (_accessToken: string, _refreshToken: string, profile: any, done: any) => {
          try {
            const email = profile.emails?.[0]?.value;
            if (!email) return done(null, false, { message: "No email from Google" });
            let user = await authStorage.getUserByEmail(email);
            if (!user) {
              user = await authStorage.upsertUser({
                email,
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
                (user as any).isSuperAdmin = true;
              }
            }
            return done(null, user);
          } catch (err) {
            return done(err);
          }
        },
      ),
    );
    logger.child("auth-session").info("Google OAuth strategy configured", { callbackURL: googleCallbackUrl });
  }

  if (config.oauth.github.clientId && config.oauth.github.clientSecret) {
    const githubCallbackUrl = resolveCallbackUrl(config.oauth.github.callbackUrl);
    passport.use(
      new GitHubStrategy(
        {
          clientID: config.oauth.github.clientId,
          clientSecret: config.oauth.github.clientSecret,
          callbackURL: githubCallbackUrl,
          scope: ["user:email"],
        },
        async (_accessToken: string, _refreshToken: string, profile: any, done: any) => {
          try {
            const emails: Array<{ value?: string; primary?: boolean; verified?: boolean }> = profile.emails || [];
            const verified = emails.find((e) => e.primary && e.verified && e.value);
            if (!verified?.value) {
              return done(null, false, { message: "No verified primary email from GitHub" });
            }
            const email = verified.value;
            let user = await authStorage.getUserByEmail(email);
            if (!user) {
              user = await authStorage.upsertUser({
                email,
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
                (user as any).isSuperAdmin = true;
              }
            }
            return done(null, user);
          } catch (err) {
            return done(err);
          }
        },
      ),
    );
    logger.child("auth-session").info("GitHub OAuth strategy configured", { callbackURL: githubCallbackUrl });
  }

  passport.serializeUser((user: any, cb) => cb(null, user.id));
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

      (user as any).orgId = row.membershipOrgId || null;
      (user as any).orgRole = row.membershipRole || null;

      deserializeCache.set(id, { user, expiresAt: now + DESERIALIZE_CACHE_TTL_MS });
      pruneDeserializeCache();

      cb(null, user);
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
