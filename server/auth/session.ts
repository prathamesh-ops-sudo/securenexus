import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as GitHubStrategy } from "passport-github2";
import session from "express-session";
import type { Express, RequestHandler } from "express";
import connectPg from "connect-pg-simple";
import { authStorage } from "./storage";
import { storage } from "../storage";
import { config } from "../config";
import { scrypt, randomBytes, timingSafeEqual } from "crypto";
import { promisify } from "util";
import { replyUnauthenticated } from "../api-response";
import { logger } from "../logger";

const scryptAsync = promisify(scrypt);

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16).toString("hex");
  const buf = (await scryptAsync(password, salt, 64)) as Buffer;
  return `${buf.toString("hex")}.${salt}`;
}

export async function comparePasswords(
  supplied: string,
  stored: string
): Promise<boolean> {
  const [hashedPassword, salt] = stored.split(".");
  const buf = (await scryptAsync(supplied, salt, 64)) as Buffer;
  return timingSafeEqual(Buffer.from(hashedPassword, "hex"), buf);
}

const PRODUCTION_ENVS = new Set(["production", "staging", "uat"]);

export function getSession() {
  const isProduction = PRODUCTION_ENVS.has(config.nodeEnv);
  const sessionTtl = 7 * 24 * 60 * 60 * 1000;
  const pgStore = connectPg(session);
  const sessionStore = new pgStore({
    conString: config.databaseUrl,
    createTableIfMissing: true,
    ttl: sessionTtl,
    tableName: "sessions",
  });
  return session({
    secret: config.session.secret,
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: config.session.forceHttps,
      maxAge: sessionTtl,
      sameSite: isProduction ? "strict" : "lax",
    },
  });
}

export async function setupAuth(app: Express) {
  app.set("trust proxy", 1);
  app.use(getSession());
  app.use(passport.initialize());
  app.use(passport.session());

  passport.use(
    new LocalStrategy(
      { usernameField: "email", passwordField: "password" },
      async (email, password, done) => {
        try {
          const user = await authStorage.getUserByEmail(email);
          if (!user || !user.passwordHash) {
            return done(null, false, { message: "Invalid email or password" });
          }
          const isValid = await comparePasswords(password, user.passwordHash);
          if (!isValid) {
            return done(null, false, { message: "Invalid email or password" });
          }
          return done(null, user);
        } catch (err) {
          return done(err);
        }
      }
    )
  );

  if (config.oauth.google.clientId && config.oauth.google.clientSecret) {
    passport.use(
      new GoogleStrategy(
        {
          clientID: config.oauth.google.clientId,
          clientSecret: config.oauth.google.clientSecret,
          callbackURL: config.oauth.google.callbackUrl,
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
            return done(null, user);
          } catch (err) {
            return done(err);
          }
        }
      )
    );
    logger.child("auth-session").info("Google OAuth strategy configured");
  }

  if (config.oauth.github.clientId && config.oauth.github.clientSecret) {
    passport.use(
      new GitHubStrategy(
        {
          clientID: config.oauth.github.clientId,
          clientSecret: config.oauth.github.clientSecret,
          callbackURL: config.oauth.github.callbackUrl,
          scope: ["user:email"],
        },
        async (_accessToken: string, _refreshToken: string, profile: any, done: any) => {
          try {
            const email = profile.emails?.[0]?.value || `${profile.username}@github.local`;
            let user = await authStorage.getUserByEmail(email);
            if (!user) {
              user = await authStorage.upsertUser({
                email,
                firstName: profile.displayName?.split(" ")[0] || profile.username || null,
                lastName: profile.displayName?.split(" ").slice(1).join(" ") || null,
                profileImageUrl: profile.photos?.[0]?.value || null,
              });
            }
            return done(null, user);
          } catch (err) {
            return done(err);
          }
        }
      )
    );
    logger.child("auth-session").info("GitHub OAuth strategy configured");
  }

  passport.serializeUser((user: any, cb) => cb(null, user.id));
  passport.deserializeUser(async (id: string, cb) => {
    try {
      const user = await authStorage.getUser(id);
      if (!user) return cb(null, null);
      const memberships = await storage.getUserMemberships(user.id);
      const active = memberships.find(m => m.status === "active");
      (user as any).orgId = active?.orgId || null;
      (user as any).orgRole = active?.role || null;
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
