import type { Request, Response, NextFunction } from "express";
import { replyRateLimit, replyError, ERROR_CODES } from "../api-response";
import { logger } from "../logger";
import { sendEmail } from "../email-service";
import { accountLockedEmail } from "../email-templates";
import { db } from "../db";
import { users, failedLoginAttempts } from "@shared/schema";
import { eq, sql, and, gte, desc, count } from "drizzle-orm";

const log = logger.child("auth-rate-limit");

interface RateBucket {
  count: number;
  resetAt: number;
}

const ipLoginBuckets = new Map<string, RateBucket>();
const emailLoginBuckets = new Map<string, RateBucket>();
const ipRegisterBuckets = new Map<string, RateBucket>();
const emailForgotBuckets = new Map<string, RateBucket>();

const LOGIN_IP_MAX = 5;
const LOGIN_IP_WINDOW_MS = 15 * 60 * 1000;

const LOGIN_EMAIL_MAX = 10;
const LOGIN_EMAIL_WINDOW_MS = 30 * 60 * 1000;

const REGISTER_IP_MAX = 3;
const REGISTER_IP_WINDOW_MS = 60 * 60 * 1000;

const FORGOT_EMAIL_MAX = 3;
const FORGOT_EMAIL_WINDOW_MS = 60 * 60 * 1000;

const DEFAULT_LOCKOUT_THRESHOLD = 10;
const DEFAULT_LOCKOUT_DURATION_MS = 30 * 60 * 1000;

export async function isAccountLocked(email: string): Promise<{ locked: boolean; lockedUntil: Date | null }> {
  try {
    const [user] = await db
      .select({ lockedUntil: users.lockedUntil })
      .from(users)
      .where(eq(users.email, email.toLowerCase()))
      .limit(1);
    if (!user || !user.lockedUntil) return { locked: false, lockedUntil: null };
    if (new Date(user.lockedUntil) > new Date()) {
      return { locked: true, lockedUntil: user.lockedUntil };
    }
    return { locked: false, lockedUntil: null };
  } catch (err) {
    log.error("Failed to check account lock status", { email, error: String(err) });
    return { locked: false, lockedUntil: null };
  }
}

function cleanupMap(map: Map<string, RateBucket>): void {
  const now = Date.now();
  map.forEach((bucket, key) => {
    if (bucket.resetAt <= now) {
      map.delete(key);
    }
  });
}

setInterval(
  () => {
    cleanupMap(ipLoginBuckets);
    cleanupMap(emailLoginBuckets);
    cleanupMap(ipRegisterBuckets);
    cleanupMap(emailForgotBuckets);
  },
  5 * 60 * 1000,
).unref();

function resolveIp(req: Request): string {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string") {
    return forwarded.split(",")[0].trim();
  }
  return req.socket.remoteAddress || req.ip || "unknown";
}

function checkBucket(
  map: Map<string, RateBucket>,
  key: string,
  maxAttempts: number,
  windowMs: number,
): { blocked: boolean; remaining: number; resetSeconds: number } {
  const now = Date.now();
  let bucket = map.get(key);

  if (!bucket || bucket.resetAt <= now) {
    bucket = { count: 0, resetAt: now + windowMs };
    map.set(key, bucket);
  }

  const resetSeconds = Math.ceil((bucket.resetAt - now) / 1000);

  if (bucket.count >= maxAttempts) {
    return { blocked: true, remaining: 0, resetSeconds };
  }

  const remaining = maxAttempts - bucket.count;
  return { blocked: false, remaining, resetSeconds };
}

function incrementBucket(map: Map<string, RateBucket>, key: string, windowMs: number): void {
  const now = Date.now();
  let bucket = map.get(key);
  if (!bucket || bucket.resetAt <= now) {
    bucket = { count: 0, resetAt: now + windowMs };
    map.set(key, bucket);
  }
  bucket.count++;
}

function setRateLimitHeaders(res: Response, limit: number, remaining: number, resetSeconds: number): void {
  res.setHeader("X-RateLimit-Limit", String(limit));
  res.setHeader("X-RateLimit-Remaining", String(Math.max(0, remaining)));
  res.setHeader("X-RateLimit-Reset", String(resetSeconds));
}

export function loginRateLimitPre(req: Request, res: Response, next: NextFunction): void {
  const ip = resolveIp(req);
  const ipCheck = checkBucket(ipLoginBuckets, ip, LOGIN_IP_MAX, LOGIN_IP_WINDOW_MS);

  if (ipCheck.blocked) {
    setRateLimitHeaders(res, LOGIN_IP_MAX, 0, ipCheck.resetSeconds);
    log.warn("Login blocked: IP rate limit exceeded", { ip });
    replyRateLimit(
      res,
      `Too many login attempts from this IP address. Try again in ${Math.ceil(ipCheck.resetSeconds / 60)} minutes.`,
    );
    return;
  }

  const email = req.body?.email?.toLowerCase?.();
  if (email) {
    const emailCheck = checkBucket(emailLoginBuckets, email, LOGIN_EMAIL_MAX, LOGIN_EMAIL_WINDOW_MS);
    if (emailCheck.blocked) {
      setRateLimitHeaders(res, LOGIN_EMAIL_MAX, 0, emailCheck.resetSeconds);
      log.warn("Login blocked: email rate limit exceeded (account locked)", { email, ip });
      replyRateLimit(
        res,
        `This account has been temporarily locked due to too many failed login attempts. Try again in ${Math.ceil(emailCheck.resetSeconds / 60)} minutes.`,
      );
      return;
    }

    isAccountLocked(email)
      .then(({ locked, lockedUntil }) => {
        if (locked && lockedUntil) {
          const remainMin = Math.ceil((lockedUntil.getTime() - Date.now()) / 60_000);
          log.warn("Login blocked: DB account lockout active", { email, ip, lockedUntil: lockedUntil.toISOString() });
          replyError(res, 423, [
            {
              code: ERROR_CODES.ACCOUNT_LOCKED,
              message: `Account is locked due to repeated failed login attempts. Try again in ${remainMin} minutes.`,
            },
          ]);
          return;
        }
        next();
      })
      .catch(() => {
        next();
      });
    return;
  }

  next();
}

async function recordFailedLoginDb(
  email: string,
  ip: string,
  userAgent: string | undefined,
  reason: string,
): Promise<void> {
  try {
    await db.insert(failedLoginAttempts).values({
      email: email.toLowerCase(),
      ipAddress: ip,
      userAgent: userAgent || null,
      reason,
    });

    const windowStart = new Date(Date.now() - DEFAULT_LOCKOUT_DURATION_MS);
    const [result] = await db
      .select({ value: count() })
      .from(failedLoginAttempts)
      .where(
        and(eq(failedLoginAttempts.email, email.toLowerCase()), gte(failedLoginAttempts.attemptedAt, windowStart)),
      );

    const failCount = result?.value ?? 0;

    if (failCount >= DEFAULT_LOCKOUT_THRESHOLD) {
      const lockUntil = new Date(Date.now() + DEFAULT_LOCKOUT_DURATION_MS);
      await db
        .update(users)
        .set({ lockedUntil: lockUntil, failedLoginCount: failCount })
        .where(eq(users.email, email.toLowerCase()));

      log.warn("Account locked: failed login threshold reached", {
        email,
        ip,
        failCount,
        lockedUntil: lockUntil.toISOString(),
      });

      const resetMinutes = Math.ceil(DEFAULT_LOCKOUT_DURATION_MS / 60_000);
      const emailContent = accountLockedEmail({ email, lockoutMinutes: resetMinutes });
      sendEmail({
        to: email,
        subject: emailContent.subject,
        html: emailContent.html,
        text: emailContent.text,
      }).catch((err) => {
        log.error("Failed to send account lockout notification email", { email, error: String(err) });
      });
    } else {
      await db.update(users).set({ failedLoginCount: failCount }).where(eq(users.email, email.toLowerCase()));
    }
  } catch (err) {
    log.error("Failed to record failed login in DB", { email, ip, error: String(err) });
  }
}

export function recordFailedLogin(req: Request): void {
  const ip = resolveIp(req);
  const email = req.body?.email?.toLowerCase?.();

  incrementBucket(ipLoginBuckets, ip, LOGIN_IP_WINDOW_MS);

  if (email) {
    incrementBucket(emailLoginBuckets, email, LOGIN_EMAIL_WINDOW_MS);
    const ua = typeof req.headers["user-agent"] === "string" ? req.headers["user-agent"] : undefined;
    recordFailedLoginDb(email, ip, ua, "invalid_credentials").catch((err) => {
      log.error("recordFailedLoginDb background error", { error: String(err) });
    });
  }
}

export function clearLoginBuckets(email: string): void {
  emailLoginBuckets.delete(email.toLowerCase());
}

export async function clearLockout(email: string): Promise<void> {
  try {
    await db.update(users).set({ lockedUntil: null, failedLoginCount: 0 }).where(eq(users.email, email.toLowerCase()));
  } catch (err) {
    log.error("Failed to clear lockout", { email, error: String(err) });
  }
}

export function registerRateLimit(req: Request, res: Response, next: NextFunction): void {
  const ip = resolveIp(req);
  const ipCheck = checkBucket(ipRegisterBuckets, ip, REGISTER_IP_MAX, REGISTER_IP_WINDOW_MS);

  if (ipCheck.blocked) {
    setRateLimitHeaders(res, REGISTER_IP_MAX, 0, ipCheck.resetSeconds);
    log.warn("Registration blocked: IP rate limit exceeded", { ip });
    replyRateLimit(
      res,
      `Too many registration attempts. Try again in ${Math.ceil(ipCheck.resetSeconds / 60)} minutes.`,
    );
    return;
  }

  incrementBucket(ipRegisterBuckets, ip, REGISTER_IP_WINDOW_MS);
  setRateLimitHeaders(res, REGISTER_IP_MAX, ipCheck.remaining - 1, ipCheck.resetSeconds);
  next();
}

export function forgotPasswordRateLimit(req: Request, res: Response, next: NextFunction): void {
  const email = req.body?.email?.toLowerCase?.();
  if (!email) {
    next();
    return;
  }

  const emailCheck = checkBucket(emailForgotBuckets, email, FORGOT_EMAIL_MAX, FORGOT_EMAIL_WINDOW_MS);

  if (emailCheck.blocked) {
    setRateLimitHeaders(res, FORGOT_EMAIL_MAX, 0, emailCheck.resetSeconds);
    log.warn("Forgot-password blocked: email rate limit exceeded", { email });
    replyRateLimit(
      res,
      `Too many password reset requests. Try again in ${Math.ceil(emailCheck.resetSeconds / 60)} minutes.`,
    );
    return;
  }

  incrementBucket(emailForgotBuckets, email, FORGOT_EMAIL_WINDOW_MS);
  setRateLimitHeaders(res, FORGOT_EMAIL_MAX, emailCheck.remaining - 1, emailCheck.resetSeconds);
  next();
}

export async function getLockedAccounts(): Promise<
  Array<{
    id: string;
    email: string | null;
    lockedUntil: Date | null;
    failedLoginCount: number;
    lastFailedAt: Date | null;
    lastFailedIp: string | null;
  }>
> {
  const now = new Date();
  const lockedUsers = await db
    .select({
      id: users.id,
      email: users.email,
      lockedUntil: users.lockedUntil,
      failedLoginCount: users.failedLoginCount,
    })
    .from(users)
    .where(gte(users.lockedUntil, now))
    .orderBy(desc(users.lockedUntil));

  const results: Array<{
    id: string;
    email: string | null;
    lockedUntil: Date | null;
    failedLoginCount: number;
    lastFailedAt: Date | null;
    lastFailedIp: string | null;
  }> = [];

  for (const u of lockedUsers) {
    const [lastAttempt] = await db
      .select({
        attemptedAt: failedLoginAttempts.attemptedAt,
        ipAddress: failedLoginAttempts.ipAddress,
      })
      .from(failedLoginAttempts)
      .where(eq(failedLoginAttempts.email, (u.email || "").toLowerCase()))
      .orderBy(desc(failedLoginAttempts.attemptedAt))
      .limit(1);

    results.push({
      id: u.id,
      email: u.email,
      lockedUntil: u.lockedUntil,
      failedLoginCount: u.failedLoginCount,
      lastFailedAt: lastAttempt?.attemptedAt ?? null,
      lastFailedIp: lastAttempt?.ipAddress ?? null,
    });
  }

  return results;
}

export async function adminUnlockAccount(userId: string): Promise<boolean> {
  try {
    const [user] = await db.select({ email: users.email }).from(users).where(eq(users.id, userId)).limit(1);
    if (!user) return false;
    await db.update(users).set({ lockedUntil: null, failedLoginCount: 0 }).where(eq(users.id, userId));
    if (user.email) {
      emailLoginBuckets.delete(user.email.toLowerCase());
    }
    log.info("Account unlocked by admin", { userId, email: user.email });
    return true;
  } catch (err) {
    log.error("Failed to unlock account", { userId, error: String(err) });
    return false;
  }
}

export async function getFailedLoginHistory(
  limit = 50,
  offset = 0,
): Promise<{ attempts: Array<typeof failedLoginAttempts.$inferSelect>; total: number }> {
  const [totalResult] = await db.select({ value: count() }).from(failedLoginAttempts);
  const total = totalResult?.value ?? 0;
  const attempts = await db
    .select()
    .from(failedLoginAttempts)
    .orderBy(desc(failedLoginAttempts.attemptedAt))
    .limit(limit)
    .offset(offset);
  return { attempts, total };
}

export async function getFailedLoginStats(): Promise<{
  totalAttempts24h: number;
  lockedAccountsCount: number;
  topIps: Array<{ ip: string; count: number }>;
}> {
  const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const now = new Date();

  const [total24h] = await db
    .select({ value: count() })
    .from(failedLoginAttempts)
    .where(gte(failedLoginAttempts.attemptedAt, oneDayAgo));

  const [lockedCount] = await db.select({ value: count() }).from(users).where(gte(users.lockedUntil, now));

  const topIpsResult = await db
    .select({
      ip: failedLoginAttempts.ipAddress,
      cnt: sql<number>`count(*)::int`,
    })
    .from(failedLoginAttempts)
    .where(gte(failedLoginAttempts.attemptedAt, oneDayAgo))
    .groupBy(failedLoginAttempts.ipAddress)
    .orderBy(sql`count(*) desc`)
    .limit(10);

  return {
    totalAttempts24h: total24h?.value ?? 0,
    lockedAccountsCount: lockedCount?.value ?? 0,
    topIps: topIpsResult.map((r) => ({ ip: r.ip, count: r.cnt })),
  };
}

export function getAuthRateLimitStats(): {
  loginIpBuckets: number;
  loginEmailBuckets: number;
  registerIpBuckets: number;
  forgotEmailBuckets: number;
} {
  return {
    loginIpBuckets: ipLoginBuckets.size,
    loginEmailBuckets: emailLoginBuckets.size,
    registerIpBuckets: ipRegisterBuckets.size,
    forgotEmailBuckets: emailForgotBuckets.size,
  };
}
