import type { Request, Response, NextFunction } from "express";
import { replyRateLimit } from "../api-response";
import { logger } from "../logger";
import { sendEmail } from "../email-service";
import { accountLockedEmail } from "../email-templates";

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
  }

  next();
}

export function recordFailedLogin(req: Request): void {
  const ip = resolveIp(req);
  const email = req.body?.email?.toLowerCase?.();

  incrementBucket(ipLoginBuckets, ip, LOGIN_IP_WINDOW_MS);

  if (email) {
    incrementBucket(emailLoginBuckets, email, LOGIN_EMAIL_WINDOW_MS);

    const bucket = emailLoginBuckets.get(email);
    if (bucket && bucket.count === LOGIN_EMAIL_MAX) {
      log.warn("Account temporarily locked due to repeated failed login attempts", { email, ip });
      const resetMinutes = Math.ceil(LOGIN_EMAIL_WINDOW_MS / 60_000);
      const emailContent = accountLockedEmail({ email, lockoutMinutes: resetMinutes });
      sendEmail({
        to: email,
        subject: emailContent.subject,
        html: emailContent.html,
        text: emailContent.text,
      }).catch((err) => {
        log.error("Failed to send account lockout notification email", { email, error: String(err) });
      });
    }
  }
}

export function clearLoginBuckets(email: string): void {
  emailLoginBuckets.delete(email.toLowerCase());
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
