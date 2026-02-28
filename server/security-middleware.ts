import type { Request, Response, NextFunction, Express } from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { randomBytes, timingSafeEqual } from "crypto";
import { config } from "./config";
import { logger } from "./logger";
import { replyRateLimit, replyForbidden, ERROR_CODES } from "./api-response";

const PRODUCTION_ENVS = new Set(["production", "staging", "uat"]);
const CSRF_TOKEN_LENGTH = 32;
const CSRF_HEADER = "x-csrf-token";
const CSRF_COOKIE = "XSRF-TOKEN";

const CSRF_EXEMPT_PATHS = new Set([
  "/api/health",
  "/ops/health",
  "/api/ops/health",
  "/api/ops/ready",
  "/api/ops/live",
  "/api/auth/google/callback",
  "/api/auth/github/callback",
  "/api/auth/forgot-password",
  "/api/auth/reset-password",
]);

const CSRF_EXEMPT_PREFIXES = ["/api/v1/ingest", "/api/v1/webhooks"];

function isApiKeyAuthenticated(req: Request): boolean {
  return !!(req as any).apiKey;
}

function isCsrfExempt(req: Request): boolean {
  if (req.method === "GET" || req.method === "HEAD" || req.method === "OPTIONS") {
    return true;
  }
  if (CSRF_EXEMPT_PATHS.has(req.path)) {
    return true;
  }
  for (const prefix of CSRF_EXEMPT_PREFIXES) {
    if (req.path.startsWith(prefix)) {
      return true;
    }
  }
  if (isApiKeyAuthenticated(req)) {
    return true;
  }
  return false;
}

function generateCsrfToken(): string {
  return randomBytes(CSRF_TOKEN_LENGTH).toString("hex");
}

function csrfProtection(req: Request, res: Response, next: NextFunction): void {
  if (!req.session) {
    next();
    return;
  }

  const session = req.session as any;
  if (!session.csrfToken) {
    session.csrfToken = generateCsrfToken();
  }

  const isSecure = PRODUCTION_ENVS.has(config.nodeEnv) && config.session.forceHttps;
  res.cookie(CSRF_COOKIE, session.csrfToken, {
    httpOnly: false,
    secure: isSecure,
    sameSite: PRODUCTION_ENVS.has(config.nodeEnv) ? "strict" : "lax",
    path: "/",
  });

  if (isCsrfExempt(req)) {
    next();
    return;
  }

  const headerToken = req.headers[CSRF_HEADER] as string | undefined;
  if (!headerToken) {
    replyForbidden(res, "CSRF token missing. Include X-CSRF-Token header.", ERROR_CODES.CSRF_MISSING);
    return;
  }

  const sessionToken = session.csrfToken as string;
  const headerBuf = Buffer.from(headerToken, "utf8");
  const sessionBuf = Buffer.from(sessionToken, "utf8");
  if (headerBuf.length !== sessionBuf.length || !timingSafeEqual(headerBuf, sessionBuf)) {
    replyForbidden(res, "CSRF token invalid. Refresh the page and try again.", ERROR_CODES.CSRF_INVALID);
    return;
  }

  next();
}

function configureHelmet(): ReturnType<typeof helmet> {
  return helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:", "blob:", "https:"],
        connectSrc: ["'self'", "https://accounts.google.com", "https://github.com"],
        frameSrc: ["'self'", "https://accounts.google.com"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: config.session.forceHttps ? [] : null,
      },
    },
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" },
    crossOriginResourcePolicy: { policy: "same-site" },
    hsts: PRODUCTION_ENVS.has(config.nodeEnv) ? { maxAge: 31536000, includeSubDomains: true, preload: true } : false,
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
    xContentTypeOptions: true,
    xDnsPrefetchControl: { allow: false },
    xDownloadOptions: true,
    xFrameOptions: { action: "deny" },
    xPermittedCrossDomainPolicies: { permittedPolicies: "none" },
    xPoweredBy: false,
    xXssProtection: true,
  } as any);
}

function authRateLimiter() {
  return rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
      return req.ip || (req.headers["x-forwarded-for"] as string) || "unknown";
    },
    handler: (_req, res) => replyRateLimit(res, "Too many authentication attempts. Try again in 5 minutes."),
    skip: (req) => req.method === "GET",
  });
}

function inputSanitization(req: Request, _res: Response, next: NextFunction): void {
  if (req.body && typeof req.body === "object") {
    sanitizeObject(req.body);
  }
  if (req.query && typeof req.query === "object") {
    sanitizeObject(req.query as Record<string, unknown>);
  }
  next();
}

function sanitizeObject(obj: Record<string, unknown>): void {
  for (const key of Object.keys(obj)) {
    const value = obj[key];
    if (typeof value === "string") {
      obj[key] = sanitizeString(value);
    } else if (value !== null && typeof value === "object" && !Array.isArray(value)) {
      sanitizeObject(value as Record<string, unknown>);
    } else if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) {
        if (typeof value[i] === "string") {
          value[i] = sanitizeString(value[i] as string);
        } else if (value[i] !== null && typeof value[i] === "object") {
          sanitizeObject(value[i] as Record<string, unknown>);
        }
      }
    }
  }
}

function sanitizeString(input: string): string {
  return input.replace(/\0/g, "");
}

export function applySecurityMiddleware(app: Express): void {
  app.use(configureHelmet());

  app.use("/api/login", authRateLimiter());
  app.use("/api/register", authRateLimiter());
  app.use("/api/auth/google", authRateLimiter());
  app.use("/api/auth/github", authRateLimiter());
  app.use("/api/auth/forgot-password", authRateLimiter());
  app.use("/api/auth/reset-password", authRateLimiter());

  logger.child("security").info("Security middleware applied: helmet, auth rate limiting");
}

export function applyInputSanitization(app: Express): void {
  app.use(inputSanitization);
  logger.child("security").info("Input sanitization middleware applied");
}

export function applyCsrfProtection(app: Express): void {
  app.use(csrfProtection);
  logger.child("security").info("CSRF protection enabled (synchronizer token pattern)");
}

export function getCsrfEndpointHandler(_req: Request, res: Response): void {
  const session = _req.session as any;
  if (!session.csrfToken) {
    session.csrfToken = generateCsrfToken();
  }
  res.json({ token: session.csrfToken });
}
