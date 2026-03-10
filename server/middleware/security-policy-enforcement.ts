import type { Request, Response, NextFunction } from "express";
import { replyForbidden, replyError } from "../api-response";
import { logger } from "../logger";
import { storage } from "../storage";

const log = logger.child("security-policy");

const POLICY_CACHE_TTL_MS = 60_000;

interface CachedPolicy {
  policy: OrgSecurityPolicyRow | null;
  expiresAt: number;
}

interface OrgSecurityPolicyRow {
  id: string;
  orgId: string;
  mfaRequired: boolean;
  sessionTimeoutMinutes: number;
  maxConcurrentSessions: number;
  passwordMinLength: number;
  passwordRequireUppercase: boolean;
  passwordRequireNumber: boolean;
  passwordRequireSpecial: boolean;
  passwordExpiryDays: number;
  ipAllowlistEnabled: boolean;
  ipAllowlistCidrs: string[] | null;
  deviceTrustRequired: boolean;
}

const policyCache = new Map<string, CachedPolicy>();

setInterval(() => {
  const now = Date.now();
  policyCache.forEach((entry, key) => {
    if (entry.expiresAt <= now) policyCache.delete(key);
  });
}, 5 * 60_000);

async function getPolicy(orgId: string): Promise<OrgSecurityPolicyRow | null> {
  const now = Date.now();
  const cached = policyCache.get(orgId);
  if (cached && cached.expiresAt > now) return cached.policy;

  const policy = (await storage.getOrgSecurityPolicy(orgId)) as OrgSecurityPolicyRow | undefined;
  policyCache.set(orgId, { policy: policy ?? null, expiresAt: now + POLICY_CACHE_TTL_MS });
  return policy ?? null;
}

export function invalidatePolicyCache(orgId?: string): void {
  if (orgId) {
    policyCache.delete(orgId);
  } else {
    policyCache.clear();
  }
}

function normalizeIp(raw: string): string {
  if (raw.startsWith("::ffff:")) return raw.slice(7);
  return raw;
}

function resolveIp(req: Request): string {
  const forwarded = req.headers["x-forwarded-for"];
  const raw = typeof forwarded === "string" ? forwarded.split(",")[0].trim() : req.socket.remoteAddress || "unknown";
  return normalizeIp(raw);
}

function ipToLong(ip: string): number {
  const parts = ip.split(".");
  if (parts.length !== 4) return 0;
  return (
    parts.reduce((acc, octet) => {
      const n = parseInt(octet, 10);
      if (isNaN(n) || n < 0 || n > 255) return acc;
      return (acc << 8) + n;
    }, 0) >>> 0
  );
}

function isIpInCidr(ip: string, cidr: string): boolean {
  const [network, prefixStr] = cidr.split("/");
  if (!network || !prefixStr) return false;
  const prefix = parseInt(prefixStr, 10);
  if (isNaN(prefix) || prefix < 0 || prefix > 32) return false;

  const ipLong = ipToLong(ip);
  const networkLong = ipToLong(network);
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  return (ipLong & mask) === (networkLong & mask);
}

function isIpAllowed(ip: string, cidrs: string[]): boolean {
  if (cidrs.length === 0) return true;
  for (let i = 0; i < cidrs.length; i++) {
    if (isIpInCidr(ip, cidrs[i])) return true;
  }
  return false;
}

export function enforceIpAllowlist(req: Request, res: Response, next: NextFunction): void {
  const user = req.user as any;
  if (!user?.orgId) {
    next();
    return;
  }

  getPolicy(user.orgId)
    .then((policy) => {
      if (!policy || !policy.ipAllowlistEnabled) {
        next();
        return;
      }

      const cidrs = policy.ipAllowlistCidrs;
      if (!cidrs || cidrs.length === 0) {
        next();
        return;
      }

      const ip = resolveIp(req);
      if (isIpAllowed(ip, cidrs)) {
        next();
        return;
      }

      log.warn("Request blocked by IP allowlist", { ip, orgId: user.orgId, userId: user.id });
      replyForbidden(res, "Access denied: your IP address is not in the organization's allowlist.", "IP_NOT_ALLOWED");
    })
    .catch((err) => {
      log.error("Failed to check IP allowlist", { error: String(err), orgId: user.orgId });
      next();
    });
}

export function enforceSessionTimeout(req: Request, res: Response, next: NextFunction): void {
  const user = req.user as any;
  if (!user?.orgId) {
    next();
    return;
  }

  const session = req.session as any;
  const now = Date.now();

  if (!session.lastActivity) {
    session.lastActivity = now;
    next();
    return;
  }

  getPolicy(user.orgId)
    .then((policy) => {
      if (!policy) {
        session.lastActivity = now;
        next();
        return;
      }

      const timeoutMs = policy.sessionTimeoutMinutes * 60 * 1000;
      const elapsed = now - session.lastActivity;

      if (elapsed > timeoutMs) {
        log.info("Session expired due to org timeout policy", {
          userId: user.id,
          orgId: user.orgId,
          timeoutMinutes: policy.sessionTimeoutMinutes,
          idleMinutes: Math.round(elapsed / 60_000),
        });
        req.logout(() => {
          req.session.destroy(() => {
            replyError(res, 401, [
              {
                code: "SESSION_EXPIRED",
                message: `Session expired due to inactivity. Your organization requires activity within ${policy.sessionTimeoutMinutes} minutes.`,
              },
            ]);
          });
        });
        return;
      }

      session.lastActivity = now;
      next();
    })
    .catch((err) => {
      log.error("Failed to check session timeout", { error: String(err), orgId: user.orgId });
      session.lastActivity = now;
      next();
    });
}

export interface LoginPolicyResult {
  allowed: boolean;
  reason?: string;
  code?: string;
  mfaRequired?: boolean;
  passwordExpired?: boolean;
  passwordExpiryDays?: number;
}

export async function checkLoginPolicy(user: any, orgId: string | null, clientIp: string): Promise<LoginPolicyResult> {
  if (!orgId) return { allowed: true };

  const policy = await getPolicy(orgId);
  if (!policy) return { allowed: true };

  if (policy.ipAllowlistEnabled && policy.ipAllowlistCidrs && policy.ipAllowlistCidrs.length > 0) {
    if (!isIpAllowed(clientIp, policy.ipAllowlistCidrs)) {
      log.warn("Login blocked by IP allowlist", { userId: user.id, orgId, ip: clientIp });
      return {
        allowed: false,
        reason: "Login denied: your IP address is not in the organization's allowlist.",
        code: "IP_NOT_ALLOWED",
      };
    }
  }

  if (policy.mfaRequired) {
    const hasMfa = !!(user as any).mfaEnabled;
    if (!hasMfa) {
      log.info("Login requires MFA setup", { userId: user.id, orgId });
      return {
        allowed: true,
        mfaRequired: true,
      };
    }
  }

  if (policy.passwordExpiryDays > 0 && user.passwordHash) {
    const changedAt = (user as any).passwordChangedAt;
    const referenceDate = changedAt ? new Date(changedAt).getTime() : new Date(user.createdAt).getTime();
    const expiryMs = policy.passwordExpiryDays * 24 * 60 * 60 * 1000;
    if (Date.now() - referenceDate > expiryMs) {
      log.info("Password expired per org policy", {
        userId: user.id,
        orgId,
        expiryDays: policy.passwordExpiryDays,
      });
      return {
        allowed: true,
        passwordExpired: true,
        passwordExpiryDays: policy.passwordExpiryDays,
      };
    }
  }

  return { allowed: true };
}

export async function enforceMaxConcurrentSessions(
  userId: string,
  orgId: string | null,
): Promise<{ allowed: boolean; evictedCount: number }> {
  if (!orgId) return { allowed: true, evictedCount: 0 };

  const policy = await getPolicy(orgId);
  if (!policy) return { allowed: true, evictedCount: 0 };

  const maxSessions = policy.maxConcurrentSessions;
  if (maxSessions <= 0) return { allowed: true, evictedCount: 0 };

  try {
    const activeSessions = await storage.countUserActiveSessions(userId);
    if (activeSessions < maxSessions) return { allowed: true, evictedCount: 0 };

    const evicted = await storage.evictOldestUserSessions(userId, activeSessions - maxSessions + 1);
    log.info("Evicted oldest sessions to enforce max concurrent sessions", {
      userId,
      orgId,
      maxSessions,
      evictedCount: evicted,
    });
    return { allowed: true, evictedCount: evicted };
  } catch (err) {
    log.error("Failed to enforce max concurrent sessions", { error: String(err), userId, orgId });
    return { allowed: true, evictedCount: 0 };
  }
}

export interface PasswordValidationResult {
  valid: boolean;
  errors: string[];
}

export async function validatePasswordComplexity(
  password: string,
  orgId: string | null,
): Promise<PasswordValidationResult> {
  const errors: string[] = [];

  const minLength = 8;
  if (password.length < minLength) {
    errors.push(`Password must be at least ${minLength} characters`);
  }

  if (!orgId) {
    return { valid: errors.length === 0, errors };
  }

  const policy = await getPolicy(orgId);
  if (!policy) {
    return { valid: errors.length === 0, errors };
  }

  if (password.length < policy.passwordMinLength) {
    errors.length = 0;
    errors.push(`Password must be at least ${policy.passwordMinLength} characters`);
  }

  if (policy.passwordRequireUppercase && !/[A-Z]/.test(password)) {
    errors.push("Password must contain at least one uppercase letter");
  }

  if (policy.passwordRequireNumber && !/\d/.test(password)) {
    errors.push("Password must contain at least one number");
  }

  if (policy.passwordRequireSpecial && !/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?`~]/.test(password)) {
    errors.push("Password must contain at least one special character");
  }

  return { valid: errors.length === 0, errors };
}

export function securityPolicyEnforcement(req: Request, res: Response, next: NextFunction): void {
  const user = req.user as any;
  if (!user?.orgId) {
    next();
    return;
  }

  getPolicy(user.orgId)
    .then((policy) => {
      if (!policy) {
        next();
        return;
      }

      if (policy.ipAllowlistEnabled && policy.ipAllowlistCidrs && policy.ipAllowlistCidrs.length > 0) {
        const ip = resolveIp(req);
        if (!isIpAllowed(ip, policy.ipAllowlistCidrs)) {
          log.warn("Request blocked by IP allowlist", { ip, orgId: user.orgId, userId: user.id });
          replyForbidden(
            res,
            "Access denied: your IP address is not in the organization's allowlist.",
            "IP_NOT_ALLOWED",
          );
          return;
        }
      }

      const session = req.session as any;
      const now = Date.now();
      if (session.lastActivity) {
        const timeoutMs = policy.sessionTimeoutMinutes * 60 * 1000;
        const elapsed = now - session.lastActivity;
        if (elapsed > timeoutMs) {
          log.info("Session expired due to org timeout policy", {
            userId: user.id,
            orgId: user.orgId,
            timeoutMinutes: policy.sessionTimeoutMinutes,
            idleMinutes: Math.round(elapsed / 60_000),
          });
          req.logout(() => {
            req.session.destroy(() => {
              replyError(res, 401, [
                {
                  code: "SESSION_EXPIRED",
                  message: `Session expired due to inactivity. Your organization requires activity within ${policy.sessionTimeoutMinutes} minutes.`,
                },
              ]);
            });
          });
          return;
        }
      }
      session.lastActivity = now;

      next();
    })
    .catch((err) => {
      log.error("Failed to enforce security policies", { error: String(err), orgId: user.orgId });
      next();
    });
}
