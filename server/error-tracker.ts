import type { Request, Response, NextFunction } from "express";
import { logger } from "./logger";

const log = logger.child("error-tracker");

/** Maximum number of error entries to keep in memory */
const MAX_ERRORS = 500;

/** Maximum number of grouped error entries */
const MAX_GROUPS = 200;

export interface TrackedError {
  id: string;
  timestamp: string;
  message: string;
  stack?: string;
  route?: string;
  method?: string;
  statusCode?: number;
  userId?: string;
  orgId?: string;
  fingerprint: string;
  context?: Record<string, unknown>;
}

export interface ErrorGroup {
  fingerprint: string;
  message: string;
  route?: string;
  count: number;
  firstSeen: string;
  lastSeen: string;
  lastStack?: string;
  recentUserIds: string[];
  recentOrgIds: string[];
}

const recentErrors: TrackedError[] = [];
const errorGroups = new Map<string, ErrorGroup>();

let errorIdCounter = 0;

/**
 * Generate a fingerprint from the error message + route + method.
 * This groups similar errors together for aggregation.
 */
function generateFingerprint(message: string, route?: string, method?: string): string {
  // Normalize the message: strip numbers, UUIDs, and hex strings
  const normalized = message
    .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, "<UUID>")
    .replace(/\b\d+\b/g, "<N>")
    .replace(/0x[0-9a-f]+/gi, "<HEX>")
    .trim();
  return `${method || "?"}:${route || "?"}:${normalized}`;
}

/**
 * Track an error with full request context.
 */
export function trackError(
  error: Error | string,
  options: {
    route?: string;
    method?: string;
    statusCode?: number;
    userId?: string;
    orgId?: string;
    context?: Record<string, unknown>;
  } = {},
): TrackedError {
  const message = typeof error === "string" ? error : error.message;
  const stack = typeof error === "string" ? undefined : error.stack;
  const fingerprint = generateFingerprint(message, options.route, options.method);

  errorIdCounter++;
  const entry: TrackedError = {
    id: `err_${Date.now()}_${errorIdCounter}`,
    timestamp: new Date().toISOString(),
    message,
    stack,
    route: options.route,
    method: options.method,
    statusCode: options.statusCode,
    userId: options.userId,
    orgId: options.orgId,
    fingerprint,
    context: options.context,
  };

  // Add to recent errors ring buffer
  recentErrors.push(entry);
  if (recentErrors.length > MAX_ERRORS) {
    recentErrors.splice(0, recentErrors.length - MAX_ERRORS);
  }

  // Update or create error group
  const existing = errorGroups.get(fingerprint);
  if (existing) {
    existing.count++;
    existing.lastSeen = entry.timestamp;
    existing.lastStack = stack;
    if (options.userId && !existing.recentUserIds.includes(options.userId)) {
      existing.recentUserIds.push(options.userId);
      if (existing.recentUserIds.length > 10) existing.recentUserIds.shift();
    }
    if (options.orgId && !existing.recentOrgIds.includes(options.orgId)) {
      existing.recentOrgIds.push(options.orgId);
      if (existing.recentOrgIds.length > 10) existing.recentOrgIds.shift();
    }
  } else {
    // Evict oldest group if at capacity
    if (errorGroups.size >= MAX_GROUPS) {
      let oldestKey: string | undefined;
      let oldestTime = Infinity;
      Array.from(errorGroups.entries()).forEach(([key, group]) => {
        const t = new Date(group.lastSeen).getTime();
        if (t < oldestTime) {
          oldestTime = t;
          oldestKey = key;
        }
      });
      if (oldestKey) errorGroups.delete(oldestKey);
    }

    errorGroups.set(fingerprint, {
      fingerprint,
      message,
      route: options.route,
      count: 1,
      firstSeen: entry.timestamp,
      lastSeen: entry.timestamp,
      lastStack: stack,
      recentUserIds: options.userId ? [options.userId] : [],
      recentOrgIds: options.orgId ? [options.orgId] : [],
    });
  }

  return entry;
}

/**
 * Express error-handling middleware that captures unhandled errors.
 * Must be registered AFTER all routes.
 */
export function errorTrackingMiddleware(err: Error, req: Request, res: Response, next: NextFunction): void {
  const user = (req as any).user;
  const tracked = trackError(err, {
    route: req.route?.path || req.path,
    method: req.method,
    statusCode: res.statusCode >= 400 ? res.statusCode : 500,
    userId: user?.id,
    orgId: user?.orgId,
    context: {
      userAgent: req.headers["user-agent"],
      ip: req.ip,
      query: req.query,
    },
  });

  log.error("Unhandled request error", {
    errorId: tracked.id,
    fingerprint: tracked.fingerprint,
    route: tracked.route,
    method: tracked.method,
    message: tracked.message,
  });

  // Don't send response if headers already sent
  if (res.headersSent) {
    return next(err);
  }

  res.status(tracked.statusCode || 500).json({
    error: "Internal server error",
    errorId: tracked.id,
  });
}

/**
 * Get recent errors, optionally filtered.
 */
export function getRecentErrors(options?: {
  route?: string;
  userId?: string;
  orgId?: string;
  limit?: number;
}): TrackedError[] {
  let filtered = [...recentErrors];
  if (options?.route) filtered = filtered.filter((e) => e.route === options.route);
  if (options?.userId) filtered = filtered.filter((e) => e.userId === options.userId);
  if (options?.orgId) filtered = filtered.filter((e) => e.orgId === options.orgId);
  const limit = Math.min(options?.limit || 50, 200);
  return filtered.slice(-limit).reverse();
}

/**
 * Get error groups sorted by count (most frequent first).
 */
export function getErrorGroups(limit = 50): ErrorGroup[] {
  return Array.from(errorGroups.values())
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

/**
 * Get summary stats for the error tracker.
 */
export function getErrorStats(): {
  totalErrors: number;
  uniqueGroups: number;
  errorsLast5min: number;
  errorsLast1hr: number;
  topRoutes: Array<{ route: string; count: number }>;
} {
  const now = Date.now();
  const fiveMinAgo = now - 5 * 60 * 1000;
  const oneHrAgo = now - 60 * 60 * 1000;

  const errorsLast5min = recentErrors.filter((e) => new Date(e.timestamp).getTime() > fiveMinAgo).length;
  const errorsLast1hr = recentErrors.filter((e) => new Date(e.timestamp).getTime() > oneHrAgo).length;

  // Top routes by error count
  const routeCounts = new Map<string, number>();
  Array.from(errorGroups.values()).forEach((group) => {
    if (group.route) {
      routeCounts.set(group.route, (routeCounts.get(group.route) || 0) + group.count);
    }
  });
  const topRoutes = Array.from(routeCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([route, count]) => ({ route, count }));

  return {
    totalErrors: recentErrors.length,
    uniqueGroups: errorGroups.size,
    errorsLast5min,
    errorsLast1hr,
    topRoutes,
  };
}
