import type { Request, Response, NextFunction } from "express";

// ─── Canonical error codes ────────────────────────────────────────────────────

export const ERROR_CODES = {
  // Authentication
  UNAUTHENTICATED:          "UNAUTHENTICATED",
  API_KEY_MISSING:          "API_KEY_MISSING",
  API_KEY_INVALID:          "API_KEY_INVALID",
  API_KEY_REVOKED:          "API_KEY_REVOKED",
  WEBHOOK_SIG_MISSING:      "WEBHOOK_SIG_MISSING",
  WEBHOOK_SIG_INVALID:      "WEBHOOK_SIG_INVALID",
  WEBHOOK_TS_EXPIRED:       "WEBHOOK_TS_EXPIRED",

  // Authorization
  FORBIDDEN:                "FORBIDDEN",
  PERMISSION_DENIED:        "PERMISSION_DENIED",
  ORG_ACCESS_DENIED:        "ORG_ACCESS_DENIED",
  ORG_MEMBERSHIP_REQUIRED:  "ORG_MEMBERSHIP_REQUIRED",

  // Client errors
  NOT_FOUND:                "NOT_FOUND",
  CONFLICT:                 "CONFLICT",
  VALIDATION_ERROR:         "VALIDATION_ERROR",
  MISSING_PARAMETER:        "MISSING_PARAMETER",

  // Throttling
  RATE_LIMITED:             "RATE_LIMITED",
  INGESTION_RATE_LIMITED:   "INGESTION_RATE_LIMITED",

  // Server / upstream
  INTERNAL_ERROR:           "INTERNAL_ERROR",
  NOT_IMPLEMENTED:          "NOT_IMPLEMENTED",
  UPSTREAM_ERROR:           "UPSTREAM_ERROR",
} as const;

export type ErrorCode = (typeof ERROR_CODES)[keyof typeof ERROR_CODES];

// ─── Canonical envelope types ─────────────────────────────────────────────────

export interface ApiError {
  code: ErrorCode | string;
  message: string;
  field?: string;
  details?: unknown;
}

export interface ApiMeta {
  page?: number;
  pageSize?: number;
  total?: number;
  requestId?: string;
  [key: string]: unknown;
}

export interface ApiEnvelope<T = unknown> {
  data: T | null;
  meta: ApiMeta;
  errors: ApiError[] | null;
}

// ─── Success reply ────────────────────────────────────────────────────────────

export function reply<T>(
  res: Response,
  data: T,
  meta: ApiMeta = {},
  status = 200,
): Response {
  const envelope: ApiEnvelope<T> = { data, meta, errors: null };
  return res.status(status).json(envelope);
}

// ─── Error replies ────────────────────────────────────────────────────────────

export function replyError(
  res: Response,
  status: number,
  errors: ApiError[],
  meta: ApiMeta = {},
): Response {
  const envelope: ApiEnvelope<null> = { data: null, meta, errors };
  return res.status(status).json(envelope);
}

export function replyUnauthenticated(
  res: Response,
  message = "Authentication required",
  code: ErrorCode | string = ERROR_CODES.UNAUTHENTICATED,
): Response {
  return replyError(res, 401, [{ code, message }]);
}

export function replyForbidden(
  res: Response,
  message: string,
  code: ErrorCode | string = ERROR_CODES.FORBIDDEN,
): Response {
  return replyError(res, 403, [{ code, message }]);
}

export function replyNotFound(
  res: Response,
  message = "Resource not found",
  code: ErrorCode | string = ERROR_CODES.NOT_FOUND,
): Response {
  return replyError(res, 404, [{ code, message }]);
}

export function replyConflict(
  res: Response,
  message: string,
  code: ErrorCode | string = ERROR_CODES.CONFLICT,
): Response {
  return replyError(res, 409, [{ code, message }]);
}

export function replyValidation(
  res: Response,
  errors: { message: string; field?: string; details?: unknown }[],
): Response {
  return replyError(
    res,
    422,
    errors.map((e) => ({ code: ERROR_CODES.VALIDATION_ERROR, ...e })),
  );
}

export function replyRateLimit(
  res: Response,
  message = "Too many requests, please try again later.",
  code: ErrorCode | string = ERROR_CODES.RATE_LIMITED,
): Response {
  return replyError(res, 429, [{ code, message }]);
}

export function replyInternal(
  res: Response,
  message = "Internal Server Error",
): Response {
  return replyError(res, 500, [{ code: ERROR_CODES.INTERNAL_ERROR, message }]);
}

export function replyNotImplemented(
  res: Response,
  message = "Not implemented",
): Response {
  return replyError(res, 501, [{ code: ERROR_CODES.NOT_IMPLEMENTED, message }]);
}

// ─── Deprecation helpers (RFC 8594) ──────────────────────────────────────────

/** ISO date after which legacy endpoints will be removed. */
export const LEGACY_SUNSET_DATE = "2026-07-01";

export function addDeprecationHeaders(res: Response, successorPath?: string): void {
  res.set("Deprecation", "true");
  res.set("Sunset", new Date(LEGACY_SUNSET_DATE).toUTCString());
  if (successorPath) {
    res.set("Link", `<${successorPath}>; rel="successor-version"`);
  }
}

/**
 * Express middleware factory that stamps deprecation headers on every response
 * for a legacy endpoint and points consumers to the v1 successor path.
 *
 * Usage:
 *   app.get("/api/alerts", legacyEndpoint("/api/v1/alerts"), isAuthenticated, handler)
 */
export function legacyEndpoint(successorPath?: string) {
  return (_req: Request, res: Response, next: NextFunction): void => {
    addDeprecationHeaders(res, successorPath);
    next();
  };
}
