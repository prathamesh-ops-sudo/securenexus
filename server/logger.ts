import { randomUUID } from "crypto";
import type { Request, Response, NextFunction } from "express";
import { AsyncLocalStorage } from "async_hooks";

type LogLevel = "debug" | "info" | "warn" | "error";

interface LogContext {
  requestId?: string;
  orgId?: string;
  userId?: string;
  route?: string;
  method?: string;
  jobId?: string;
  outboxEventId?: string;
  [key: string]: unknown;
}

interface LogEntry {
  timestamp: string;
  level: LogLevel;
  message: string;
  source: string;
  context: LogContext;
}

const LEVEL_PRIORITY: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

const MIN_LEVEL: LogLevel =
  process.env.NODE_ENV === "development" || process.env.NODE_ENV === "test"
    ? "debug"
    : "info";

const REDACT_PATTERNS: Array<{ pattern: RegExp; replacement: string }> = [
  { pattern: /("?password"?\s*[:=]\s*)"[^"]*"/gi, replacement: '$1"[REDACTED]"' },
  { pattern: /("?secret"?\s*[:=]\s*)"[^"]*"/gi, replacement: '$1"[REDACTED]"' },
  { pattern: /("?token"?\s*[:=]\s*)"[^"]*"/gi, replacement: '$1"[REDACTED]"' },
  { pattern: /("?authorization"?\s*[:=]\s*)"[^"]*"/gi, replacement: '$1"[REDACTED]"' },
  { pattern: /("?cookie"?\s*[:=]\s*)"[^"]*"/gi, replacement: '$1"[REDACTED]"' },
  { pattern: /("?apiKey"?\s*[:=]\s*)"[^"]*"/gi, replacement: '$1"[REDACTED]"' },
  { pattern: /("?api_key"?\s*[:=]\s*)"[^"]*"/gi, replacement: '$1"[REDACTED]"' },
  { pattern: /("?x-api-key"?\s*[:=]\s*)"[^"]*"/gi, replacement: '$1"[REDACTED]"' },
  { pattern: /("?webhookSecret"?\s*[:=]\s*)"[^"]*"/gi, replacement: '$1"[REDACTED]"' },
  { pattern: /("?sessionSecret"?\s*[:=]\s*)"[^"]*"/gi, replacement: '$1"[REDACTED]"' },
  { pattern: /("?databaseUrl"?\s*[:=]\s*)"[^"]*"/gi, replacement: '$1"[REDACTED]"' },
  { pattern: /("?DATABASE_URL"?\s*[:=]\s*)"[^"]*"/gi, replacement: '$1"[REDACTED]"' },
  { pattern: /("?accessKeyId"?\s*[:=]\s*)"[^"]*"/gi, replacement: '$1"[REDACTED]"' },
  { pattern: /("?secretAccessKey"?\s*[:=]\s*)"[^"]*"/gi, replacement: '$1"[REDACTED]"' },
  { pattern: /("?connect\.sid"?\s*[:=]\s*)[^\s;,}]+/gi, replacement: "$1[REDACTED]" },
  { pattern: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/g, replacement: "Bearer [REDACTED]" },
  { pattern: /snx_[a-f0-9]{64}/g, replacement: "snx_[REDACTED]" },
  { pattern: /ghp_[A-Za-z0-9]{36}/g, replacement: "ghp_[REDACTED]" },
  { pattern: /AKIA[A-Z0-9]{16}/g, replacement: "AKIA[REDACTED]" },
];

function redact(input: string): string {
  let result = input;
  for (const { pattern, replacement } of REDACT_PATTERNS) {
    pattern.lastIndex = 0;
    result = result.replace(pattern, replacement);
  }
  return result;
}

const contextStore = new AsyncLocalStorage<LogContext>();

export function currentContext(): LogContext {
  return contextStore.getStore() ?? {};
}

function emit(level: LogLevel, source: string, message: string, extra?: Record<string, unknown>): void {
  if (LEVEL_PRIORITY[level] < LEVEL_PRIORITY[MIN_LEVEL]) return;

  const ctx = { ...currentContext(), ...extra };

  const entry: LogEntry = {
    timestamp: new Date().toISOString(),
    level,
    message: redact(message),
    source,
    context: ctx,
  };

  const serialized = redact(JSON.stringify(entry));

  switch (level) {
    case "error":
      process.stderr.write(serialized + "\n");
      break;
    case "warn":
      process.stderr.write(serialized + "\n");
      break;
    default:
      process.stdout.write(serialized + "\n");
      break;
  }
}

function createChild(source: string) {
  return {
    debug(message: string, extra?: Record<string, unknown>) {
      emit("debug", source, message, extra);
    },
    info(message: string, extra?: Record<string, unknown>) {
      emit("info", source, message, extra);
    },
    warn(message: string, extra?: Record<string, unknown>) {
      emit("warn", source, message, extra);
    },
    error(message: string, extra?: Record<string, unknown>) {
      emit("error", source, message, extra);
    },
  };
}

export const logger = {
  child: createChild,

  debug(message: string, extra?: Record<string, unknown>) {
    emit("debug", "app", message, extra);
  },
  info(message: string, extra?: Record<string, unknown>) {
    emit("info", "app", message, extra);
  },
  warn(message: string, extra?: Record<string, unknown>) {
    emit("warn", "app", message, extra);
  },
  error(message: string, extra?: Record<string, unknown>) {
    emit("error", "app", message, extra);
  },
};

export function correlationMiddleware(req: Request, res: Response, next: NextFunction): void {
  const requestId = (req.headers["x-request-id"] as string) || randomUUID();
  const user = (req as any).user;
  const orgId: string | undefined = user?.orgId ?? (req as any).orgId;
  const userId: string | undefined = user?.id;

  res.setHeader("x-request-id", requestId);

  const ctx: LogContext = {
    requestId,
    ...(orgId ? { orgId } : {}),
    ...(userId ? { userId } : {}),
    route: req.path,
    method: req.method,
  };

  contextStore.run(ctx, () => next());
}

export function requestLogger(req: Request, res: Response, next: NextFunction): void {
  const start = Date.now();
  const log = logger.child("http");

  res.on("finish", () => {
    const duration = Date.now() - start;
    if (!req.path.startsWith("/api")) return;

    const level: LogLevel = res.statusCode >= 500 ? "error" : res.statusCode >= 400 ? "warn" : "info";
    emit(level, "http", `${req.method} ${req.path} ${res.statusCode} ${duration}ms`, {
      statusCode: res.statusCode,
      durationMs: duration,
      contentLength: res.getHeader("content-length"),
    });
  });

  next();
}

export function withJobContext<T>(jobId: string, jobType: string, fn: () => T): T {
  return contextStore.run({ jobId, jobType }, fn);
}

export function withOutboxContext<T>(outboxEventId: string, eventType: string, fn: () => T): T {
  return contextStore.run({ outboxEventId, eventType }, fn);
}
