import { randomUUID } from "crypto";
import { AsyncLocalStorage } from "async_hooks";
import type { Request, Response, NextFunction } from "express";
import { logger } from "./logger";

const log = logger.child("tracing");

interface SpanContext {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  service: string;
  operation: string;
  startTime: number;
  attributes: Record<string, string | number | boolean>;
}

interface FinishedSpan {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  service: string;
  operation: string;
  startTimeMs: number;
  durationMs: number;
  status: "ok" | "error";
  attributes: Record<string, string | number | boolean>;
}

const traceStore = new AsyncLocalStorage<SpanContext>();

const MAX_TRACE_BUFFER = 1000;
const FLUSH_INTERVAL_MS = 30_000;
const spanBuffer: FinishedSpan[] = [];
let flushTimer: NodeJS.Timeout | null = null;

function generateId(): string {
  return randomUUID().replace(/-/g, "").slice(0, 16);
}

function generateTraceId(): string {
  return randomUUID().replace(/-/g, "");
}

export function currentSpan(): SpanContext | undefined {
  return traceStore.getStore();
}

export function currentTraceId(): string | undefined {
  return traceStore.getStore()?.traceId;
}

export function startSpan<T>(
  service: string,
  operation: string,
  fn: () => T,
  attributes?: Record<string, string | number | boolean>,
): T {
  const parent = traceStore.getStore();
  const span: SpanContext = {
    traceId: parent?.traceId ?? generateTraceId(),
    spanId: generateId(),
    parentSpanId: parent?.spanId,
    service,
    operation,
    startTime: Date.now(),
    attributes: { ...attributes },
  };

  return traceStore.run(span, () => {
    try {
      const result = fn();
      if (result instanceof Promise) {
        return (result as Promise<unknown>)
          .then((val) => {
            finishSpan(span, "ok");
            return val;
          })
          .catch((err) => {
            finishSpan(span, "error", err);
            throw err;
          }) as T;
      }
      finishSpan(span, "ok");
      return result;
    } catch (err) {
      finishSpan(span, "error", err);
      throw err;
    }
  });
}

function finishSpan(span: SpanContext, status: "ok" | "error", error?: unknown): void {
  const durationMs = Date.now() - span.startTime;
  const finished: FinishedSpan = {
    traceId: span.traceId,
    spanId: span.spanId,
    parentSpanId: span.parentSpanId,
    service: span.service,
    operation: span.operation,
    startTimeMs: span.startTime,
    durationMs,
    status,
    attributes: { ...span.attributes },
  };

  if (error) {
    finished.attributes.errorMessage = String((error as Error).message ?? error);
  }

  spanBuffer.push(finished);
  if (spanBuffer.length > MAX_TRACE_BUFFER) {
    spanBuffer.splice(0, spanBuffer.length - MAX_TRACE_BUFFER);
  }
}

export function addSpanAttribute(key: string, value: string | number | boolean): void {
  const span = traceStore.getStore();
  if (span) {
    span.attributes[key] = value;
  }
}

export function injectTraceHeaders(headers: Record<string, string>): Record<string, string> {
  const span = traceStore.getStore();
  if (span) {
    headers["x-trace-id"] = span.traceId;
    headers["x-span-id"] = span.spanId;
  }
  return headers;
}

export function extractTraceContext(headers: Record<string, string | string[] | undefined>): {
  traceId?: string;
  parentSpanId?: string;
} {
  const traceId = typeof headers["x-trace-id"] === "string" ? headers["x-trace-id"] : undefined;
  const parentSpanId = typeof headers["x-span-id"] === "string" ? headers["x-span-id"] : undefined;
  return { traceId, parentSpanId };
}

export function tracingMiddleware(req: Request, res: Response, next: NextFunction): void {
  const incoming = extractTraceContext(req.headers as Record<string, string | string[] | undefined>);
  const traceId = incoming.traceId ?? generateTraceId();
  const spanId = generateId();

  const span: SpanContext = {
    traceId,
    spanId,
    parentSpanId: incoming.parentSpanId,
    service: "http",
    operation: `${req.method} ${req.path}`,
    startTime: Date.now(),
    attributes: {
      "http.method": req.method,
      "http.url": req.path,
      "http.user_agent": (req.headers["user-agent"] as string) ?? "unknown",
    },
  };

  res.setHeader("x-trace-id", traceId);

  traceStore.run(span, () => {
    res.on("finish", () => {
      span.attributes["http.status_code"] = res.statusCode;
      const status = res.statusCode >= 500 ? "error" : "ok";
      finishSpan(span, status as "ok" | "error");
    });
    next();
  });
}

export function withTraceContext<T>(
  traceId: string,
  service: string,
  operation: string,
  fn: () => T,
  attributes?: Record<string, string | number | boolean>,
): T {
  const span: SpanContext = {
    traceId,
    spanId: generateId(),
    service,
    operation,
    startTime: Date.now(),
    attributes: { ...attributes },
  };
  return traceStore.run(span, () => {
    try {
      const result = fn();
      if (result instanceof Promise) {
        return (result as Promise<unknown>)
          .then((val) => {
            finishSpan(span, "ok");
            return val;
          })
          .catch((err) => {
            finishSpan(span, "error", err);
            throw err;
          }) as T;
      }
      finishSpan(span, "ok");
      return result;
    } catch (err) {
      finishSpan(span, "error", err);
      throw err;
    }
  });
}

function flushSpans(): void {
  if (spanBuffer.length === 0) return;

  const batch = [...spanBuffer];
  const errorSpans = batch.filter((s) => s.status === "error");
  const slowSpans = batch.filter((s) => s.durationMs > 5000);

  if (errorSpans.length > 0) {
    log.warn("Trace flush: error spans detected", {
      total: batch.length,
      errors: errorSpans.length,
      errorTraces: errorSpans.slice(0, 5).map((s) => ({
        traceId: s.traceId,
        operation: s.operation,
        durationMs: s.durationMs,
        error: s.attributes.errorMessage,
      })),
    });
  }

  if (slowSpans.length > 0) {
    log.info("Trace flush: slow spans", {
      count: slowSpans.length,
      spans: slowSpans.slice(0, 5).map((s) => ({
        traceId: s.traceId,
        operation: s.operation,
        durationMs: s.durationMs,
      })),
    });
  }

  log.debug("Trace flush", { spanCount: batch.length });
}

export function getRecentTraces(limit: number = 50): FinishedSpan[] {
  return spanBuffer.slice(-limit);
}

export function getTraceById(traceId: string): FinishedSpan[] {
  return spanBuffer.filter((s) => s.traceId === traceId);
}

export function getTraceStats(): {
  bufferedSpans: number;
  flushIntervalMs: number;
  maxBuffer: number;
} {
  return {
    bufferedSpans: spanBuffer.length,
    flushIntervalMs: FLUSH_INTERVAL_MS,
    maxBuffer: MAX_TRACE_BUFFER,
  };
}

export function startTracingFlush(): void {
  if (flushTimer) return;
  flushTimer = setInterval(flushSpans, FLUSH_INTERVAL_MS);
  log.info("Tracing flush started", { intervalMs: FLUSH_INTERVAL_MS });
}

export function stopTracingFlush(): void {
  if (flushTimer) {
    clearInterval(flushTimer);
    flushTimer = null;
  }
  flushSpans();
}
