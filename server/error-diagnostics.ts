import { redactLogText } from "./logger";

export interface DatabaseErrorDiagnostics {
  code?: string;
  detail?: string;
  constraint?: string;
  column?: string;
}

type ErrorRecord = Record<string, unknown>;

function asRecord(value: unknown): ErrorRecord | null {
  return value && typeof value === "object" ? (value as ErrorRecord) : null;
}

function redactDiagnosticText(value: string): string {
  return redactLogText(value)
    .replace(/Failing row contains\s+\([^)]*\)/gi, "Failing row contains [REDACTED]")
    .replace(/(Key\s+\([^)]*\)=)\([^)]*\)/gi, "$1[REDACTED]")
    .replace(/((?:api[_-]?key|token|password|secret|authorization|cookie)\s*[:=]\s*)[^\s,;)]+/gi, "$1[REDACTED]");
}

function safeString(value: unknown, redactDetail: boolean = false): string | undefined {
  if (typeof value !== "string" || value.length === 0) return undefined;
  return redactDetail ? redactDiagnosticText(value) : redactLogText(value);
}

export function getDatabaseErrorDiagnostics(error: unknown): DatabaseErrorDiagnostics {
  let current: unknown = error;
  const diagnostics: DatabaseErrorDiagnostics = {};
  for (let depth = 0; depth < 5; depth++) {
    const record = asRecord(current);
    if (!record) break;
    diagnostics.code ??= safeString(record.code);
    diagnostics.detail ??= safeString(record.detail, true);
    diagnostics.constraint ??= safeString(record.constraint);
    diagnostics.column ??= safeString(record.column);
    current = record.cause;
  }
  return diagnostics;
}
