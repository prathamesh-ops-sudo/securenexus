import { logger } from "./logger";

const DEFAULT_TIMEZONE = "UTC";

const HOUR_MS = 3_600_000;
const DAY_MS = 86_400_000;

export function isValidTimezone(tz: string): boolean {
  try {
    Intl.DateTimeFormat(undefined, { timeZone: tz });
    return true;
  } catch {
    return false;
  }
}

export function safeTimezone(tz: string | null | undefined): string {
  if (!tz) return DEFAULT_TIMEZONE;
  if (isValidTimezone(tz)) return tz;
  logger.child("timezone").warn(`Invalid timezone "${tz}", falling back to UTC`);
  return DEFAULT_TIMEZONE;
}

export function nowInTimezone(tz: string): Date {
  const safeTz = safeTimezone(tz);
  const formatter = new Intl.DateTimeFormat("en-US", {
    timeZone: safeTz,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
  const parts = formatter.formatToParts(new Date());
  const get = (type: string) => parts.find((p) => p.type === type)?.value ?? "0";
  return new Date(`${get("year")}-${get("month")}-${get("day")}T${get("hour")}:${get("minute")}:${get("second")}Z`);
}

export function formatInTimezone(
  date: Date | string | null | undefined,
  tz: string | null | undefined,
  options?: Intl.DateTimeFormatOptions,
): string {
  if (!date) return "N/A";
  const d = typeof date === "string" ? new Date(date) : date;
  const safeTz = safeTimezone(tz);
  const defaultOptions: Intl.DateTimeFormatOptions = {
    timeZone: safeTz,
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  };
  return d.toLocaleString("en-US", { ...defaultOptions, ...options });
}

export function startOfDayInTimezone(date: Date, tz: string): Date {
  const safeTz = safeTimezone(tz);
  const formatter = new Intl.DateTimeFormat("en-US", {
    timeZone: safeTz,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour12: false,
  });
  const parts = formatter.formatToParts(date);
  const get = (type: string) => parts.find((p) => p.type === type)?.value ?? "0";
  return new Date(`${get("year")}-${get("month")}-${get("day")}T00:00:00Z`);
}

export function endOfDayInTimezone(date: Date, tz: string): Date {
  const start = startOfDayInTimezone(date, tz);
  return new Date(start.getTime() + DAY_MS - 1);
}

export function calculateNextRunTimeInTimezone(cadence: string, tz: string | null | undefined): Date {
  const now = nowInTimezone(safeTimezone(tz));
  switch (cadence) {
    case "daily":
      return new Date(now.getTime() + DAY_MS);
    case "weekly":
      return new Date(now.getTime() + 7 * DAY_MS);
    case "biweekly":
      return new Date(now.getTime() + 14 * DAY_MS);
    case "monthly": {
      const d = new Date(now);
      d.setMonth(d.getMonth() + 1);
      return d;
    }
    case "quarterly": {
      const d = new Date(now);
      d.setMonth(d.getMonth() + 3);
      return d;
    }
    default:
      return new Date(now.getTime() + 7 * DAY_MS);
  }
}

export function isSLABreached(createdAt: Date | string, targetHours: number, tz: string | null | undefined): boolean {
  const created = typeof createdAt === "string" ? new Date(createdAt) : createdAt;
  const deadlineMs = created.getTime() + targetHours * HOUR_MS;
  const currentMs = nowInTimezone(safeTimezone(tz)).getTime();
  return currentMs > deadlineMs;
}

export function slaRemainingMs(createdAt: Date | string, targetHours: number, tz: string | null | undefined): number {
  const created = typeof createdAt === "string" ? new Date(createdAt) : createdAt;
  const deadlineMs = created.getTime() + targetHours * HOUR_MS;
  const currentMs = nowInTimezone(safeTimezone(tz)).getTime();
  return deadlineMs - currentMs;
}

export function getTimezoneAbbreviation(tz: string): string {
  const safeTz = safeTimezone(tz);
  const formatter = new Intl.DateTimeFormat("en-US", {
    timeZone: safeTz,
    timeZoneName: "short",
  });
  const parts = formatter.formatToParts(new Date());
  return parts.find((p) => p.type === "timeZoneName")?.value ?? safeTz;
}
