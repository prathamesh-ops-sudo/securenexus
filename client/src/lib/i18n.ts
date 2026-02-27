const DEFAULT_LOCALE = "en-US";
const DEFAULT_TIMEZONE = "UTC";

let currentLocale: string = DEFAULT_LOCALE;
let currentTimezone: string = DEFAULT_TIMEZONE;

export function setLocale(locale: string) {
  currentLocale = locale;
}

export function getLocale(): string {
  return currentLocale;
}

export function setTimezone(tz: string) {
  currentTimezone = tz;
}

export function getTimezone(): string {
  return currentTimezone;
}

export function initLocaleFromOrg(org: { locale?: string | null; timezone?: string | null } | null | undefined) {
  if (org?.locale) currentLocale = org.locale;
  if (org?.timezone) currentTimezone = org.timezone;
}

function toDate(value: string | Date | null | undefined): Date | null {
  if (!value) return null;
  return value instanceof Date ? value : new Date(value);
}

export function formatDateTime(
  value: string | Date | null | undefined,
  options?: { timezone?: string; locale?: string },
): string {
  const d = toDate(value);
  if (!d) return "N/A";
  const tz = options?.timezone ?? currentTimezone;
  const loc = options?.locale ?? currentLocale;
  return d.toLocaleString(loc, {
    timeZone: tz,
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function formatDateShort(
  value: string | Date | null | undefined,
  options?: { timezone?: string; locale?: string },
): string {
  const d = toDate(value);
  if (!d) return "N/A";
  const tz = options?.timezone ?? currentTimezone;
  const loc = options?.locale ?? currentLocale;
  return d.toLocaleDateString(loc, {
    timeZone: tz,
    month: "short",
    day: "numeric",
  });
}

export function formatDateFull(
  value: string | Date | null | undefined,
  options?: { timezone?: string; locale?: string },
): string {
  const d = toDate(value);
  if (!d) return "N/A";
  const tz = options?.timezone ?? currentTimezone;
  const loc = options?.locale ?? currentLocale;
  return d.toLocaleDateString(loc, {
    timeZone: tz,
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

export function formatTime(
  value: string | Date | null | undefined,
  options?: { timezone?: string; locale?: string },
): string {
  const d = toDate(value);
  if (!d) return "N/A";
  const tz = options?.timezone ?? currentTimezone;
  const loc = options?.locale ?? currentLocale;
  return d.toLocaleTimeString(loc, {
    timeZone: tz,
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function formatTimestamp(
  value: string | Date | null | undefined,
  options?: { timezone?: string; locale?: string },
): string {
  return formatDateTime(value, options);
}

const MINUTE_MS = 60_000;
const HOUR_MS = 3_600_000;
const DAY_MS = 86_400_000;
const WEEK_MS = 604_800_000;

export function formatRelativeTime(
  value: string | Date | null | undefined,
  options?: { timezone?: string; locale?: string },
): string {
  const d = toDate(value);
  if (!d) return "N/A";
  const now = new Date();
  const diffMs = now.getTime() - d.getTime();
  const absDiff = Math.abs(diffMs);

  if (absDiff < MINUTE_MS) return "just now";
  if (absDiff < HOUR_MS) return `${Math.floor(absDiff / MINUTE_MS)}m ago`;
  if (absDiff < DAY_MS) return `${Math.floor(absDiff / HOUR_MS)}h ago`;
  if (absDiff < WEEK_MS) return `${Math.floor(absDiff / DAY_MS)}d ago`;
  return formatDateShort(value, options);
}

export function formatNumber(value: number, options?: { locale?: string; maximumFractionDigits?: number }): string {
  const loc = options?.locale ?? currentLocale;
  return value.toLocaleString(loc, {
    maximumFractionDigits: options?.maximumFractionDigits,
  });
}

export function formatPercent(value: number, options?: { locale?: string; maximumFractionDigits?: number }): string {
  const loc = options?.locale ?? currentLocale;
  const fractionDigits = options?.maximumFractionDigits ?? 1;
  return (value / 100).toLocaleString(loc, {
    style: "percent",
    maximumFractionDigits: fractionDigits,
  });
}

export function formatChartDateLabel(dateStr: string, options?: { timezone?: string; locale?: string }): string {
  const d = new Date(dateStr + "T00:00:00");
  const tz = options?.timezone ?? currentTimezone;
  const loc = options?.locale ?? currentLocale;
  return d.toLocaleDateString(loc, {
    timeZone: tz,
    month: "short",
    day: "numeric",
  });
}

export const SUPPORTED_LOCALES = [
  { value: "en-US", label: "English (US)" },
  { value: "en-GB", label: "English (UK)" },
  { value: "de-DE", label: "Deutsch" },
  { value: "fr-FR", label: "Français" },
  { value: "es-ES", label: "Español" },
  { value: "pt-BR", label: "Português (BR)" },
  { value: "ja-JP", label: "日本語" },
  { value: "ko-KR", label: "한국어" },
  { value: "zh-CN", label: "中文 (简体)" },
] as const;

export const COMMON_TIMEZONES = [
  { value: "UTC", label: "UTC" },
  { value: "America/New_York", label: "Eastern Time (US)" },
  { value: "America/Chicago", label: "Central Time (US)" },
  { value: "America/Denver", label: "Mountain Time (US)" },
  { value: "America/Los_Angeles", label: "Pacific Time (US)" },
  { value: "America/Sao_Paulo", label: "São Paulo" },
  { value: "Europe/London", label: "London" },
  { value: "Europe/Berlin", label: "Berlin" },
  { value: "Europe/Paris", label: "Paris" },
  { value: "Asia/Kolkata", label: "India (IST)" },
  { value: "Asia/Singapore", label: "Singapore" },
  { value: "Asia/Tokyo", label: "Tokyo" },
  { value: "Asia/Shanghai", label: "Shanghai" },
  { value: "Asia/Seoul", label: "Seoul" },
  { value: "Australia/Sydney", label: "Sydney" },
  { value: "Pacific/Auckland", label: "Auckland" },
] as const;
