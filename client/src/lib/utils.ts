import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

const BYTE_UNITS = ["B", "KB", "MB", "GB", "TB", "PB"] as const;

/**
 * Format a byte count as a human-readable binary-unit string.
 *
 * Uses base-1024 units (B/KB/MB/GB/TB/PB) with one decimal place, matching the
 * historical behaviour of per-page copies of this helper across the dashboard.
 */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const k = 1024;
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), BYTE_UNITS.length - 1);
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${BYTE_UNITS[i]}`;
}

/**
 * Shorten a chain-of-custody / audit hash for display.
 *
 * Preserves the literal string "GENESIS" (case-insensitive) and returns an
 * em-dash placeholder for nullish input, matching the evidence-chain pages.
 */
export function truncateHash(hash: string | null | undefined): string {
  if (!hash) return "\u2014";
  if (hash === "GENESIS" || hash === "genesis") return "GENESIS";
  return `${hash.slice(0, 8)}\u2026${hash.slice(-6)}`;
}
