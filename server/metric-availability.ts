export function percentageOrNull(numerator: number, denominator: number): number | null {
  return denominator > 0 ? Math.round((numerator / denominator) * 100) : null;
}

export function noDataReason(label: string, denominator: number): string | null {
  return denominator > 0 ? null : `No ${label} have been recorded for this organization.`;
}
