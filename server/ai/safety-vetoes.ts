export interface GuardVetoMetadata {
  injectionScore: number;
  withheld?: boolean;
  schemaRetryUsed?: boolean;
  unverifiedCitations?: boolean;
  redactionRemovedContent?: boolean;
}

export function getGuardVetoes(guard: GuardVetoMetadata): string[] {
  const vetoes: string[] = [];
  if (guard.injectionScore > 0) vetoes.push("injection_detected");
  if (guard.withheld) vetoes.push("analysis_withheld");
  if (guard.schemaRetryUsed) vetoes.push("schema_retry_used");
  if (guard.unverifiedCitations) vetoes.push("unverified_citations");
  return vetoes;
}
