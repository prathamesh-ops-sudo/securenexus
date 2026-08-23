export const AI_INFERENCE_RETENTION_DAYS = 30;

export type ProofRetentionClass =
  | "decisions"
  | "evidence"
  | "inference"
  | "redaction_receipts"
  | "adjudications"
  | "replay_runs"
  | "replay_reports";

export interface ProofRetentionStatus {
  effectiveRetentionDays: number;
  fullExportHorizon: string;
  completeExportAvailable: boolean;
  classes: Array<{
    recordClass: ProofRetentionClass;
    retentionDays: number | null;
    enforcement: "enforced" | "not_enforced";
  }>;
}

export function getProofRetentionStatus(createdAt: Date, now = new Date()): ProofRetentionStatus {
  const horizon = new Date(createdAt.getTime() + AI_INFERENCE_RETENTION_DAYS * 24 * 60 * 60 * 1000);
  return {
    effectiveRetentionDays: AI_INFERENCE_RETENTION_DAYS,
    fullExportHorizon: horizon.toISOString(),
    completeExportAvailable: now <= horizon,
    classes: [
      { recordClass: "decisions", retentionDays: null, enforcement: "not_enforced" },
      { recordClass: "evidence", retentionDays: null, enforcement: "not_enforced" },
      { recordClass: "inference", retentionDays: AI_INFERENCE_RETENTION_DAYS, enforcement: "enforced" },
      { recordClass: "redaction_receipts", retentionDays: null, enforcement: "not_enforced" },
      { recordClass: "adjudications", retentionDays: null, enforcement: "not_enforced" },
      { recordClass: "replay_runs", retentionDays: null, enforcement: "not_enforced" },
      { recordClass: "replay_reports", retentionDays: null, enforcement: "not_enforced" },
    ],
  };
}
