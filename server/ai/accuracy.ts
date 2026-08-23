import { pool } from "../db";
import type { AiDecisionAdjudication, AiAnalystDecision } from "@shared/schema";
import { ADJUDICATED_OUTCOMES, ADJUDICATION_SOURCES } from "@shared/schema";

export const ACCURACY_MINIMUM_SAMPLE = 20;

type QueryExecutor = {
  query<T extends Record<string, unknown>>(text: string, values?: unknown[]): Promise<{ rows: T[] }>;
};

export const AI_OUTCOME_CLASS_MAP = {
  true_positive: "malicious",
  auto_contained: "malicious",
  escalate_tier2: "malicious",
  escalate_tier3: "malicious",
  escalate_human: "malicious",
  needs_investigation: "malicious",
  false_positive: "benign",
  auto_resolved: "benign",
} as const;

export type PredictedClass = "malicious" | "benign";
export type AdjudicatedClass = "malicious" | "benign" | "inconclusive";

export function mapAiOutcome(outcome: string | null): PredictedClass | null {
  if (!outcome) return null;
  return AI_OUTCOME_CLASS_MAP[outcome as keyof typeof AI_OUTCOME_CLASS_MAP] ?? null;
}

export async function createAdjudication(
  input: {
    orgId: string;
    decisionId: string;
    adjudicatedOutcome: AdjudicatedClass;
    source: (typeof ADJUDICATION_SOURCES)[number];
    actorUserId?: string | null;
    rationale: string;
    isFinal: boolean;
  },
  executor: QueryExecutor = pool,
): Promise<AiDecisionAdjudication> {
  if (!ADJUDICATED_OUTCOMES.includes(input.adjudicatedOutcome)) throw new Error("Invalid adjudicated outcome");
  if (!ADJUDICATION_SOURCES.includes(input.source)) throw new Error("Invalid adjudication source");
  const result = await executor.query<AiDecisionAdjudication>(
    `INSERT INTO ai_decision_adjudications
      (org_id, decision_id, alert_id, adjudicated_outcome, source, actor_user_id, rationale, is_final)
     SELECT $1::varchar, d.id, d.alert_id, $3::text, $4::text, $5::varchar, $6::text, $7::boolean
     FROM ai_analyst_decisions d
     WHERE d.id = $2::varchar AND d.org_id = $1::varchar
     RETURNING id, org_id AS "orgId", decision_id AS "decisionId", alert_id AS "alertId",
       adjudicated_outcome AS "adjudicatedOutcome", source, actor_user_id AS "actorUserId",
       rationale, adjudicated_at AS "adjudicatedAt", is_final AS "isFinal", created_at AS "createdAt"`,
    [
      input.orgId,
      input.decisionId,
      input.adjudicatedOutcome,
      input.source,
      input.actorUserId ?? null,
      input.rationale,
      input.isFinal,
    ],
  );
  if (!result.rows[0]) throw new Error("Decision not found in organization");
  return result.rows[0];
}

export function selectLatestAdjudication(
  adjudications: Pick<AiDecisionAdjudication, "adjudicatedAt" | "isFinal" | "adjudicatedOutcome">[],
): {
  final: (typeof adjudications)[number] | null;
  provisional: (typeof adjudications)[number] | null;
} {
  const ordered = [...adjudications].sort(
    (a, b) => new Date(b.adjudicatedAt).getTime() - new Date(a.adjudicatedAt).getTime(),
  );
  const final = ordered.find((item) => item.isFinal) ?? null;
  return {
    final,
    provisional: final ? null : (ordered.find((item) => !item.isFinal) ?? null),
  };
}

type AccuracyDecision = Pick<AiAnalystDecision, "id" | "orgId" | "outcome" | "confidenceScore" | "createdAt">;

export interface AccuracyReport {
  window: { from: string; to: string };
  decisionsTotal: number;
  adjudicatedCount: number;
  finalCount: number;
  provisionalCount: number;
  adjudicationCoverage: number | null;
  insufficientData: boolean;
  minimumSample: { threshold: number; count: number; reason: string | null };
  matrix: { truePositive: number; trueNegative: number; falsePositive: number; falseNegative: number };
  rates: {
    agreementRate: number | null;
    agreementRateReason: string | null;
    precision: number | null;
    precisionReason: string | null;
    recall: number | null;
    recallReason: string | null;
  };
  inconclusiveCount: number;
  unmappedCount: number;
  calibration: {
    label: string;
    count: number;
    inconclusiveCount: number;
    observedMaliciousRate: number | null;
    bucketMidpoint: number;
    insufficientData: boolean;
  }[];
  disagreements: {
    decisionId: string;
    predictedClass: PredictedClass;
    adjudicatedClass: "malicious" | "benign";
    confidenceScore: number | null;
    createdAt: Date | null;
  }[];
}

function rate(numerator: number, denominator: number, reason: string): { value: number | null; reason: string | null } {
  return denominator === 0
    ? { value: null, reason }
    : { value: Number((numerator / denominator).toFixed(4)), reason: null };
}

export function calculateAccuracy(
  decisions: AccuracyDecision[],
  adjudications: AiDecisionAdjudication[],
  from: string,
  to: string,
  orgId: string,
): AccuracyReport {
  const scopedDecisions = decisions.filter((decision) => decision.orgId === orgId);
  const scopedAdjudications = adjudications.filter((adjudication) => adjudication.orgId === orgId);
  const byDecision = new Map<string, AiDecisionAdjudication[]>();
  for (const adjudication of scopedAdjudications) {
    const entries = byDecision.get(adjudication.decisionId) ?? [];
    entries.push(adjudication);
    byDecision.set(adjudication.decisionId, entries);
  }

  const selected = scopedDecisions
    .map((decision) => {
      const selection = selectLatestAdjudication(byDecision.get(decision.id) ?? []);
      const adjudication = selection.final ?? selection.provisional;
      return adjudication ? { decision, adjudication, final: !!selection.final } : null;
    })
    .filter((value): value is NonNullable<typeof value> => value !== null);
  const matrix = { truePositive: 0, trueNegative: 0, falsePositive: 0, falseNegative: 0 };
  const disagreements: AccuracyReport["disagreements"] = [];
  let inconclusiveCount = 0;
  let unmappedCount = 0;
  const calibration = Array.from({ length: 10 }, (_, index) => ({
    label: `${(index / 10).toFixed(1)}–${((index + 1) / 10).toFixed(1)}`,
    count: 0,
    inconclusiveCount: 0,
    malicious: 0,
    bucketMidpoint: Number((index / 10 + 0.05).toFixed(2)),
  }));

  for (const { decision, adjudication } of selected) {
    const isInconclusive = adjudication.adjudicatedOutcome === "inconclusive";
    if (isInconclusive) {
      inconclusiveCount++;
    } else {
      const predicted = mapAiOutcome(decision.outcome);
      if (!predicted) {
        unmappedCount++;
      } else {
        if (predicted === "malicious" && adjudication.adjudicatedOutcome === "malicious") matrix.truePositive++;
        if (predicted === "benign" && adjudication.adjudicatedOutcome === "benign") matrix.trueNegative++;
        if (predicted === "malicious" && adjudication.adjudicatedOutcome === "benign") matrix.falsePositive++;
        if (predicted === "benign" && adjudication.adjudicatedOutcome === "malicious") matrix.falseNegative++;
        if (predicted !== adjudication.adjudicatedOutcome) {
          disagreements.push({
            decisionId: decision.id,
            predictedClass: predicted,
            adjudicatedClass: adjudication.adjudicatedOutcome as "malicious" | "benign",
            confidenceScore: decision.confidenceScore,
            createdAt: decision.createdAt,
          });
        }
      }
    }
    if (decision.confidenceScore != null && decision.confidenceScore >= 0 && decision.confidenceScore <= 1) {
      const bucket = calibration[Math.min(9, Math.floor(decision.confidenceScore * 10))];
      if (isInconclusive) {
        bucket.inconclusiveCount++;
      } else {
        bucket.count++;
        if (adjudication.adjudicatedOutcome === "malicious") bucket.malicious++;
      }
    }
  }

  const adjudicatedCount = selected.length;
  const denominator = matrix.truePositive + matrix.trueNegative + matrix.falsePositive + matrix.falseNegative;
  const sufficient = adjudicatedCount >= ACCURACY_MINIMUM_SAMPLE;
  const agreement = rate(matrix.truePositive + matrix.trueNegative, denominator, "No classified adjudications");
  const precision = rate(
    matrix.truePositive,
    matrix.truePositive + matrix.falsePositive,
    "No predicted-malicious decisions",
  );
  const recall = rate(
    matrix.truePositive,
    matrix.truePositive + matrix.falseNegative,
    "No adjudicated-malicious decisions",
  );
  const reportRates = sufficient
    ? { agreementRate: agreement, precision, recall }
    : {
        agreementRate: { value: null, reason: `Fewer than ${ACCURACY_MINIMUM_SAMPLE} adjudicated decisions` },
        precision: { value: null, reason: `Fewer than ${ACCURACY_MINIMUM_SAMPLE} adjudicated decisions` },
        recall: { value: null, reason: `Fewer than ${ACCURACY_MINIMUM_SAMPLE} adjudicated decisions` },
      };

  return {
    window: { from, to },
    decisionsTotal: scopedDecisions.length,
    adjudicatedCount,
    finalCount: selected.filter((item) => item.final).length,
    provisionalCount: selected.filter((item) => !item.final).length,
    adjudicationCoverage:
      scopedDecisions.length === 0 ? null : Number((adjudicatedCount / scopedDecisions.length).toFixed(4)),
    insufficientData: !sufficient,
    minimumSample: {
      threshold: ACCURACY_MINIMUM_SAMPLE,
      count: adjudicatedCount,
      reason: sufficient ? null : `Fewer than ${ACCURACY_MINIMUM_SAMPLE} adjudicated decisions`,
    },
    matrix,
    rates: {
      agreementRate: reportRates.agreementRate.value,
      agreementRateReason: reportRates.agreementRate.reason,
      precision: reportRates.precision.value,
      precisionReason: reportRates.precision.reason,
      recall: reportRates.recall.value,
      recallReason: reportRates.recall.reason,
    },
    inconclusiveCount,
    unmappedCount,
    calibration: calibration.map((bucket) => ({
      label: bucket.label,
      count: bucket.count,
      inconclusiveCount: bucket.inconclusiveCount,
      observedMaliciousRate: bucket.count === 0 ? null : Number((bucket.malicious / bucket.count).toFixed(4)),
      bucketMidpoint: bucket.bucketMidpoint,
      insufficientData: bucket.count < 10,
    })),
    disagreements: disagreements.sort((a, b) => {
      const falseNegativeA = a.predictedClass === "benign" ? 0 : 1;
      const falseNegativeB = b.predictedClass === "benign" ? 0 : 1;
      if (falseNegativeA !== falseNegativeB) return falseNegativeA - falseNegativeB;
      return (b.createdAt?.getTime() ?? 0) - (a.createdAt?.getTime() ?? 0);
    }),
  };
}

export async function getAccuracyReport(orgId: string, from: string, to: string): Promise<AccuracyReport> {
  const decisionsResult = await pool.query<AccuracyDecision>(
    `SELECT id, org_id AS "orgId", outcome, confidence_score AS "confidenceScore", created_at AS "createdAt"
     FROM ai_analyst_decisions
     WHERE org_id = $1 AND created_at >= $2::timestamptz AND created_at < $3::timestamptz`,
    [orgId, from, to],
  );
  const adjudicationsResult = await pool.query<AiDecisionAdjudication>(
    `SELECT a.id, a.org_id AS "orgId", a.decision_id AS "decisionId", a.alert_id AS "alertId",
            a.adjudicated_outcome AS "adjudicatedOutcome", a.source, a.actor_user_id AS "actorUserId",
            a.rationale, a.adjudicated_at AS "adjudicatedAt", a.is_final AS "isFinal", a.created_at AS "createdAt"
     FROM ai_decision_adjudications a
     JOIN ai_analyst_decisions d ON d.id = a.decision_id AND d.org_id = a.org_id
     WHERE a.org_id = $1
       AND d.created_at >= $2::timestamptz
       AND d.created_at < $3::timestamptz`,
    [orgId, from, to],
  );
  return calculateAccuracy(decisionsResult.rows, adjudicationsResult.rows, from, to, orgId);
}
