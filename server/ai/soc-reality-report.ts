import { pool } from "../db";
import { mapAiOutcome, selectLatestAdjudication } from "./accuracy";

const MINIMUM_RATE_SAMPLE = 20;

export interface SocRealityReport {
  generatedAt: string;
  runId: string;
  window: { from: string; to: string };
  partialCoverage: boolean;
  alertsInWindow: { total: number; bySource: Array<{ source: string; count: number }> };
  replayCoverage: {
    replayed: number;
    inWindow: number;
    rate: number | null;
    rateReason: string | null;
  };
  dispositionMix: {
    counts: Record<string, number>;
    abstentionCount: number;
    verdictBelowActionThresholdCount: number;
    confidenceUnavailableCount: number;
    decisionIds: string[];
  };
  autoCloseCandidates: {
    count: number | null;
    threshold: number | null;
    decisionIds: string[];
    unavailableReason: string | null;
  };
  humanAgreement: {
    agreed: number;
    definitive: number;
    coverage: { adjudicated: number; replayed: number };
    rate: number | null;
    rateReason: string | null;
  };
  mttrBaseline: {
    averageMinutes: number | null;
    sampleSize: number;
    unresolvedExcluded: number;
    unavailableReason: string | null;
    measurementDefinition: string;
  };
  whatWeCouldNotSee: {
    replayedDecisions: number;
    retrievalUnavailable: number;
    retrievalNotAttempted: number;
    zeroEvidenceRows: number;
    decisionIds: string[];
  };
  attackCoverage: {
    tactics: string[];
    techniques: string[];
    absentStatement: string;
  };
  runCost: {
    inputTokens: number | null;
    outputTokens: number | null;
    costUsd: number | null;
    unmeasuredInvocations: number;
  };
}

type DecisionRow = {
  id: string;
  outcome: string | null;
  confidenceScore: number | null;
  safetyVetoes: unknown;
  retrievalStatus: string | null;
};

function parseJsonArray(value: unknown): unknown[] {
  if (Array.isArray(value)) return value;
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }
  return [];
}

function gatedRate(numerator: number, denominator: number): { rate: number | null; rateReason: string | null } {
  if (denominator < MINIMUM_RATE_SAMPLE) {
    return {
      rate: null,
      rateReason: `Rate withheld until ${MINIMUM_RATE_SAMPLE} items; denominator is ${denominator}.`,
    };
  }
  return { rate: Number((numerator / denominator).toFixed(4)), rateReason: null };
}

export async function generateSocRealityReport(
  orgId: string,
  run: {
    id: string;
    fromAt: Date;
    toAt: Date;
    source: string | null;
    severity: string | null;
    status: string;
    totalCount: number;
    processedCount: number;
  },
): Promise<SocRealityReport> {
  const alertFilters = ["org_id = $1", "detected_at >= $2", "detected_at < $3"];
  const alertValues: unknown[] = [orgId, run.fromAt, run.toAt];
  if (run.source) {
    alertValues.push(run.source);
    alertFilters.push(`source = $${alertValues.length}`);
  }
  if (run.severity) {
    alertValues.push(run.severity);
    alertFilters.push(`severity = $${alertValues.length}`);
  }
  const alertWhere = alertFilters.join(" AND ");
  const [alerts, decisions, adjudications, evidence, invocations, policy] = await Promise.all([
    pool.query<{ source: string; count: string }>(
      `SELECT COALESCE(source, 'unknown') AS source, COUNT(*)::text AS count
       FROM alerts
       WHERE ${alertWhere}
       GROUP BY COALESCE(source, 'unknown') ORDER BY source`,
      alertValues,
    ),
    pool.query<DecisionRow>(
      `SELECT id, outcome, confidence_score AS "confidenceScore", safety_vetoes AS "safetyVetoes",
              retrieval_status AS "retrievalStatus"
       FROM ai_analyst_decisions
       WHERE org_id = $1 AND replay_run_id = $2`,
      [orgId, run.id],
    ),
    pool.query<{
      decisionId: string;
      adjudicatedOutcome: string;
      adjudicatedAt: Date;
      isFinal: boolean;
    }>(
      `SELECT decision_id AS "decisionId", adjudicated_outcome AS "adjudicatedOutcome",
              adjudicated_at AS "adjudicatedAt", is_final AS "isFinal"
       FROM ai_decision_adjudications
       WHERE org_id = $1
         AND decision_id IN (
           SELECT id FROM ai_analyst_decisions WHERE org_id = $1 AND replay_run_id = $2
         )
       ORDER BY adjudicated_at DESC`,
      [orgId, run.id],
    ),
    pool.query<{ decisionId: string; count: string }>(
      `SELECT decision_id AS "decisionId", COUNT(*)::text AS count
       FROM ai_decision_evidence
       WHERE org_id = $1
         AND decision_id IN (
           SELECT id FROM ai_analyst_decisions WHERE org_id = $1 AND replay_run_id = $2
         )
       GROUP BY decision_id`,
      [orgId, run.id],
    ),
    pool.query<{ inputTokens: string | null; outputTokens: string | null; costUsd: string | null; unmeasured: string }>(
      `SELECT SUM(input_tokens)::text AS "inputTokens", SUM(output_tokens)::text AS "outputTokens",
              SUM(cost_estimate_usd)::text AS "costUsd",
              COUNT(*) FILTER (
                WHERE input_tokens IS NULL OR output_tokens IS NULL OR cost_estimate_usd IS NULL OR latency_ms IS NULL
              )::text AS unmeasured
       FROM ai_inference_log
       WHERE org_id = $1
         AND decision_id IN (
           SELECT id FROM ai_analyst_decisions WHERE org_id = $1 AND replay_run_id = $2
         )`,
      [orgId, run.id],
    ),
    pool.query<{ threshold: string | null }>(
      `SELECT MIN(confidence_threshold)::text AS threshold
       FROM auto_response_policies
       WHERE org_id = $1 AND status = 'active'`,
      [orgId],
    ),
  ]);
  const mttr = await pool.query<{ averageMinutes: string | null; sampleSize: string; unresolvedExcluded: string }>(
    `SELECT AVG(EXTRACT(EPOCH FROM (i.resolved_at - a.created_at)) / 60)::text AS "averageMinutes",
            COUNT(*) FILTER (WHERE i.resolved_at IS NOT NULL)::text AS "sampleSize",
            COUNT(*) FILTER (WHERE i.resolved_at IS NULL)::text AS "unresolvedExcluded"
     FROM alerts a
     LEFT JOIN incidents i ON i.id = a.incident_id AND i.org_id = a.org_id
     WHERE a.${alertWhere}`,
    alertValues,
  );
  const attack = await pool.query<{ tactics: string[] | null; techniques: string[] | null }>(
    `SELECT ARRAY_AGG(DISTINCT a.mitre_tactic) FILTER (WHERE a.mitre_tactic IS NOT NULL) AS tactics,
            ARRAY_AGG(DISTINCT a.mitre_technique) FILTER (WHERE a.mitre_technique IS NOT NULL) AS techniques
     FROM alerts a
     WHERE a.${alertWhere}`,
    alertValues,
  );

  const decisionRows = decisions.rows;
  const decisionIds = decisionRows.map((decision) => decision.id);
  const alertCounts = alerts.rows.map((row) => ({ source: row.source, count: Number(row.count) }));
  const inWindow = alertCounts.reduce((sum, row) => sum + row.count, 0);
  const coverageRate = gatedRate(run.processedCount, inWindow);
  const thresholdValue = policy.rows[0]?.threshold;
  const threshold = thresholdValue == null ? null : Number(thresholdValue);
  const counts: Record<string, number> = {};
  let abstentionCount = 0;
  let verdictBelowActionThresholdCount = 0;
  let confidenceUnavailableCount = 0;
  const autoCloseIds: string[] = [];
  for (const decision of decisionRows) {
    if (decision.outcome) counts[decision.outcome] = (counts[decision.outcome] ?? 0) + 1;
    const mapped = mapAiOutcome(decision.outcome);
    const belowThreshold =
      threshold != null && decision.confidenceScore != null && decision.confidenceScore < threshold;
    if (!mapped) abstentionCount++;
    if (belowThreshold) verdictBelowActionThresholdCount++;
    if (mapped && decision.confidenceScore == null) confidenceUnavailableCount++;
    const vetoes = parseJsonArray(decision.safetyVetoes);
    if (
      threshold != null &&
      mapped === "benign" &&
      decision.confidenceScore != null &&
      !belowThreshold &&
      vetoes.length === 0
    )
      autoCloseIds.push(decision.id);
  }

  const adjudicationsByDecision = new Map<string, typeof adjudications.rows>();
  for (const row of adjudications.rows) {
    const entries = adjudicationsByDecision.get(row.decisionId) ?? [];
    entries.push(row);
    adjudicationsByDecision.set(row.decisionId, entries);
  }
  const latestAdjudication = new Map(
    Array.from(adjudicationsByDecision.entries()).map(([decisionId, rows]) => {
      const selection = selectLatestAdjudication(rows);
      return [decisionId, selection.final?.adjudicatedOutcome ?? selection.provisional?.adjudicatedOutcome ?? null];
    }),
  );
  let agreed = 0;
  let definitive = 0;
  for (const decision of decisionRows) {
    const adjudicated = latestAdjudication.get(decision.id);
    const predicted = mapAiOutcome(decision.outcome);
    if (!adjudicated || adjudicated === "inconclusive" || !predicted) continue;
    definitive++;
    if (predicted === adjudicated) agreed++;
  }
  const agreementRate = gatedRate(agreed, definitive);
  const evidenceCounts = new Map(evidence.rows.map((row) => [row.decisionId, Number(row.count)]));
  const couldNotSeeIds = decisionRows
    .filter(
      (decision) =>
        decision.retrievalStatus === "unavailable" ||
        decision.retrievalStatus === "not_attempted" ||
        !evidenceCounts.get(decision.id),
    )
    .map((decision) => decision.id);
  const retrievalUnavailable = decisionRows.filter((decision) => decision.retrievalStatus === "unavailable").length;
  const retrievalNotAttempted = decisionRows.filter((decision) => decision.retrievalStatus === "not_attempted").length;
  const zeroEvidenceRows = decisionRows.filter((decision) => !evidenceCounts.get(decision.id)).length;
  const mttrRow = mttr.rows[0];
  const averageMinutes = mttrRow?.averageMinutes == null ? null : Number(mttrRow.averageMinutes);
  const sampleSize = Number(mttrRow?.sampleSize ?? 0);
  const unresolvedExcluded = Number(mttrRow?.unresolvedExcluded ?? 0);
  const cost = invocations.rows[0];
  const metric = (value: string | null | undefined): number | null => (value == null ? null : Number(value));
  const tactics = attack.rows[0]?.tactics ?? [];
  const techniques = attack.rows[0]?.techniques ?? [];

  return {
    generatedAt: new Date().toISOString(),
    runId: run.id,
    window: { from: run.fromAt.toISOString(), to: run.toAt.toISOString() },
    partialCoverage: run.processedCount < inWindow || run.status !== "completed",
    alertsInWindow: { total: inWindow, bySource: alertCounts },
    replayCoverage: {
      replayed: run.processedCount,
      inWindow,
      rate: coverageRate.rate,
      rateReason: coverageRate.rateReason,
    },
    dispositionMix: {
      counts,
      abstentionCount,
      verdictBelowActionThresholdCount,
      confidenceUnavailableCount,
      decisionIds,
    },
    autoCloseCandidates:
      threshold == null
        ? {
            count: null,
            threshold: null,
            decisionIds: [],
            unavailableReason: "Unavailable: no active auto-response policy is configured for this tenant.",
          }
        : { count: autoCloseIds.length, threshold, decisionIds: autoCloseIds, unavailableReason: null },
    humanAgreement: {
      agreed,
      definitive,
      coverage: { adjudicated: latestAdjudication.size, replayed: decisionRows.length },
      rate: agreementRate.rate,
      rateReason: agreementRate.rateReason,
    },
    mttrBaseline: {
      averageMinutes: sampleSize === 0 ? null : averageMinutes,
      sampleSize,
      unresolvedExcluded,
      unavailableReason: sampleSize === 0 ? "No alerts in the window reached a terminal resolved state." : null,
      measurementDefinition:
        "Alert creation to linked incident resolution; alerts without a linked resolved incident are excluded.",
    },
    whatWeCouldNotSee: {
      replayedDecisions: decisionRows.length,
      retrievalUnavailable,
      retrievalNotAttempted,
      zeroEvidenceRows,
      decisionIds: couldNotSeeIds,
    },
    attackCoverage: {
      tactics,
      techniques,
      absentStatement:
        "No alerts mapped to an unlisted tactic or technique in this window; this is not a detection-gap claim.",
    },
    runCost: {
      inputTokens: metric(cost?.inputTokens),
      outputTokens: metric(cost?.outputTokens),
      costUsd: metric(cost?.costUsd),
      unmeasuredInvocations: Number(cost?.unmeasured ?? 0),
    },
  };
}
