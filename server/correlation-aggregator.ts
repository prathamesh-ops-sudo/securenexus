/**
 * Weighted Voting Aggregator for Correlation Engine
 *
 * Combines confidence scores from multiple correlation algorithms
 * (temporal+entity, graph-based, physical-digital) using locked weights.
 * Flags divergent cases for analyst review when algorithm spread exceeds threshold.
 */

import { logger } from "./logger";

const log = logger.child("correlation-aggregator");

/** Locked algorithm weights per CONTEXT.md decision D-01 */
export const ALGORITHM_WEIGHTS: Record<AlgorithmName, number> = {
  temporal_entity: 0.50,
  graph: 0.30,
  physical: 0.20,
};

/** Divergence threshold: flag needsReview when spread > this value */
const DIVERGENCE_THRESHOLD = 0.3;

export type AlgorithmName = "temporal_entity" | "graph" | "physical";

export interface AlgorithmScore {
  algorithm: AlgorithmName;
  confidence: number;
  weight: number;
  available: boolean;
}

export interface AggregatedScore {
  finalConfidence: number;
  algorithmScores: AlgorithmScore[];
  needsReview: boolean;
  divergenceSpread: number;
}

/**
 * Aggregate correlation scores from multiple algorithms using weighted voting.
 *
 * - Filters to available algorithms only
 * - Renormalizes weights so available weights sum to 1.0
 * - Computes divergence spread (max - min of available confidences)
 * - Flags needsReview when spread exceeds DIVERGENCE_THRESHOLD (0.3)
 */
export function aggregateCorrelationScores(scores: AlgorithmScore[]): AggregatedScore {
  const available = scores.filter((s) => s.available);

  if (available.length === 0) {
    log.debug("no algorithms available for aggregation", { scoreCount: scores.length });
    return {
      finalConfidence: 0,
      algorithmScores: scores,
      needsReview: false,
      divergenceSpread: 0,
    };
  }

  // Renormalize weights among available algorithms
  const totalWeight = available.reduce((sum, s) => sum + s.weight, 0);
  const weightedSum = available.reduce((sum, s) => sum + (s.confidence * s.weight) / totalWeight, 0);
  const finalConfidence = Math.round(weightedSum * 100) / 100;

  // Divergence detection
  const confidences = available.map((s) => s.confidence);
  const divergenceSpread = Math.max(...confidences) - Math.min(...confidences);
  const needsReview = divergenceSpread > DIVERGENCE_THRESHOLD;

  if (needsReview) {
    log.warn("algorithm divergence detected, flagging for review", {
      divergenceSpread,
      scores: available.map((s) => ({ algorithm: s.algorithm, confidence: s.confidence })),
    });
  }

  log.debug("aggregation complete", {
    finalConfidence,
    availableCount: available.length,
    divergenceSpread,
    needsReview,
  });

  return {
    finalConfidence,
    algorithmScores: scores,
    needsReview,
    divergenceSpread,
  };
}

/**
 * Helper to build an AlgorithmScore with the locked weight from ALGORITHM_WEIGHTS.
 */
export function buildAlgorithmScore(
  algorithm: AlgorithmName,
  confidence: number,
  available: boolean,
): AlgorithmScore {
  return {
    algorithm,
    confidence,
    weight: ALGORITHM_WEIGHTS[algorithm],
    available,
  };
}
