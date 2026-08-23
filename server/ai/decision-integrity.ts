import { createHash } from "crypto";
import { pool } from "../db";

const INTEGRITY_FIELDS = new Set([
  "integrity_digest",
  "integrity_previous_digest",
  "integrity_sequence",
  "integrity_finalized_at",
  "updated_at",
]);

export type DecisionIntegrityStatus = "verified" | "mismatched" | "unverifiable";

export interface DecisionIntegrityResult {
  decisionId: string;
  status: DecisionIntegrityStatus;
  digest: string | null;
  expectedDigest: string | null;
  previousDigest: string | null;
  sequence: number | null;
  reason: string | null;
}

export function canonicalize(value: unknown): unknown {
  if (value instanceof Date) return value.toISOString();
  if (Array.isArray(value)) {
    return value.map(canonicalize).sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([, item]) => item !== undefined)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, item]) => [key, canonicalize(item)]),
    );
  }
  return value;
}

export function canonicalSerialize(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

export function computeDecisionDigest(payload: unknown): string {
  return createHash("sha256").update(canonicalSerialize(payload)).digest("hex");
}

function stripIntegrityFields(decision: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(decision).filter(([key]) => !INTEGRITY_FIELDS.has(key)));
}

function buildPayload(
  decision: Record<string, unknown>,
  evidence: unknown[],
  inference: unknown[],
  redactions: unknown[],
  previousDigest: string,
  sequence: number,
): Record<string, unknown> {
  return {
    decision: stripIntegrityFields(decision),
    evidence,
    inference,
    redactions,
    previousDigest,
    sequence,
  };
}

async function loadComponents(
  executor: { query: (text: string, values?: unknown[]) => Promise<{ rows: Record<string, unknown>[] }> },
  orgId: string,
  decisionId: string,
): Promise<{
  decision: Record<string, unknown> | null;
  evidence: Record<string, unknown>[];
  inference: Record<string, unknown>[];
  redactions: Record<string, unknown>[];
  actions: Record<string, unknown>[];
  adjudications: Record<string, unknown>[];
}> {
  const decisionResult = await executor.query(
    `SELECT row_to_json(d) AS decision
     FROM ai_analyst_decisions d
     WHERE d.org_id = $1 AND d.id = $2`,
    [orgId, decisionId],
  );
  const decision = (decisionResult.rows[0]?.decision as Record<string, unknown> | undefined) ?? null;
  if (!decision) {
    return { decision: null, evidence: [], inference: [], redactions: [], actions: [], adjudications: [] };
  }
  const [evidence, inference, redactions, actions, adjudications] = await Promise.all([
    executor.query(
      `SELECT row_to_json(e) AS item
       FROM ai_decision_evidence e
       WHERE e.org_id = $1 AND e.decision_id = $2
       ORDER BY e.id`,
      [orgId, decisionId],
    ),
    executor.query(
      `SELECT row_to_json(i) AS item
       FROM ai_inference_log i
       WHERE i.org_id = $1 AND i.decision_id = $2
       ORDER BY i.id`,
      [orgId, decisionId],
    ),
    executor.query(
      `SELECT row_to_json(r) AS item
       FROM ai_decision_redaction_receipts r
       WHERE r.org_id = $1 AND r.decision_id = $2
       ORDER BY r.id`,
      [orgId, decisionId],
    ),
    executor.query(
      `SELECT row_to_json(a) AS item
       FROM autonomy_log a
       WHERE a.org_id = $1 AND a.decision_id = $2
       ORDER BY a.id`,
      [orgId, decisionId],
    ),
    executor.query(
      `SELECT row_to_json(a) AS item
       FROM ai_decision_adjudications a
       WHERE a.org_id = $1 AND a.decision_id = $2
       ORDER BY a.id`,
      [orgId, decisionId],
    ),
  ]);
  const items = (result: { rows: Record<string, unknown>[] }): Record<string, unknown>[] =>
    result.rows.map((row) => row.item as Record<string, unknown>);
  return {
    decision,
    evidence: items(evidence),
    inference: items(inference),
    redactions: items(redactions),
    actions: items(actions),
    adjudications: items(adjudications),
  };
}

export async function finalizeDecisionIntegrity(orgId: string, decisionId: string): Promise<DecisionIntegrityResult> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [`ai-decision-integrity:${orgId}`]);
    const components = await loadComponents(client, orgId, decisionId);
    if (!components.decision) throw new Error("Decision not found in organization");
    const existingDigest = components.decision.integrity_digest;
    if (typeof existingDigest === "string") {
      await client.query("COMMIT");
      return {
        decisionId,
        status: "verified",
        digest: existingDigest,
        expectedDigest: existingDigest,
        previousDigest: (components.decision.integrity_previous_digest as string | null) ?? null,
        sequence: (components.decision.integrity_sequence as number | null) ?? null,
        reason: null,
      };
    }
    const previousResult = await client.query(
      `SELECT integrity_digest AS "integrityDigest", integrity_sequence AS "integritySequence"
       FROM ai_analyst_decisions
       WHERE org_id = $1 AND integrity_digest IS NOT NULL
       ORDER BY integrity_sequence DESC
       LIMIT 1`,
      [orgId],
    );
    const previousDigest = (previousResult.rows[0]?.integrityDigest as string | undefined) ?? "genesis";
    const sequence = Number(previousResult.rows[0]?.integritySequence ?? 0) + 1;
    const digest = computeDecisionDigest(
      buildPayload(
        components.decision,
        components.evidence,
        components.inference,
        components.redactions,
        previousDigest,
        sequence,
      ),
    );
    await client.query(
      `UPDATE ai_analyst_decisions
       SET integrity_digest = $1, integrity_previous_digest = $2,
           integrity_sequence = $3, integrity_finalized_at = NOW(), updated_at = NOW()
       WHERE org_id = $4 AND id = $5`,
      [digest, previousDigest, sequence, orgId, decisionId],
    );
    await client.query("COMMIT");
    return {
      decisionId,
      status: "verified",
      digest,
      expectedDigest: digest,
      previousDigest,
      sequence,
      reason: null,
    };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

export async function verifyDecisionIntegrity(orgId: string, decisionId: string): Promise<DecisionIntegrityResult> {
  const components = await loadComponents(pool, orgId, decisionId);
  if (!components.decision) throw new Error("Decision not found in organization");
  const storedDigest = components.decision.integrity_digest;
  const sequence = Number(components.decision.integrity_sequence ?? 0) || null;
  const previousDigest = (components.decision.integrity_previous_digest as string | null) ?? null;
  if (typeof storedDigest !== "string" || sequence == null || previousDigest == null) {
    return {
      decisionId,
      status: "unverifiable",
      digest: typeof storedDigest === "string" ? storedDigest : null,
      expectedDigest: null,
      previousDigest,
      sequence,
      reason: "This decision predates integrity digest capture.",
    };
  }
  const expectedDigest = computeDecisionDigest(
    buildPayload(
      components.decision,
      components.evidence,
      components.inference,
      components.redactions,
      previousDigest,
      sequence,
    ),
  );
  if (expectedDigest !== storedDigest) {
    return {
      decisionId,
      status: "mismatched",
      digest: storedDigest,
      expectedDigest,
      previousDigest,
      sequence,
      reason: "Stored decision or receipt data does not match its integrity digest.",
    };
  }
  if (sequence > 1) {
    const previous = await pool.query<{ integrityDigest: string | null }>(
      `SELECT integrity_digest AS "integrityDigest"
       FROM ai_analyst_decisions
       WHERE org_id = $1 AND integrity_sequence = $2`,
      [orgId, sequence - 1],
    );
    if (previous.rows[0]?.integrityDigest !== previousDigest) {
      return {
        decisionId,
        status: "mismatched",
        digest: storedDigest,
        expectedDigest,
        previousDigest,
        sequence,
        reason: "The tenant integrity chain does not link to the preceding decision.",
      };
    }
  } else if (previousDigest !== "genesis") {
    return {
      decisionId,
      status: "mismatched",
      digest: storedDigest,
      expectedDigest,
      previousDigest,
      sequence,
      reason: "The first tenant integrity entry does not link to genesis.",
    };
  }
  return {
    decisionId,
    status: "verified",
    digest: storedDigest,
    expectedDigest,
    previousDigest,
    sequence,
    reason: null,
  };
}

export async function verifyTenantDecisionIntegrity(orgId: string): Promise<DecisionIntegrityResult[]> {
  const decisions = await pool.query<{ id: string }>(
    `SELECT id FROM ai_analyst_decisions WHERE org_id = $1 ORDER BY integrity_sequence NULLS LAST, created_at, id`,
    [orgId],
  );
  return Promise.all(decisions.rows.map((decision) => verifyDecisionIntegrity(orgId, decision.id)));
}
