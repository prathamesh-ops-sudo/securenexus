import { pool } from "../db";
import { logger } from "../logger";

const log = logger.child("active-learning");

// ─── Types ───────────────────────────────────────────────────────────────────

export interface FewShotExample {
  id: string;
  orgId: string | null;
  domain: string; // "triage" | "correlation" | "narrative"
  input: string;
  incorrectOutput: string;
  correctOutput: string;
  lesson: string;
  alertSource: string | null;
  alertCategory: string | null;
  feedbackId: string | null;
  active: boolean;
  createdAt: string;
}

export interface FalsePositiveStats {
  source: string;
  category: string;
  totalAlerts: number;
  falsePositives: number;
  fpRate: number;
  suppressed: boolean;
}

export interface SourceSignalScore {
  source: string;
  category: string;
  orgId: string;
  totalFeedback: number;
  overriddenCount: number;
  dismissedCount: number;
  fpRate: number;
  suppressed: boolean;
  lastUpdated: string;
}

export interface ActiveLearningStats {
  totalExamples: number;
  byDomain: Record<string, number>;
  activeExamples: number;
  suppressedSources: number;
  totalFeedbackProcessed: number;
  fpRateBySource: FalsePositiveStats[];
}

// ─── Schema Initialization ───────────────────────────────────────────────────

const TABLES_ENSURED = { done: false };

async function ensureActiveLearningTables(): Promise<void> {
  if (TABLES_ENSURED.done) return;

  await pool.query(`
    CREATE TABLE IF NOT EXISTS ai_few_shot_examples (
      id VARCHAR PRIMARY KEY DEFAULT gen_random_uuid()::text,
      org_id VARCHAR,
      domain VARCHAR NOT NULL,
      input TEXT NOT NULL,
      incorrect_output TEXT NOT NULL,
      correct_output TEXT NOT NULL,
      lesson TEXT NOT NULL,
      alert_source VARCHAR,
      alert_category VARCHAR,
      feedback_id VARCHAR,
      active BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_few_shot_org_domain ON ai_few_shot_examples (org_id, domain)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_few_shot_active ON ai_few_shot_examples (active)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_few_shot_feedback ON ai_few_shot_examples (feedback_id)`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS ai_source_signal_scores (
      id SERIAL PRIMARY KEY,
      org_id VARCHAR NOT NULL,
      source VARCHAR NOT NULL,
      category VARCHAR NOT NULL DEFAULT '',
      total_feedback INTEGER NOT NULL DEFAULT 0,
      overridden_count INTEGER NOT NULL DEFAULT 0,
      dismissed_count INTEGER NOT NULL DEFAULT 0,
      fp_rate DOUBLE PRECISION NOT NULL DEFAULT 0.0,
      suppressed BOOLEAN NOT NULL DEFAULT false,
      manual_override BOOLEAN NOT NULL DEFAULT false,
      last_updated TIMESTAMP DEFAULT NOW(),
      UNIQUE (org_id, source, category)
    )
  `);
  // Add manual_override column if it doesn't exist (migration-safe)
  await pool.query(
    `ALTER TABLE ai_source_signal_scores ADD COLUMN IF NOT EXISTS manual_override BOOLEAN NOT NULL DEFAULT false`,
  );
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_source_signal_org ON ai_source_signal_scores (org_id)`);
  await pool.query(
    `CREATE INDEX IF NOT EXISTS idx_source_signal_suppressed ON ai_source_signal_scores (org_id, suppressed)`,
  );

  await pool.query(`
    CREATE TABLE IF NOT EXISTS ai_feedback_learning_log (
      id SERIAL PRIMARY KEY,
      org_id VARCHAR,
      feedback_id VARCHAR NOT NULL,
      action VARCHAR NOT NULL,
      domain VARCHAR,
      few_shot_example_id VARCHAR,
      source VARCHAR,
      category VARCHAR,
      details JSONB,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_feedback_learning_org ON ai_feedback_learning_log (org_id)`);

  TABLES_ENSURED.done = true;
}

// ─── Few-Shot Example Management ─────────────────────────────────────────────

export async function addFewShotExample(params: {
  orgId?: string;
  domain: string;
  input: string;
  incorrectOutput: string;
  correctOutput: string;
  lesson: string;
  alertSource?: string;
  alertCategory?: string;
  feedbackId?: string;
}): Promise<FewShotExample> {
  await ensureActiveLearningTables();

  const result = await pool.query(
    `INSERT INTO ai_few_shot_examples (org_id, domain, input, incorrect_output, correct_output, lesson, alert_source, alert_category, feedback_id)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
     RETURNING *`,
    [
      params.orgId || null,
      params.domain,
      params.input,
      params.incorrectOutput,
      params.correctOutput,
      params.lesson,
      params.alertSource || null,
      params.alertCategory || null,
      params.feedbackId || null,
    ],
  );

  const row = result.rows[0];
  log.info("Few-shot example added", {
    id: row.id,
    domain: params.domain,
    orgId: params.orgId,
    feedbackId: params.feedbackId,
  });

  return rowToFewShotExample(row);
}

export async function getFewShotExamples(
  domain: string,
  orgId?: string,
  limit: number = 10,
): Promise<FewShotExample[]> {
  await ensureActiveLearningTables();

  const safeLimit = Math.min(Math.max(1, limit), 50);

  // Get org-specific + global (null org_id) examples
  const result = await pool.query(
    `SELECT * FROM ai_few_shot_examples
     WHERE domain = $1 AND active = true AND (org_id = $2 OR org_id IS NULL)
     ORDER BY created_at DESC
     LIMIT $3`,
    [domain, orgId || null, safeLimit],
  );

  return result.rows.map(rowToFewShotExample);
}

export async function getAllFewShotExamples(orgId?: string, domain?: string): Promise<FewShotExample[]> {
  await ensureActiveLearningTables();

  let query = `SELECT * FROM ai_few_shot_examples WHERE (org_id = $1 OR org_id IS NULL)`;
  const params: (string | null)[] = [orgId || null];

  if (domain) {
    query += ` AND domain = $2`;
    params.push(domain);
  }

  query += ` ORDER BY created_at DESC LIMIT 200`;

  const result = await pool.query(query, params);
  return result.rows.map(rowToFewShotExample);
}

export async function deactivateFewShotExample(id: string, orgId?: string): Promise<boolean> {
  await ensureActiveLearningTables();

  const result = orgId
    ? await pool.query(`UPDATE ai_few_shot_examples SET active = false WHERE id = $1 AND org_id = $2 RETURNING id`, [
        id,
        orgId,
      ])
    : await pool.query(`UPDATE ai_few_shot_examples SET active = false WHERE id = $1 RETURNING id`, [id]);

  return (result.rowCount ?? 0) > 0;
}

export async function deleteFewShotExample(id: string, orgId?: string): Promise<boolean> {
  await ensureActiveLearningTables();

  const result = orgId
    ? await pool.query(`DELETE FROM ai_few_shot_examples WHERE id = $1 AND org_id = $2`, [id, orgId])
    : await pool.query(`DELETE FROM ai_few_shot_examples WHERE id = $1`, [id]);

  return (result.rowCount ?? 0) > 0;
}

// ─── Format Few-Shot Examples for Prompt Injection ───────────────────────────

export function formatFewShotExamplesForPrompt(examples: FewShotExample[]): string {
  if (examples.length === 0) return "";

  const lines: string[] = [
    "ANALYST CORRECTIONS (learn from past mistakes — these are real corrections by human analysts):",
    "",
  ];

  for (let i = 0; i < examples.length; i++) {
    const ex = examples[i];
    lines.push(`CORRECTION ${i + 1}:`);
    lines.push(`Context: ${truncateText(ex.input, 500)}`);
    lines.push(`AI said: ${truncateText(ex.incorrectOutput, 300)}`);
    lines.push(`Analyst corrected to: ${truncateText(ex.correctOutput, 300)}`);
    lines.push(`Lesson: ${ex.lesson}`);
    lines.push("");
  }

  lines.push(
    "Apply these lessons to avoid repeating past mistakes. If you see a similar pattern, follow the analyst's correction.",
  );

  return lines.join("\n");
}

// ─── False Positive Rate Tracking ────────────────────────────────────────────

export async function recordFeedbackOutcome(params: {
  orgId: string;
  feedbackId: string;
  outcome: "overridden" | "dismissed" | "confirmed";
  source: string;
  category: string;
  domain?: string;
  originalContext?: string;
  aiOutput?: string;
  analystCorrection?: string;
  reason?: string;
}): Promise<void> {
  await ensureActiveLearningTables();

  const isNegative = params.outcome === "overridden" || params.outcome === "dismissed";

  // Upsert source signal score
  await pool.query(
    `INSERT INTO ai_source_signal_scores (org_id, source, category, total_feedback, overridden_count, dismissed_count, fp_rate, last_updated)
     VALUES ($1, $2, $3, 1,
       CASE WHEN $4 = 'overridden' THEN 1 ELSE 0 END,
       CASE WHEN $4 = 'dismissed' THEN 1 ELSE 0 END,
       CASE WHEN $4 IN ('overridden', 'dismissed') THEN 1.0 ELSE 0.0 END,
       NOW()
     )
     ON CONFLICT (org_id, source, category) DO UPDATE SET
       total_feedback = ai_source_signal_scores.total_feedback + 1,
       overridden_count = ai_source_signal_scores.overridden_count + CASE WHEN $4 = 'overridden' THEN 1 ELSE 0 END,
       dismissed_count = ai_source_signal_scores.dismissed_count + CASE WHEN $4 = 'dismissed' THEN 1 ELSE 0 END,
       fp_rate = CAST(
         (ai_source_signal_scores.overridden_count + ai_source_signal_scores.dismissed_count +
           CASE WHEN $4 IN ('overridden', 'dismissed') THEN 1 ELSE 0 END)
         AS DOUBLE PRECISION
       ) / CAST(ai_source_signal_scores.total_feedback + 1 AS DOUBLE PRECISION),
       last_updated = NOW()`,
    [params.orgId, params.source || "unknown", params.category || "unknown", params.outcome],
  );

  // Auto-suppress sources with high FP rate (>= 70% FP rate with at least 5 samples)
  // Skip rows where manual_override is true — admin toggles take precedence
  await pool.query(
    `UPDATE ai_source_signal_scores
     SET suppressed = (fp_rate >= 0.7 AND total_feedback >= 5)
     WHERE org_id = $1 AND source = $2 AND category = $3 AND manual_override = false`,
    [params.orgId, params.source || "unknown", params.category || "unknown"],
  );

  // If overridden, inject few-shot example into prompt context
  if (params.outcome === "overridden" && params.originalContext && params.analystCorrection) {
    const domain = params.domain || inferDomainFromContext(params.source, params.category);

    const example = await addFewShotExample({
      orgId: params.orgId,
      domain,
      input: params.originalContext,
      incorrectOutput: params.aiOutput || "AI classification was incorrect",
      correctOutput: params.analystCorrection,
      lesson: params.reason || "Analyst determined the AI assessment was incorrect",
      alertSource: params.source,
      alertCategory: params.category,
      feedbackId: params.feedbackId,
    });

    // Log the learning event
    await pool.query(
      `INSERT INTO ai_feedback_learning_log (org_id, feedback_id, action, domain, few_shot_example_id, source, category, details)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        params.orgId,
        params.feedbackId,
        "few_shot_injected",
        domain,
        example.id,
        params.source,
        params.category,
        JSON.stringify({
          outcome: params.outcome,
          lesson: params.reason,
        }),
      ],
    );

    log.info("Few-shot example injected from analyst override", {
      feedbackId: params.feedbackId,
      exampleId: example.id,
      domain,
      source: params.source,
    });
  }

  // Log all feedback outcomes (skip if already logged as few_shot_injected above to avoid double-counting)
  if (isNegative && !(params.outcome === "overridden" && params.originalContext && params.analystCorrection)) {
    await pool.query(
      `INSERT INTO ai_feedback_learning_log (org_id, feedback_id, action, source, category, details)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        params.orgId,
        params.feedbackId,
        params.outcome === "dismissed" ? "alert_dismissed" : "triage_overridden",
        params.source,
        params.category,
        JSON.stringify({
          outcome: params.outcome,
          reason: params.reason,
        }),
      ],
    );
  }
}

// ─── Suppressed Sources ──────────────────────────────────────────────────────

export async function getSuppressedSources(orgId: string): Promise<SourceSignalScore[]> {
  await ensureActiveLearningTables();

  const result = await pool.query(
    `SELECT * FROM ai_source_signal_scores WHERE org_id = $1 AND suppressed = true ORDER BY fp_rate DESC`,
    [orgId],
  );

  return result.rows.map(rowToSourceSignalScore);
}

export async function getSourceSignalScores(orgId: string, limit: number = 50): Promise<SourceSignalScore[]> {
  await ensureActiveLearningTables();

  const safeLimit = Math.min(Math.max(1, limit), 200);
  const result = await pool.query(
    `SELECT * FROM ai_source_signal_scores WHERE org_id = $1 ORDER BY fp_rate DESC, total_feedback DESC LIMIT $2`,
    [orgId, safeLimit],
  );

  return result.rows.map(rowToSourceSignalScore);
}

export async function toggleSourceSuppression(
  orgId: string,
  source: string,
  category: string,
  suppressed: boolean,
): Promise<boolean> {
  await ensureActiveLearningTables();

  const result = await pool.query(
    `UPDATE ai_source_signal_scores SET suppressed = $4, manual_override = true, last_updated = NOW()
     WHERE org_id = $1 AND source = $2 AND category = $3
     RETURNING id`,
    [orgId, source, category, suppressed],
  );

  return (result.rowCount ?? 0) > 0;
}

export async function isSourceSuppressed(orgId: string, source: string, category: string): Promise<boolean> {
  await ensureActiveLearningTables();

  const result = await pool.query(
    `SELECT suppressed FROM ai_source_signal_scores
     WHERE org_id = $1 AND source = $2 AND category = $3`,
    [orgId, source, category],
  );

  if (result.rows.length === 0) return false;
  return result.rows[0].suppressed === true;
}

// ─── Active Learning Stats ───────────────────────────────────────────────────

export async function getActiveLearningStats(orgId: string): Promise<ActiveLearningStats> {
  await ensureActiveLearningTables();

  // Count examples
  const examplesResult = await pool.query(
    `SELECT domain, COUNT(*) as cnt, SUM(CASE WHEN active THEN 1 ELSE 0 END) as active_cnt
     FROM ai_few_shot_examples
     WHERE org_id = $1 OR org_id IS NULL
     GROUP BY domain`,
    [orgId],
  );

  const byDomain: Record<string, number> = {};
  let totalExamples = 0;
  let activeExamples = 0;
  for (const row of examplesResult.rows) {
    const domain = row.domain as string;
    const cnt = parseInt(String(row.cnt), 10) || 0;
    const activeCnt = parseInt(String(row.active_cnt), 10) || 0;
    byDomain[domain] = cnt;
    totalExamples += cnt;
    activeExamples += activeCnt;
  }

  // Count suppressed sources
  const suppressedResult = await pool.query(
    `SELECT COUNT(*) as cnt FROM ai_source_signal_scores WHERE org_id = $1 AND suppressed = true`,
    [orgId],
  );
  const suppressedSources = parseInt(String(suppressedResult.rows[0].cnt), 10) || 0;

  // Total feedback processed
  const feedbackResult = await pool.query(`SELECT COUNT(*) as cnt FROM ai_feedback_learning_log WHERE org_id = $1`, [
    orgId,
  ]);
  const totalFeedbackProcessed = parseInt(String(feedbackResult.rows[0].cnt), 10) || 0;

  // FP rate by source
  const fpResult = await pool.query(
    `SELECT source, category, total_feedback, overridden_count + dismissed_count as false_positives, fp_rate, suppressed
     FROM ai_source_signal_scores
     WHERE org_id = $1
     ORDER BY fp_rate DESC
     LIMIT 50`,
    [orgId],
  );

  const fpRateBySource: FalsePositiveStats[] = fpResult.rows.map((row: Record<string, unknown>) => ({
    source: row.source as string,
    category: row.category as string,
    totalAlerts: parseInt(String(row.total_feedback), 10) || 0,
    falsePositives: parseInt(String(row.false_positives), 10) || 0,
    fpRate: parseFloat(String(row.fp_rate)) || 0,
    suppressed: row.suppressed === true,
  }));

  return {
    totalExamples,
    byDomain,
    activeExamples,
    suppressedSources,
    totalFeedbackProcessed,
    fpRateBySource,
  };
}

// ─── Learning Log ────────────────────────────────────────────────────────────

export interface LearningLogEntry {
  id: number;
  orgId: string | null;
  feedbackId: string;
  action: string;
  domain: string | null;
  fewShotExampleId: string | null;
  source: string | null;
  category: string | null;
  details: Record<string, unknown> | null;
  createdAt: string;
}

export async function getLearningLog(orgId: string, limit: number = 50): Promise<LearningLogEntry[]> {
  await ensureActiveLearningTables();

  const safeLimit = Math.min(Math.max(1, limit), 200);
  const result = await pool.query(
    `SELECT * FROM ai_feedback_learning_log WHERE org_id = $1 ORDER BY created_at DESC LIMIT $2`,
    [orgId, safeLimit],
  );

  return result.rows.map((row: Record<string, unknown>) => ({
    id: row.id as number,
    orgId: row.org_id as string | null,
    feedbackId: row.feedback_id as string,
    action: row.action as string,
    domain: row.domain as string | null,
    fewShotExampleId: row.few_shot_example_id as string | null,
    source: row.source as string | null,
    category: row.category as string | null,
    details: row.details as Record<string, unknown> | null,
    createdAt: row.created_at ? (row.created_at as Date).toISOString() : new Date().toISOString(),
  }));
}

// ─── Prompt Enhancement with Few-Shot Examples ───────────────────────────────

/**
 * Build a few-shot augmented system prompt by appending analyst corrections
 * to the base system prompt for a given domain.
 */
export async function buildFewShotAugmentedPrompt(domain: string, orgId?: string): Promise<string | null> {
  const examples = await getFewShotExamples(domain, orgId, 5);
  if (examples.length === 0) return null;
  return formatFewShotExamplesForPrompt(examples);
}

/**
 * Get the list of suppressed source+category combos to exclude from AI context.
 * These are sources with persistently high false positive rates.
 */
export async function getSuppressedSourcesForContext(orgId: string): Promise<Set<string>> {
  const suppressed = await getSuppressedSources(orgId);
  const keys = new Set<string>();
  for (const s of suppressed) {
    keys.add(`${s.source}::${s.category}`);
  }
  return keys;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function rowToFewShotExample(row: Record<string, unknown>): FewShotExample {
  return {
    id: row.id as string,
    orgId: row.org_id as string | null,
    domain: row.domain as string,
    input: row.input as string,
    incorrectOutput: row.incorrect_output as string,
    correctOutput: row.correct_output as string,
    lesson: row.lesson as string,
    alertSource: row.alert_source as string | null,
    alertCategory: row.alert_category as string | null,
    feedbackId: row.feedback_id as string | null,
    active: row.active as boolean,
    createdAt: row.created_at ? (row.created_at as Date).toISOString() : new Date().toISOString(),
  };
}

function rowToSourceSignalScore(row: Record<string, unknown>): SourceSignalScore {
  return {
    source: row.source as string,
    category: row.category as string,
    orgId: row.org_id as string,
    totalFeedback: parseInt(String(row.total_feedback), 10) || 0,
    overriddenCount: parseInt(String(row.overridden_count), 10) || 0,
    dismissedCount: parseInt(String(row.dismissed_count), 10) || 0,
    fpRate: parseFloat(String(row.fp_rate)) || 0,
    suppressed: row.suppressed === true,
    lastUpdated: row.last_updated ? (row.last_updated as Date).toISOString() : new Date().toISOString(),
  };
}

function truncateText(text: string, maxLen: number): string {
  if (text.length <= maxLen) return text;
  return text.slice(0, maxLen) + "...";
}

function inferDomainFromContext(source?: string, category?: string): string {
  // Default to "triage" since most analyst corrections come from alert triage
  if (!source && !category) return "triage";

  const combined = `${source || ""} ${category || ""}`.toLowerCase();
  if (combined.includes("correlat") || combined.includes("incident")) return "correlation";
  if (combined.includes("narrative") || combined.includes("report")) return "narrative";
  return "triage";
}
