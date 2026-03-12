/**
 * SecureNexus Native Detection Engine
 *
 * Evaluates sensor telemetry events against Sigma-compatible detection rules
 * and produces alerts — no third-party EDR/XDR required.
 *
 * Architecture:
 *   SensorEvent → MatchEvent → [Rule.conditions evaluation] → Alert
 */

import type { SensorEvent, DetectionRule } from "../../shared/schema";

// ============================================================================
// Rule condition types
// ============================================================================

export type FieldOperator =
  | "equals"
  | "not_equals"
  | "contains"
  | "not_contains"
  | "starts_with"
  | "ends_with"
  | "regex"
  | "gt"
  | "gte"
  | "lt"
  | "lte"
  | "in"
  | "not_in"
  | "exists"
  | "not_exists";

export interface FieldCondition {
  type: "field";
  field: string; // dot-path into SensorEvent, e.g. "processName", "rawData.cmdline"
  operator: FieldOperator;
  value?: string | number | string[];
  caseSensitive?: boolean;
}

export interface AndCondition {
  type: "and";
  conditions: RuleCondition[];
}

export interface OrCondition {
  type: "or";
  conditions: RuleCondition[];
}

export interface NotCondition {
  type: "not";
  condition: RuleCondition;
}

export type RuleCondition = FieldCondition | AndCondition | OrCondition | NotCondition;

export interface RuleMatchResult {
  ruleId: string;
  ruleName: string;
  severity: string;
  category: string;
  mitreTactic?: string | null;
  mitreTechnique?: string | null;
  mitreTechniqueId?: string | null;
  alertTitle: string;
  confidence: number;
  matchedFields: Record<string, unknown>;
}

// ============================================================================
// Deep-get field value from a sensor event
// ============================================================================

function getField(event: SensorEvent, path: string): unknown {
  const parts = path.split(".");
  let cur: unknown = event;
  for (const p of parts) {
    if (cur == null || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[p];
  }
  return cur;
}

// ============================================================================
// Evaluate a single field condition
// ============================================================================

function evalFieldCondition(event: SensorEvent, cond: FieldCondition): boolean {
  const raw = getField(event, cond.field);
  const { operator, value, caseSensitive } = cond;

  if (operator === "exists") return raw !== undefined && raw !== null;
  if (operator === "not_exists") return raw === undefined || raw === null;
  if (raw === undefined || raw === null) return false;

  const str = String(raw);
  const normalStr = caseSensitive ? str : str.toLowerCase();
  const normalVal = typeof value === "string" ? (caseSensitive ? value : value.toLowerCase()) : value;

  switch (operator) {
    case "equals":
      return str === String(value);
    case "not_equals":
      return str !== String(value);
    case "contains":
      return normalStr.includes(String(normalVal));
    case "not_contains":
      return !normalStr.includes(String(normalVal));
    case "starts_with":
      return normalStr.startsWith(String(normalVal));
    case "ends_with":
      return normalStr.endsWith(String(normalVal));
    case "regex":
      try {
        return new RegExp(String(value), caseSensitive ? "" : "i").test(str);
      } catch {
        return false;
      }
    case "gt":
      return Number(raw) > Number(value);
    case "gte":
      return Number(raw) >= Number(value);
    case "lt":
      return Number(raw) < Number(value);
    case "lte":
      return Number(raw) <= Number(value);
    case "in":
      if (!Array.isArray(value)) return false;
      return (value as string[]).some((v) =>
        caseSensitive ? str === String(v) : str.toLowerCase() === String(v).toLowerCase(),
      );
    case "not_in":
      if (!Array.isArray(value)) return true;
      return !(value as string[]).some((v) =>
        caseSensitive ? str === String(v) : str.toLowerCase() === String(v).toLowerCase(),
      );
    default:
      return false;
  }
}

// ============================================================================
// Evaluate a condition tree
// ============================================================================

function evalCondition(event: SensorEvent, cond: RuleCondition): boolean {
  switch (cond.type) {
    case "field":
      return evalFieldCondition(event, cond);
    case "and":
      return cond.conditions.every((c) => evalCondition(event, c));
    case "or":
      return cond.conditions.some((c) => evalCondition(event, c));
    case "not":
      return !evalCondition(event, cond.condition);
    default:
      return false;
  }
}

// ============================================================================
// Collect which fields triggered the match (for alert context)
// ============================================================================

function collectMatchedFields(event: SensorEvent, cond: RuleCondition): Record<string, unknown> {
  const fields: Record<string, unknown> = {};

  function walk(c: RuleCondition) {
    if (c.type === "field" && evalFieldCondition(event, c)) {
      fields[c.field] = getField(event, c.field);
    } else if (c.type === "and" || c.type === "or") {
      c.conditions.forEach(walk);
    } else if (c.type === "not") {
      walk(c.condition);
    }
  }

  walk(cond);
  return fields;
}

// ============================================================================
// Evaluate one event against all loaded rules
// ============================================================================

export function evaluateEvent(event: SensorEvent, rules: DetectionRule[]): RuleMatchResult[] {
  const results: RuleMatchResult[] = [];

  for (const rule of rules) {
    if (rule.status !== "active") continue;

    // Check platform applicability
    const platforms = (rule.platforms as string[]) ?? [];
    // We don't have platform directly on event, so skip platform check here
    // (sensor registration carries the platform)

    // Check event type applicability
    const eventTypes = (rule.eventTypes as string[]) ?? [];
    if (eventTypes.length > 0 && !eventTypes.includes(event.eventType)) continue;

    // Evaluate condition tree
    const conditions = rule.conditions as RuleCondition;
    let matched = false;
    try {
      matched = evalCondition(event, conditions);
    } catch {
      continue;
    }

    if (!matched) continue;

    const matchedFields = collectMatchedFields(event, conditions);
    const alertTitle = buildAlertTitle(rule, event, matchedFields);

    results.push({
      ruleId: rule.id,
      ruleName: rule.name,
      severity: rule.severity,
      category: rule.category,
      mitreTactic: rule.mitreTactic,
      mitreTechnique: rule.mitreTechnique,
      mitreTechniqueId: rule.mitreTechniqueId,
      alertTitle,
      confidence: 0.85,
      matchedFields,
    });
  }

  return results;
}

// ============================================================================
// Build alert title with template substitution
// ============================================================================

function buildAlertTitle(rule: DetectionRule, event: SensorEvent, fields: Record<string, unknown>): string {
  const template = rule.alertTitle ?? rule.name;
  return template
    .replace("{hostname}", event.hostname ?? "unknown")
    .replace("{processName}", event.processName ?? "unknown")
    .replace("{username}", event.username ?? "unknown")
    .replace("{srcIp}", event.srcIp ?? "unknown")
    .replace("{dstIp}", event.dstIp ?? "unknown")
    .replace("{filePath}", event.filePath ?? "unknown")
    .replace("{dnsQuery}", event.dnsQuery ?? "unknown");
}
