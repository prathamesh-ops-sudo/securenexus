import type { InsertAlert, SuppressionRule } from "@shared/schema";
import { logger } from "./logger";
import { getActiveSuppressionRules, incrementSuppressionMatchCount } from "./storage/misc";

const log = logger.child("suppression-engine");

interface MatcherCondition {
  field: string;
  op: "eq" | "regex" | "contains";
  value: string;
}

interface SuppressionResult {
  suppressed: boolean;
  ruleId: string | null;
}

/**
 * Evaluate an incoming alert against active suppression rules for the org.
 * Returns on first match (short-circuit). Expired and disabled rules are
 * filtered at the query level by getActiveSuppressionRules.
 */
export async function evaluateSuppression(alert: InsertAlert, orgId: string): Promise<SuppressionResult> {
  const rules = await getActiveSuppressionRules(orgId);

  for (const rule of rules) {
    if (matchesRule(alert, rule)) {
      await incrementSuppressionMatchCount(rule.id);
      return { suppressed: true, ruleId: rule.id };
    }
  }

  return { suppressed: false, ruleId: null };
}

function matchesRule(alert: InsertAlert, rule: SuppressionRule): boolean {
  // Check source filter
  if (rule.source && alert.source !== rule.source) {
    return false;
  }

  // Check severity filter
  if (rule.severity && alert.severity !== rule.severity) {
    return false;
  }

  // Check category filter
  if (rule.category && alert.category !== rule.category) {
    return false;
  }

  // If matcher conditions exist, evaluate with AND logic
  if (rule.matcher && Array.isArray(rule.matcher) && rule.matcher.length > 0) {
    const conditions = rule.matcher as MatcherCondition[];
    for (const condition of conditions) {
      const fieldValue = getAlertFieldValue(alert, condition.field);
      if (!evaluateCondition(fieldValue, condition)) {
        return false;
      }
    }
    return true;
  }

  // Fall back to simple scope/scopeValue check
  if (rule.scope && rule.scopeValue) {
    const fieldValue = getAlertFieldValue(alert, rule.scope);
    return fieldValue === rule.scopeValue;
  }

  // If source or severity matched and no matcher/scope to check, it's a match
  if (rule.source || rule.severity || rule.category) {
    return true;
  }

  return false;
}

function getAlertFieldValue(alert: InsertAlert, field: string): string | null | undefined {
  const alertRecord = alert as Record<string, unknown>;
  const value = alertRecord[field];
  if (value === null || value === undefined) {
    return value as null | undefined;
  }
  return String(value);
}

function evaluateCondition(fieldValue: string | null | undefined, condition: MatcherCondition): boolean {
  const strValue = fieldValue ?? "";

  switch (condition.op) {
    case "eq":
      return strValue === condition.value;
    case "contains":
      return strValue.includes(condition.value);
    case "regex":
      try {
        const regex = new RegExp(condition.value, "i");
        return regex.test(strValue);
      } catch (err) {
        log.warn("Invalid regex pattern in suppression rule", {
          pattern: condition.value,
          error: String(err),
        });
        return false;
      }
    default:
      return false;
  }
}
