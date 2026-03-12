/**
 * Sigma-compatible condition tree evaluator for the Native Detection Engine.
 *
 * Condition tree format:
 *   { "field": "<fieldName>", "op": "<operator>", "value": <any> }
 *   { "and": [<condition>, ...] }
 *   { "or":  [<condition>, ...] }
 *   { "not": <condition> }
 *
 * Supported operators:
 *   eq, neq, contains, startsWith, endsWith, regex, in, exists, gt, gte, lt, lte
 */

export interface FieldCondition {
  field: string;
  op: "eq" | "neq" | "contains" | "startsWith" | "endsWith" | "regex" | "in" | "exists" | "gt" | "gte" | "lt" | "lte";
  value: unknown;
}

export interface AndCondition {
  and: ConditionNode[];
}

export interface OrCondition {
  or: ConditionNode[];
}

export interface NotCondition {
  not: ConditionNode;
}

export type ConditionNode = FieldCondition | AndCondition | OrCondition | NotCondition;

function getNestedValue(obj: Record<string, unknown>, path: string): unknown {
  const parts = path.split(".");
  let current: unknown = obj;
  for (const part of parts) {
    if (current === null || current === undefined || typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}

function evaluateField(event: Record<string, unknown>, cond: FieldCondition): boolean {
  const fieldValue = getNestedValue(event, cond.field);
  const target = cond.value;

  switch (cond.op) {
    case "eq":
      return fieldValue === target;
    case "neq":
      return fieldValue !== target;
    case "contains":
      if (typeof fieldValue === "string" && typeof target === "string") {
        return fieldValue.toLowerCase().includes(target.toLowerCase());
      }
      if (Array.isArray(fieldValue) && typeof target === "string") {
        return fieldValue.some((v) => typeof v === "string" && v.toLowerCase() === target.toLowerCase());
      }
      return false;
    case "startsWith":
      return (
        typeof fieldValue === "string" &&
        typeof target === "string" &&
        fieldValue.toLowerCase().startsWith(target.toLowerCase())
      );
    case "endsWith":
      return (
        typeof fieldValue === "string" &&
        typeof target === "string" &&
        fieldValue.toLowerCase().endsWith(target.toLowerCase())
      );
    case "regex":
      if (typeof fieldValue === "string" && typeof target === "string") {
        try {
          return new RegExp(target, "i").test(fieldValue);
        } catch {
          return false;
        }
      }
      return false;
    case "in":
      if (Array.isArray(target)) {
        const strValue = String(fieldValue ?? "").toLowerCase();
        return target.some((t) => String(t).toLowerCase() === strValue);
      }
      return false;
    case "exists":
      return target ? fieldValue !== undefined && fieldValue !== null : fieldValue === undefined || fieldValue === null;
    case "gt":
      return typeof fieldValue === "number" && typeof target === "number" && fieldValue > target;
    case "gte":
      return typeof fieldValue === "number" && typeof target === "number" && fieldValue >= target;
    case "lt":
      return typeof fieldValue === "number" && typeof target === "number" && fieldValue < target;
    case "lte":
      return typeof fieldValue === "number" && typeof target === "number" && fieldValue <= target;
    default:
      return false;
  }
}

export function evaluateCondition(event: Record<string, unknown>, node: ConditionNode): boolean {
  if ("and" in node) {
    return (node as AndCondition).and.every((child) => evaluateCondition(event, child));
  }
  if ("or" in node) {
    return (node as OrCondition).or.some((child) => evaluateCondition(event, child));
  }
  if ("not" in node) {
    return !evaluateCondition(event, (node as NotCondition).not);
  }
  if ("field" in node) {
    return evaluateField(event, node as FieldCondition);
  }
  return false;
}

/**
 * Collect all field names that matched in a condition tree, useful for alert details.
 */
export function collectMatchedFields(event: Record<string, unknown>, node: ConditionNode): Record<string, unknown> {
  const matched: Record<string, unknown> = {};

  function walk(n: ConditionNode): void {
    if ("and" in n) {
      (n as AndCondition).and.forEach(walk);
    } else if ("or" in n) {
      (n as OrCondition).or.forEach(walk);
    } else if ("not" in n) {
      walk((n as NotCondition).not);
    } else if ("field" in n) {
      const fc = n as FieldCondition;
      if (evaluateField(event, fc)) {
        matched[fc.field] = getNestedValue(event, fc.field);
      }
    }
  }

  walk(node);
  return matched;
}
