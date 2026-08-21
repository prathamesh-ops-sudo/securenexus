/**
 * Compiles hunt languages into structured, bound conditions.
 *
 * No caller-controlled text is emitted as SQL. The hunt engine maps these
 * allowlisted fields to real schema columns and binds every condition value.
 */

export type HuntTable = "alerts" | "ingestion_logs" | "sensor_events";
export type HuntOperator = "eq" | "neq" | "contains" | "startsWith" | "endsWith" | "gt" | "lt";

export interface HuntCondition {
  field: string;
  operator: HuntOperator;
  value: string | number | boolean;
}

export interface CompiledFilter {
  conditions: HuntCondition[];
  conditionLogic: "and" | "or";
  explanation: string;
  targetTable: HuntTable;
  rejected?: boolean;
  rejectionReason?: string;
}

export class HuntQueryRejectedError extends Error {
  constructor(reason: string) {
    super(reason);
    this.name = "HuntQueryRejectedError";
  }
}

const TABLES = new Set<HuntTable>(["alerts", "ingestion_logs", "sensor_events"]);
const OPERATORS = new Set<HuntOperator>(["eq", "neq", "contains", "startsWith", "endsWith", "gt", "lt"]);

const FIELD_ALIASES: Record<HuntTable, Record<string, string>> = {
  alerts: {
    title: "title",
    description: "description",
    severity: "severity",
    status: "status",
    source: "source",
    category: "category",
    source_ip: "sourceIp",
    dest_ip: "destIp",
    user_id: "userId",
    hostname: "hostname",
    file_hash: "fileHash",
    url: "url",
    domain: "domain",
    payload: "payloadText",
    raw_data: "payloadText",
    commandline: "payloadText",
    command_line: "payloadText",
    image: "payloadText",
    parentimage: "payloadText",
    user: "payloadText",
    process: "payloadText",
  },
  ingestion_logs: {
    source: "source",
    status: "status",
    error_message: "errorMessage",
    request_id: "requestId",
    ip_address: "ipAddress",
  },
  sensor_events: {
    event_type: "eventType",
    process_name: "processName",
    process_path: "processPath",
    process_args: "processArgs",
    parent_process: "parentProcess",
    user_name: "userName",
    src_ip: "srcIp",
    dst_ip: "dstIp",
    file_path: "filePath",
    file_hash: "fileHash",
    auth_action: "authAction",
    auth_result: "authResult",
    dns_query: "dnsQuery",
    log_source: "logSource",
    log_level: "logLevel",
    log_message: "logMessage",
    payload: "payloadText",
    raw_data: "payloadText",
    commandline: "payloadText",
    command_line: "payloadText",
    image: "payloadText",
    parentimage: "payloadText",
    user: "payloadText",
    process: "payloadText",
  },
};

function rejected(targetTable: HuntTable, reason: string): CompiledFilter {
  return {
    conditions: [],
    conditionLogic: "and",
    explanation: reason,
    targetTable,
    rejected: true,
    rejectionReason: reason,
  };
}

function normalizeField(table: HuntTable, field: string): string | null {
  return FIELD_ALIASES[table][field.toLowerCase()] || null;
}

function condition(table: HuntTable, field: string, operator: HuntOperator, value: unknown): HuntCondition | null {
  const normalizedField = normalizeField(table, field);
  if (!normalizedField || !OPERATORS.has(operator)) return null;
  if (typeof value !== "string" && typeof value !== "number" && typeof value !== "boolean") return null;
  return { field: normalizedField, operator, value };
}

function parseSigmaYaml(text: string): {
  title?: string;
  description?: string;
  logsource?: { category?: string; product?: string; service?: string };
  detection?: Record<string, unknown>;
  condition?: string;
} {
  const result: Record<string, unknown> = {};
  let section = "";
  let subsection = "";
  let lastDetectionField = "";
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trimEnd();
    if (!line.trim() || line.trim().startsWith("#")) continue;
    const top = line.match(/^([A-Za-z][\w-]*):\s*(.*)$/);
    if (top && !line.startsWith(" ")) {
      section = top[1];
      subsection = "";
      result[section] = top[2] || {};
      continue;
    }
    const nested = line.match(/^\s{2}([\w-]+):\s*(.*)$/);
    if (nested) {
      const target = (result[section] as Record<string, unknown>) || {};
      target[nested[1]] = nested[2].replace(/^['"]|['"]$/g, "");
      result[section] = target;
      subsection = nested[1];
      continue;
    }
    const detectionField = line.match(/^\s{4}([\w-|]+):\s*(.*)$/);
    if (detectionField && section === "detection" && subsection) {
      const detection = result.detection as Record<string, unknown>;
      const selection = (detection[subsection] as Record<string, unknown>) || {};
      selection[detectionField[1]] = detectionField[2].replace(/^['"]|['"]$/g, "");
      detection[subsection] = selection;
      lastDetectionField = detectionField[1];
      continue;
    }
    const list = line.match(/^\s{4,}-\s+(.+)$/);
    if (list && section === "detection" && subsection && lastDetectionField) {
      const target = result.detection as Record<string, unknown>;
      const selection = (target[subsection] as Record<string, unknown>) || {};
      const existing = selection[lastDetectionField];
      selection[lastDetectionField] = Array.isArray(existing)
        ? [...existing, list[1].replace(/^['"]|['"]$/g, "")]
        : [list[1].replace(/^['"]|['"]$/g, "")];
      target[subsection] = selection;
    }
  }
  return result as ReturnType<typeof parseSigmaYaml>;
}

export function compileSigmaRule(ruleText: string): CompiledFilter {
  const rule = parseSigmaYaml(ruleText);
  const logsource = rule.logsource || {};
  let targetTable: HuntTable = "alerts";
  if (logsource.category === "process_creation" || logsource.product === "windows") targetTable = "sensor_events";
  if (logsource.category === "firewall" || logsource.service === "syslog") targetTable = "ingestion_logs";

  const detection = rule.detection || {};
  const selectionConditions = new Map<string, HuntCondition[]>();
  for (const [selectionName, rawSelection] of Object.entries(detection)) {
    if (selectionName === "condition" || typeof rawSelection !== "object" || rawSelection === null) continue;
    const compiledSelection: HuntCondition[] = [];
    for (const [rawField, rawValue] of Object.entries(rawSelection as Record<string, unknown>)) {
      const [field, ...modifiers] = rawField.split("|");
      const modifier = modifiers.join("|");
      const values = Array.isArray(rawValue) ? rawValue : [rawValue];
      for (const value of values) {
        const op: HuntOperator = modifier.includes("contains")
          ? "contains"
          : modifier.includes("startswith")
            ? "startsWith"
            : modifier.includes("endswith")
              ? "endsWith"
              : "eq";
        const parsed = condition(targetTable, field, op, typeof value === "string" ? value : String(value));
        if (!parsed) return rejected(targetTable, `Sigma field "${field}" is not supported for ${targetTable}.`);
        compiledSelection.push(parsed);
      }
    }
    if (compiledSelection.length > 0) selectionConditions.set(selectionName, compiledSelection);
  }

  if (selectionConditions.size === 0) {
    return rejected(targetTable, "Sigma rule has no supported detection conditions.");
  }

  const conditionExpression =
    typeof detection.condition === "string"
      ? detection.condition.trim()
      : typeof rule.condition === "string"
        ? rule.condition.trim()
        : "";
  if (!conditionExpression) {
    return rejected(targetTable, "Sigma rule has no supported condition expression.");
  }
  if (/\b(?:not|or)\b|\b(?:1|all)\s+of\b|\*/i.test(conditionExpression)) {
    return rejected(targetTable, `Sigma condition expression "${conditionExpression}" is not supported yet.`);
  }

  const selectionNames = conditionExpression.split(/\s+and\s+/i).map((name) => name.trim());
  if (selectionNames.some((name) => !/^[A-Za-z_][\w-]*$/.test(name) || !selectionConditions.has(name))) {
    const unknown = selectionNames.find((name) => !selectionConditions.has(name)) || conditionExpression;
    return rejected(targetTable, `Sigma condition expression references unsupported selection "${unknown}".`);
  }

  const conditions = selectionNames.flatMap((name) => selectionConditions.get(name) || []);
  if (conditions.length === 0) return rejected(targetTable, "Sigma rule has no supported detection conditions.");

  return {
    conditions,
    conditionLogic: "and",
    explanation: `Sigma rule "${rule.title || "Untitled"}": ${rule.description || "No description"}`,
    targetTable,
  };
}

export function compileYaraRule(ruleText: string): CompiledFilter {
  const targetTable: HuntTable = "alerts";
  const patterns: string[] = [];
  const stringBlock = ruleText.match(/strings:\s*\n([\s\S]*?)(?=condition:|$)/i);
  for (const line of stringBlock?.[1]?.split(/\r?\n/) || []) {
    const stringMatch = line.match(/^\s*\$\w+\s*=\s*"([^"]+)"/);
    const hexMatch = line.match(/^\s*\$\w+\s*=\s*\{([^}]+)\}/);
    if (stringMatch) patterns.push(stringMatch[1]);
    if (hexMatch) patterns.push(hexMatch[1].replace(/\s/g, ""));
  }
  const ruleName = ruleText.match(/rule\s+(\w+)/i)?.[1] || "Untitled YARA Rule";
  if (patterns.length === 0) {
    return rejected(targetTable, "YARA rule contains no supported string patterns.");
  }
  return {
    conditions: patterns.map((value) => ({ field: "payloadText", operator: "contains", value })),
    conditionLogic: "or",
    explanation: `YARA rule "${ruleName}": searches for ${patterns.length} string pattern(s) across alert payloads`,
    targetTable,
  };
}

export function compileKqlQuery(kqlText: string): CompiledFilter {
  const parts = kqlText
    .split("|")
    .map((part) => part.trim())
    .filter(Boolean);
  let targetTable: HuntTable = "alerts";
  const conditions: HuntCondition[] = [];
  for (const part of parts) {
    if (TABLES.has(part.toLowerCase() as HuntTable)) {
      targetTable = part.toLowerCase() as HuntTable;
      continue;
    }
    const match = part.match(
      /^where\s+([A-Za-z_][\w]*)\s*(==|!=|contains|>|<)\s*(?:"([^"]*)"|'([^']*)'|(-?\d+(?:\.\d+)?))$/i,
    );
    if (!match) return rejected(targetTable, `Unsupported KQL expression: "${part}".`);
    const value = match[3] ?? match[4] ?? (match[5] !== undefined ? Number(match[5]) : "");
    const operator: HuntOperator =
      match[2] === "=="
        ? "eq"
        : match[2] === "!="
          ? "neq"
          : match[2] === ">"
            ? "gt"
            : match[2] === "<"
              ? "lt"
              : "contains";
    const parsed = condition(targetTable, match[1], operator, value);
    if (!parsed) return rejected(targetTable, `KQL field "${match[1]}" is not supported for ${targetTable}.`);
    conditions.push(parsed);
  }
  if (conditions.length === 0)
    return rejected(targetTable, "A KQL hunt must contain at least one supported where condition.");
  return {
    conditions,
    conditionLogic: "and",
    explanation: `KQL query with ${conditions.length} filter condition(s)`,
    targetTable,
  };
}

export function compileSqlQuery(sqlText: string): CompiledFilter {
  const normalized = sqlText.trim();
  const header = normalized.match(
    /^SELECT\s+\*\s+FROM\s+(alerts|ingestion_logs|sensor_events)\s*(?:WHERE\s+([\s\S]*?))?(?:ORDER\s+BY[\s\S]*)?$/i,
  );
  if (!header)
    return rejected(
      "alerts",
      "SQL hunts only support SELECT * from an allowlisted event table with simple AND filters.",
    );
  const targetTable = header[1].toLowerCase() as HuntTable;
  const whereText = (header[2] || "").trim();
  if (!whereText) return rejected(targetTable, "SQL hunts require at least one supported WHERE condition.");
  if (/[();]|--|\/\*|\*\/|\b(OR|UNION|JOIN|SELECT|DROP|INSERT|UPDATE|DELETE)\b/i.test(whereText)) {
    return rejected(
      targetTable,
      "SQL query rejected: only simple AND equality, comparison, and text filters are supported.",
    );
  }
  const conditions: HuntCondition[] = [];
  for (const fragment of whereText.split(/\s+AND\s+/i)) {
    const match = fragment.trim().match(/^([A-Za-z_][\w]*)\s*(=|!=|>|<|LIKE|ILIKE)\s*(['"])(.*?)\3$/i);
    if (!match) return rejected(targetTable, `Unsupported SQL condition: "${fragment.trim()}".`);
    const operator: HuntOperator =
      match[2] === "="
        ? "eq"
        : match[2] === "!="
          ? "neq"
          : match[2] === ">"
            ? "gt"
            : match[2] === "<"
              ? "lt"
              : "contains";
    const value = operator === "contains" ? match[4].replace(/^%|%$/g, "") : match[4];
    const parsed = condition(targetTable, match[1], operator, value);
    if (!parsed) return rejected(targetTable, `SQL field "${match[1]}" is not supported for ${targetTable}.`);
    conditions.push(parsed);
  }
  return { conditions, conditionLogic: "and", explanation: `Structured SQL query against ${targetTable}`, targetTable };
}

export function compileQuery(queryType: string, queryText: string): CompiledFilter {
  switch (queryType) {
    case "sigma":
      return compileSigmaRule(queryText);
    case "yara":
      return compileYaraRule(queryText);
    case "kql":
      return compileKqlQuery(queryText);
    case "sql":
      return compileSqlQuery(queryText);
    default:
      return rejected("alerts", `Query type "${queryType}" is not executable.`);
  }
}
