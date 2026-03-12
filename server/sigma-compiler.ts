/**
 * Sigma Rule Compiler
 *
 * Compiles Sigma detection rules, YARA rules, and KQL queries
 * into SQL-compatible filter expressions that can be executed
 * against the event store (alerts / ingestion_logs / sensor_events).
 */

export interface CompiledFilter {
  /** SQL WHERE clause fragment (parameterised with $1, $2, ...) */
  whereClause: string;
  /** Ordered parameter values */
  params: unknown[];
  /** Human-readable explanation of what the compiled query matches */
  explanation: string;
  /** Target table to query against */
  targetTable: "alerts" | "ingestion_logs" | "sensor_events";
}

// ─── Sigma Rule Compiler ────────────────────────────────────────────────────

interface SigmaDetection {
  [key: string]: Record<string, string | string[] | number | boolean> | string | string[];
}

interface SigmaRule {
  title?: string;
  description?: string;
  logsource?: { category?: string; product?: string; service?: string };
  detection?: { condition?: string } & SigmaDetection;
  level?: string;
}

function parseSigmaYaml(text: string): SigmaRule {
  // Lightweight YAML-subset parser for Sigma rules
  const rule: Record<string, unknown> = {};
  const lines = text.split("\n");
  let currentKey = "";
  let currentBlock: Record<string, unknown> = {};
  let inBlock = false;

  for (const rawLine of lines) {
    const line = rawLine.replace(/\r$/, "");
    if (line.trim() === "" || line.trim().startsWith("#")) continue;

    const topMatch = line.match(/^(\w[\w-]*):\s*(.*)/);
    if (topMatch && !line.startsWith("  ")) {
      if (inBlock && currentKey) {
        rule[currentKey] = currentBlock;
      }
      currentKey = topMatch[1];
      const val = topMatch[2].trim();
      if (val) {
        rule[currentKey] = val;
        inBlock = false;
      } else {
        currentBlock = {};
        inBlock = true;
      }
      continue;
    }

    if (inBlock) {
      const kvMatch = line.match(/^\s{2,}(\w[\w-|]*):\s*(.*)/);
      if (kvMatch) {
        const k = kvMatch[1];
        let v: unknown = kvMatch[2].trim();
        if (typeof v === "string" && v.startsWith("'") && v.endsWith("'")) v = v.slice(1, -1);
        if (typeof v === "string" && v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
        currentBlock[k] = v;
      }
      const listMatch = line.match(/^\s{4,}-\s+(.*)/);
      if (listMatch) {
        // Find the parent key
        const parentKey = Object.keys(currentBlock).pop();
        if (parentKey) {
          const existing = currentBlock[parentKey];
          if (Array.isArray(existing)) {
            existing.push(listMatch[1].trim().replace(/^['"]|['"]$/g, ""));
          } else {
            currentBlock[parentKey] = [String(existing || ""), listMatch[1].trim().replace(/^['"]|['"]$/g, "")].filter(
              Boolean,
            );
          }
        }
      }
    }
  }
  if (inBlock && currentKey) {
    rule[currentKey] = currentBlock;
  }
  return rule as unknown as SigmaRule;
}

function sigmaDetectionToSql(detection: SigmaDetection): { where: string; params: unknown[] } {
  const params: unknown[] = [];
  const clauses: string[] = [];

  for (const [key, value] of Object.entries(detection)) {
    if (key === "condition") continue;
    if (typeof value === "object" && value !== null && !Array.isArray(value)) {
      for (const [field, pattern] of Object.entries(value as Record<string, unknown>)) {
        const cleanField = field.replace(/\|.*$/, ""); // strip modifiers like |contains
        const modifier = field.includes("|") ? field.split("|").slice(1).join("|") : "";

        if (Array.isArray(pattern)) {
          const orClauses = pattern.map((p) => {
            params.push(modifier.includes("contains") ? `%${p}%` : String(p));
            return modifier.includes("contains")
              ? `LOWER(raw_payload::text) LIKE LOWER($${params.length})`
              : `raw_payload->>'${sanitizeFieldName(cleanField)}' = $${params.length}`;
          });
          clauses.push(`(${orClauses.join(" OR ")})`);
        } else {
          const strPattern = String(pattern);
          if (modifier.includes("contains")) {
            params.push(`%${strPattern}%`);
            clauses.push(`LOWER(raw_payload::text) LIKE LOWER($${params.length})`);
          } else if (modifier.includes("startswith")) {
            params.push(`${strPattern}%`);
            clauses.push(`raw_payload->>'${sanitizeFieldName(cleanField)}' LIKE $${params.length}`);
          } else if (modifier.includes("endswith")) {
            params.push(`%${strPattern}`);
            clauses.push(`raw_payload->>'${sanitizeFieldName(cleanField)}' LIKE $${params.length}`);
          } else {
            params.push(strPattern);
            clauses.push(`raw_payload->>'${sanitizeFieldName(cleanField)}' = $${params.length}`);
          }
        }
      }
    }
  }

  return { where: clauses.length > 0 ? clauses.join(" AND ") : "1=1", params };
}

function sanitizeFieldName(name: string): string {
  return name.replace(/[^a-zA-Z0-9_.]/g, "");
}

export function compileSigmaRule(ruleText: string): CompiledFilter {
  const rule = parseSigmaYaml(ruleText);
  const detection = rule.detection || {};
  const { where, params } = sigmaDetectionToSql(detection);

  // Determine target table based on logsource
  let targetTable: CompiledFilter["targetTable"] = "alerts";
  if (rule.logsource?.category === "process_creation" || rule.logsource?.product === "windows") {
    targetTable = "sensor_events";
  } else if (rule.logsource?.category === "firewall" || rule.logsource?.service === "syslog") {
    targetTable = "ingestion_logs";
  }

  return {
    whereClause: where,
    params,
    explanation: `Sigma rule "${rule.title || "Untitled"}": ${rule.description || "No description"}`,
    targetTable,
  };
}

// ─── YARA Rule Compiler ─────────────────────────────────────────────────────

export function compileYaraRule(ruleText: string): CompiledFilter {
  // Extract string patterns from YARA rules to search in event payloads
  const stringMatches: string[] = [];
  const stringBlock = ruleText.match(/strings:\s*\n([\s\S]*?)(?=condition:|$)/);

  if (stringBlock) {
    const lines = stringBlock[1].split("\n");
    for (const line of lines) {
      const match = line.match(/\$\w+\s*=\s*"([^"]+)"/);
      if (match) {
        stringMatches.push(match[1]);
      }
      // Hex patterns
      const hexMatch = line.match(/\$\w+\s*=\s*\{([^}]+)\}/);
      if (hexMatch) {
        stringMatches.push(hexMatch[1].replace(/\s/g, ""));
      }
    }
  }

  const params: unknown[] = [];
  const clauses = stringMatches.map((s) => {
    params.push(`%${s}%`);
    return `LOWER(raw_payload::text) LIKE LOWER($${params.length})`;
  });

  // Extract rule name
  const nameMatch = ruleText.match(/rule\s+(\w+)/);
  const ruleName = nameMatch ? nameMatch[1] : "Untitled YARA Rule";

  return {
    whereClause: clauses.length > 0 ? clauses.join(" OR ") : "1=1",
    params,
    explanation: `YARA rule "${ruleName}": searches for ${stringMatches.length} string pattern(s) across event payloads`,
    targetTable: "alerts",
  };
}

// ─── KQL Compiler ───────────────────────────────────────────────────────────

export function compileKqlQuery(kqlText: string): CompiledFilter {
  const params: unknown[] = [];
  const clauses: string[] = [];

  // Parse KQL-like syntax: Table | where Field == "value" | where Field contains "value"
  const lines = kqlText
    .split("|")
    .map((s) => s.trim())
    .filter(Boolean);

  let targetTable: CompiledFilter["targetTable"] = "alerts";

  for (const line of lines) {
    // Table name
    const tableMatch = line.match(/^(alerts|ingestion_logs|sensor_events)$/i);
    if (tableMatch) {
      targetTable = tableMatch[1].toLowerCase() as CompiledFilter["targetTable"];
      continue;
    }

    // where Field == "value"
    const eqMatch = line.match(/where\s+(\w+)\s*==\s*"([^"]+)"/i);
    if (eqMatch) {
      params.push(eqMatch[2]);
      clauses.push(`"${sanitizeFieldName(eqMatch[1])}" = $${params.length}`);
      continue;
    }

    // where Field != "value"
    const neqMatch = line.match(/where\s+(\w+)\s*!=\s*"([^"]+)"/i);
    if (neqMatch) {
      params.push(neqMatch[2]);
      clauses.push(`"${sanitizeFieldName(neqMatch[1])}" != $${params.length}`);
      continue;
    }

    // where Field contains "value"
    const containsMatch = line.match(/where\s+(\w+)\s+contains\s+"([^"]+)"/i);
    if (containsMatch) {
      params.push(`%${containsMatch[2]}%`);
      clauses.push(`"${sanitizeFieldName(containsMatch[1])}"::text ILIKE $${params.length}`);
      continue;
    }

    // where Field > number
    const gtMatch = line.match(/where\s+(\w+)\s*>\s*(\d+)/i);
    if (gtMatch) {
      params.push(Number(gtMatch[2]));
      clauses.push(`"${sanitizeFieldName(gtMatch[1])}"::numeric > $${params.length}`);
      continue;
    }

    // where Field < number
    const ltMatch = line.match(/where\s+(\w+)\s*<\s*(\d+)/i);
    if (ltMatch) {
      params.push(Number(ltMatch[2]));
      clauses.push(`"${sanitizeFieldName(ltMatch[1])}"::numeric < $${params.length}`);
      continue;
    }

    // where Field in ("a","b","c")
    const inMatch = line.match(/where\s+(\w+)\s+in\s*\(([^)]+)\)/i);
    if (inMatch) {
      const values = inMatch[2].split(",").map((v) => v.trim().replace(/^["']|["']$/g, ""));
      for (const v of values) {
        params.push(v);
      }
      const placeholders = values.map((_, i) => `$${params.length - values.length + i + 1}`).join(", ");
      clauses.push(`"${sanitizeFieldName(inMatch[1])}" IN (${placeholders})`);
      continue;
    }
  }

  return {
    whereClause: clauses.length > 0 ? clauses.join(" AND ") : "1=1",
    params,
    explanation: `KQL query with ${clauses.length} filter condition(s)`,
    targetTable,
  };
}

// ─── SQL Pass-through ───────────────────────────────────────────────────────

// Dangerous SQL keywords/patterns that indicate injection attempts
const SQL_INJECTION_PATTERNS = [
  /;\s*(DROP|DELETE|TRUNCATE|ALTER|CREATE|INSERT|UPDATE|GRANT|REVOKE)\s/i,
  /;\s*$/,
  /--\s/,
  /\/\*[\s\S]*?\*\//,
  /\bUNION\s+(ALL\s+)?SELECT\b/i,
  /\bINTO\s+(OUT|DUMP)FILE\b/i,
  /\bLOAD_FILE\s*\(/i,
  /\bEXEC(UTE)?\s*\(/i,
  /\bxp_\w+/i,
  /\bpg_\w+\s*\(/i,
  /\bINFORMATION_SCHEMA\b/i,
];

export function compileSqlQuery(sqlText: string): CompiledFilter {
  // Extract WHERE clause from raw SQL — only allow SELECT queries
  const normalized = sqlText.trim();
  if (!/^SELECT\s/i.test(normalized)) {
    return {
      whereClause: "1=0",
      params: [],
      explanation: "Only SELECT queries are allowed",
      targetTable: "alerts",
    };
  }

  // Reject queries containing multiple statements or injection patterns
  for (const pattern of SQL_INJECTION_PATTERNS) {
    if (pattern.test(normalized)) {
      return {
        whereClause: "1=0",
        params: [],
        explanation: "Query rejected: potentially unsafe SQL pattern detected",
        targetTable: "alerts",
      };
    }
  }

  // Determine target table
  let targetTable: CompiledFilter["targetTable"] = "alerts";
  if (/FROM\s+ingestion_logs/i.test(normalized)) targetTable = "ingestion_logs";
  else if (/FROM\s+sensor_events/i.test(normalized)) targetTable = "sensor_events";

  const whereMatch = normalized.match(/WHERE\s+([\s\S]+?)(?:ORDER|GROUP|LIMIT|$)/i);
  const whereClause = whereMatch ? whereMatch[1].trim() : "1=1";

  // Final check: reject WHERE clause if it still contains suspicious patterns
  for (const pattern of SQL_INJECTION_PATTERNS) {
    if (pattern.test(whereClause)) {
      return {
        whereClause: "1=0",
        params: [],
        explanation: "WHERE clause rejected: potentially unsafe SQL pattern detected",
        targetTable,
      };
    }
  }

  return {
    whereClause,
    params: [],
    explanation: `Raw SQL query against ${targetTable}`,
    targetTable,
  };
}

// ─── Unified Compiler ───────────────────────────────────────────────────────

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
    case "custom":
      return {
        whereClause: "1=1",
        params: [],
        explanation: "Custom query — manual review required",
        targetTable: "alerts",
      };
    default:
      return {
        whereClause: "1=0",
        params: [],
        explanation: `Unknown query type: ${queryType}`,
        targetTable: "alerts",
      };
  }
}
