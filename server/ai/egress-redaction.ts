export type PiiMaskingMode = "mask_identifiers" | "mask_all" | "off";

export interface RedactionCount {
  kind: string;
  count: number;
}

export interface RedactionResult {
  text: string;
  redactions: RedactionCount[];
}

interface RedactionRule {
  kind: string;
  pattern: RegExp;
}

const SECRET_RULES: RedactionRule[] = [
  { kind: "aws_access_key", pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g },
  { kind: "bearer_token", pattern: /\bBearer\s+[A-Za-z0-9._~+/=-]{12,}/gi },
  { kind: "jwt", pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9._-]{8,}\.[A-Za-z0-9._-]{8,}\b/g },
  { kind: "private_key", pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
  {
    kind: "connection_string",
    pattern: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s/]+:[^@\s]+@[^\s]+/gi,
  },
  {
    kind: "credential_value",
    pattern:
      /\b(?:password|passwd|pwd|secret|token|api[_-]?key|client_secret|session|set-cookie)\s*[:=]\s*["']?[^"',;\s}]+/gi,
  },
  { kind: "authorization", pattern: /\bAuthorization\s*:\s*[^\r\n]+/gi },
  { kind: "openai_key", pattern: /\bsk-[A-Za-z0-9_-]{16,}\b/g },
  { kind: "github_token", pattern: /\bghp_[A-Za-z0-9]{20,}\b/g },
  { kind: "slack_token", pattern: /\bxox[baprs]-[A-Za-z0-9-]{12,}\b/g },
  { kind: "google_api_key", pattern: /\bAIza[A-Za-z0-9_-]{20,}\b/g },
  { kind: "stripe_key", pattern: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
  {
    kind: "aws_secret_adjacent",
    pattern: /\b(?:aws_secret_access_key|secret_access_key)\s*[:=]\s*[A-Za-z0-9/+=]{20,}/gi,
  },
];

const EMAIL_PATTERN = /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g;
const USER_IDENTIFIER_PATTERN =
  /\b(?:user(?:name|_id)?|account(?:_id)?|employee(?:_id)?|principal)\s*[:=]\s*[^\s,;]+/gi;
const IP_PATTERN = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const HOSTNAME_PATTERN = /\b(?=[a-z0-9.-]{3,253}\b)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi;
const CREDIT_CARD_PATTERN = /\b(?:\d[ -]*?){13,19}\b/g;

function luhnValid(value: string): boolean {
  const digits = value.replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let alternate = false;
  for (let index = digits.length - 1; index >= 0; index--) {
    let digit = Number(digits[index]);
    if (alternate) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

function replaceRule(text: string, rule: RedactionRule, counts: Map<string, number>): string {
  return text.replace(rule.pattern, () => {
    counts.set(rule.kind, (counts.get(rule.kind) ?? 0) + 1);
    return `[REDACTED:${rule.kind}]`;
  });
}

export function redactEgress(text: string, piiMasking: PiiMaskingMode = "mask_identifiers"): RedactionResult {
  const counts = new Map<string, number>();
  let result = text;

  for (const rule of SECRET_RULES) result = replaceRule(result, rule, counts);
  result = result.replace(CREDIT_CARD_PATTERN, (match) => {
    if (!luhnValid(match)) return match;
    counts.set("credit_card", (counts.get("credit_card") ?? 0) + 1);
    return "[REDACTED:credit_card]";
  });

  if (piiMasking !== "off") {
    result = result.replace(EMAIL_PATTERN, () => {
      counts.set("email", (counts.get("email") ?? 0) + 1);
      return "[REDACTED:email]";
    });
    result = result.replace(USER_IDENTIFIER_PATTERN, () => {
      counts.set("user_identifier", (counts.get("user_identifier") ?? 0) + 1);
      return "[REDACTED:user_identifier]";
    });
  }
  if (piiMasking === "mask_all") {
    result = result.replace(IP_PATTERN, () => {
      counts.set("ip", (counts.get("ip") ?? 0) + 1);
      return "[REDACTED:ip]";
    });
    result = result.replace(HOSTNAME_PATTERN, (match) => {
      if (match.startsWith("[REDACTED:")) return match;
      counts.set("hostname", (counts.get("hostname") ?? 0) + 1);
      return "[REDACTED:hostname]";
    });
  }

  return {
    text: result,
    redactions: Array.from(counts.entries()).map(([kind, count]) => ({ kind, count })),
  };
}

export function mergeRedactionCounts(...groups: RedactionCount[][]): RedactionCount[] {
  const counts = new Map<string, number>();
  for (const group of groups) {
    for (const { kind, count } of group) counts.set(kind, (counts.get(kind) ?? 0) + count);
  }
  return Array.from(counts.entries()).map(([kind, count]) => ({ kind, count }));
}
