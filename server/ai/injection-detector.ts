export type InjectionSeverity = "suspected" | "likely" | "none";

export interface InjectionSignal {
  rule: string;
  excerpt: string;
}

export interface InjectionDetection {
  detected: boolean;
  score: number;
  severity: InjectionSeverity;
  signals: InjectionSignal[];
}

const ZERO_WIDTH_OR_BIDI = /[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g;
const CONTROL_OR_ZERO_WIDTH = /[\u0000-\u001f\u007f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g;

function normalizeContent(content: string): string {
  return content.replace(ZERO_WIDTH_OR_BIDI, "").replace(/\s+/g, " ").trim();
}

function excerpt(content: string, index = 0): string {
  const normalized = content.replace(CONTROL_OR_ZERO_WIDTH, " ").replace(/\s+/g, " ").trim();
  const start = Math.max(0, Math.min(index, Math.max(0, normalized.length - 120)));
  return normalized.slice(start, start + 120);
}

function hasRule(content: string, pattern: RegExp): number {
  const match = pattern.exec(content);
  return match?.index ?? -1;
}

export function detectInjection(content: string): InjectionDetection {
  const normalized = normalizeContent(content);
  const signals: InjectionSignal[] = [];
  const add = (rule: string, index: number): void => {
    if (index >= 0) signals.push({ rule, excerpt: excerpt(content, index) });
  };

  add(
    "instruction_override",
    hasRule(
      normalized,
      /\b(?:ignore|disregard|forget|override)\s+(?:the\s+)?(?:previous|prior|above|earlier|all)\s+(?:instructions?|prompts?|rules?|directions?)\b/i,
    ),
  );
  add(
    "system_prompt_probe",
    hasRule(
      normalized,
      /\b(?:system\s+prompt|developer\s+message|your\s+instructions|reveal\s+(?:the\s+)?prompt|repeat\s+the\s+text\s+above)\b/i,
    ),
  );
  add(
    "role_injection",
    hasRule(normalized, /(?:^|\s)(?:system:|assistant:|user:|<\|im_start\|>|\[INST\]|###\s*(?:system|instruction))\b/i),
  );
  add(
    "fence_forgery",
    hasRule(normalized, /<<\/?UNTRUSTED_EVIDENCE\b|<<\/UNTRUSTED_EVIDENCE\b[^>]*\bid="[0-9a-f]{16}"/i),
  );
  add(
    "verdict_steering",
    hasRule(
      normalized,
      /\b(?:ignore|disregard|override|you\s+must|mark\s+(?:this\s+)?(?:alert|event|finding)|classify\s+(?:this\s+)?(?:alert|event|finding)|set\s+the\s+verdict|declare\s+(?:this\s+)?(?:alert|event|finding))\b.{0,80}\b(?:benign|false\s*positive|informational|resolved|close|lower\s+severity|authorized\s+testing|bypass)\b/i,
    ),
  );
  add(
    "exfiltration_attempt",
    hasRule(
      normalized,
      /\b(?:send|post|curl|fetch|upload|email)\b.{0,80}(?:https?:\/\/|www\.|(?:\d{1,3}\.){3}\d{1,3}|webhook\b)|(?:data:|file:\/\/)/i,
    ),
  );
  add(
    "tool_or_action_request",
    hasRule(
      normalized,
      /\b(?:you\s+must|you\s+should\s+now|immediately)\b.{0,100}\b(?:execute|run\s+(?:the\s+)?command|isolate\s+(?:the\s+)?host|disable|delete|block\s+(?:the\s+)?ip)\b/i,
    ),
  );
  add("obfuscation", hasRule(normalized, /(?:[A-Za-z0-9+/]{512,}={0,2}|[0-9a-f]{512,})/i));
  if (content.length >= 200) {
    const nonAscii = Array.from(content).filter((char) => char.charCodeAt(0) > 127).length;
    if (nonAscii / content.length > 0.2) add("obfuscation", 0);
  }
  const zeroWidthIndex = content.search(ZERO_WIDTH_OR_BIDI);
  add("zero_width_or_bidi", zeroWidthIndex);
  add(
    "prompt_leak_bait",
    hasRule(
      normalized,
      /\b(?:print|output|show|list|identify)\b.{0,80}\b(?:your\s+configuration|system\s+prompt|developer\s+message|internal\s+instructions?|available\s+tools?|model\s+configuration)\b/i,
    ),
  );

  const distinctRules = Array.from(new Map(signals.map((signal) => [signal.rule, signal])).values());
  const score = distinctRules.length;
  return {
    detected: score >= 1,
    score,
    severity: score >= 3 ? "likely" : score >= 1 ? "suspected" : "none",
    signals: distinctRules,
  };
}

export function detectUntrustedContent(blocks: { label: string; content: string }[]): InjectionDetection {
  const detections = blocks.map((block) => detectInjection(block.content)).filter((result) => result.detected);
  const signals = detections.flatMap((result) => result.signals);
  const score = Array.from(new Set(signals.map((signal) => signal.rule))).length;
  return {
    detected: score >= 1,
    score,
    severity: score >= 3 ? "likely" : score >= 1 ? "suspected" : "none",
    signals: Array.from(new Map(signals.map((signal) => [signal.rule, signal])).values()),
  };
}

export function normalizeForInjectionDetection(content: string): string {
  return normalizeContent(content);
}
