import { redactSensitiveText } from "@shared/redaction";

export function maskUntrustedText(value: string): string {
  return redactSensitiveText(value, "off").text;
}

export function hasMaskedUntrustedText(value: string): boolean {
  return maskUntrustedText(value) !== value;
}
