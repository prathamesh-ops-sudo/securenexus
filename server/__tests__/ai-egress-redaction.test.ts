import { describe, expect, it } from "vitest";
import { redactEgress } from "../ai/egress-redaction";

describe("AI egress redaction", () => {
  it("redacts secrets and preserves a stable placeholder on repeated passes", () => {
    const input = "AKIA1234567890ABCDEF Bearer abcdefghijklmnop password=secret";
    const once = redactEgress(input);
    const twice = redactEgress(once.text);
    expect(once.text).toContain("[REDACTED:aws_access_key]");
    expect(once.text).toContain("[REDACTED:bearer_token]");
    expect(once.text).toContain("[REDACTED:credential_value]");
    expect(twice.text).toBe(once.text);
  });

  it("masks identifiers without masking network evidence by default", () => {
    const result = redactEgress("user@example.com from 10.0.0.5 host.example.com port 443 hash abc123");
    expect(result.text).toContain("[REDACTED:email]");
    expect(result.text).toContain("10.0.0.5");
    expect(result.text).toContain("host.example.com");
    expect(result.text).toContain("443");
  });

  it("supports mask_all while always redacting secrets", () => {
    const result = redactEgress("user@example.com 10.0.0.5 host.example.com", "mask_all");
    expect(result.text).toContain("[REDACTED:email]");
    expect(result.text).toContain("[REDACTED:ip]");
    expect(result.text).toContain("[REDACTED:hostname]");
  });
});
