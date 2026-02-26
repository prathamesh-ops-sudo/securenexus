/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../logger", () => ({
  logger: {
    child: () => ({
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    }),
  },
}));

import {
  validateWebhookUrl,
  getCircuitState,
  isCircuitOpen,
  recordDeliverySuccess,
  recordDeliveryFailure,
  resetCircuitBreaker,
  isWebhookRateLimited,
  redactDeliveryLog,
  getCircuitBreakerStatus,
  getOutboundSecurityStats,
} from "../outbound-security";

describe("Webhook Delivery Tests", () => {
  beforeEach(() => {
    resetCircuitBreaker("test-webhook");
    resetCircuitBreaker("wh-rate");
  });

  describe("validateWebhookUrl — SSRF protection", () => {
    it("accepts valid HTTPS URL", () => {
      const result = validateWebhookUrl("https://hooks.slack.com/services/T00/B00/xxx");
      expect(result.valid).toBe(true);
    });

    it("accepts valid HTTP URL", () => {
      const result = validateWebhookUrl("http://webhook.example.com/receive");
      expect(result.valid).toBe(true);
    });

    it("rejects empty URL", () => {
      const result = validateWebhookUrl("");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("required");
    });

    it("rejects null-like input", () => {
      const result = validateWebhookUrl(null as any);
      expect(result.valid).toBe(false);
    });

    it("rejects invalid URL format", () => {
      const result = validateWebhookUrl("not-a-url");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("Invalid URL");
    });

    it("rejects file: scheme", () => {
      const result = validateWebhookUrl("file:///etc/passwd");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("not allowed");
    });

    it("rejects ftp: scheme", () => {
      const result = validateWebhookUrl("ftp://evil.com/payload");
      expect(result.valid).toBe(false);
    });

    it("rejects gopher: scheme", () => {
      const result = validateWebhookUrl("gopher://evil.com/");
      expect(result.valid).toBe(false);
    });

    it("rejects data: scheme", () => {
      const result = validateWebhookUrl("data:text/html,<script>alert(1)</script>");
      expect(result.valid).toBe(false);
    });

    it("rejects javascript: scheme", () => {
      const result = validateWebhookUrl("javascript:alert(1)");
      expect(result.valid).toBe(false);
    });

    it("rejects localhost", () => {
      const result = validateWebhookUrl("http://localhost:8080/hook");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("loopback");
    });

    it("rejects 127.0.0.1", () => {
      const result = validateWebhookUrl("http://127.0.0.1/hook");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("loopback");
    });

    it("rejects 0.0.0.0", () => {
      const result = validateWebhookUrl("http://0.0.0.0/hook");
      expect(result.valid).toBe(false);
    });

    it("rejects [::1] IPv6 loopback", () => {
      const result = validateWebhookUrl("http://[::1]/hook");
      expect(result.valid).toBe(false);
    });

    it("rejects 10.x.x.x private range", () => {
      const result = validateWebhookUrl("http://10.0.0.1/hook");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("Private");
    });

    it("rejects 192.168.x.x private range", () => {
      const result = validateWebhookUrl("http://192.168.1.1/hook");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("Private");
    });

    it("rejects 172.16-31.x.x private range", () => {
      const result = validateWebhookUrl("http://172.16.0.1/hook");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("Private");

      const result2 = validateWebhookUrl("http://172.31.255.255/hook");
      expect(result2.valid).toBe(false);
    });

    it("rejects 169.254.x.x link-local", () => {
      const result = validateWebhookUrl("http://169.254.1.1/hook");
      expect(result.valid).toBe(false);
    });

    it("rejects AWS metadata endpoint (169.254.169.254)", () => {
      const result = validateWebhookUrl("http://169.254.169.254/latest/meta-data/");
      expect(result.valid).toBe(false);
    });

    it("rejects Google metadata endpoint", () => {
      const result = validateWebhookUrl("http://metadata.google.internal/computeMetadata/v1/");
      expect(result.valid).toBe(false);
    });

    it("rejects Kubernetes internal endpoints", () => {
      const result = validateWebhookUrl("http://kubernetes.default.svc/api");
      expect(result.valid).toBe(false);
    });

    it("rejects URLs with embedded credentials", () => {
      const result = validateWebhookUrl("http://admin:password@example.com/hook");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("Credentials");
    });

    it("rejects .local TLD", () => {
      const result = validateWebhookUrl("http://server.local/hook");
      expect(result.valid).toBe(false);
      expect(result.reason).toContain("Local");
    });

    it("rejects .internal TLD", () => {
      const result = validateWebhookUrl("http://service.internal/hook");
      expect(result.valid).toBe(false);
    });

    it("rejects .localhost TLD", () => {
      const result = validateWebhookUrl("http://app.localhost/hook");
      expect(result.valid).toBe(false);
    });

    it("rejects IPv6 private address (fd00 in INTERNAL_HOSTNAMES or detected)", () => {
      const result = validateWebhookUrl("http://fd00::1/hook");
      expect(result.valid).toBe(false);
    });

    it("rejects IPv6 link-local (fe80 in INTERNAL_HOSTNAMES or detected)", () => {
      const result = validateWebhookUrl("http://fe80::1/hook");
      expect(result.valid).toBe(false);
    });
  });

  describe("circuit breaker — state transitions", () => {
    it("starts in closed state", () => {
      const state = getCircuitState("fresh-webhook");
      expect(state.state).toBe("closed");
      expect(state.failures).toBe(0);
      resetCircuitBreaker("fresh-webhook");
    });

    it("stays closed after single failure", () => {
      recordDeliveryFailure("test-webhook");
      const state = getCircuitState("test-webhook");
      expect(state.state).toBe("closed");
      expect(state.failures).toBe(1);
    });

    it("opens after 5 consecutive failures", () => {
      for (let i = 0; i < 5; i++) {
        recordDeliveryFailure("test-webhook");
      }
      const state = getCircuitState("test-webhook");
      expect(state.state).toBe("open");
      expect(state.failures).toBe(5);
    });

    it("isCircuitOpen returns true when circuit is open", () => {
      for (let i = 0; i < 5; i++) {
        recordDeliveryFailure("test-webhook");
      }
      expect(isCircuitOpen("test-webhook")).toBe(true);
    });

    it("isCircuitOpen returns false when circuit is closed", () => {
      expect(isCircuitOpen("test-webhook")).toBe(false);
    });

    it("resets to closed on successful delivery", () => {
      for (let i = 0; i < 3; i++) {
        recordDeliveryFailure("test-webhook");
      }
      recordDeliverySuccess("test-webhook");

      const state = getCircuitState("test-webhook");
      expect(state.state).toBe("closed");
      expect(state.failures).toBe(0);
    });

    it("tracks last failure timestamp", () => {
      const before = Date.now();
      recordDeliveryFailure("test-webhook");
      const state = getCircuitState("test-webhook");
      expect(state.lastFailure).toBeGreaterThanOrEqual(before);
      expect(state.lastFailure).toBeLessThanOrEqual(Date.now());
    });

    it("getCircuitBreakerStatus returns correct status", () => {
      recordDeliveryFailure("test-webhook");
      recordDeliveryFailure("test-webhook");
      const status = getCircuitBreakerStatus("test-webhook");
      expect(status.state).toBe("closed");
      expect(status.failures).toBe(2);
      expect(status.lastFailure).toBeGreaterThan(0);
    });

    it("resetCircuitBreaker clears all state", () => {
      for (let i = 0; i < 5; i++) {
        recordDeliveryFailure("test-webhook");
      }
      expect(isCircuitOpen("test-webhook")).toBe(true);

      resetCircuitBreaker("test-webhook");

      expect(isCircuitOpen("test-webhook")).toBe(false);
      const state = getCircuitState("test-webhook");
      expect(state.failures).toBe(0);
      expect(state.state).toBe("closed");
    });
  });

  describe("rate limiting", () => {
    it("allows first request", () => {
      expect(isWebhookRateLimited("wh-rate")).toBe(false);
    });

    it("allows up to 100 requests in a window", () => {
      for (let i = 0; i < 99; i++) {
        expect(isWebhookRateLimited("wh-rate")).toBe(false);
      }
    });

    it("blocks after 100 requests in same window", () => {
      for (let i = 0; i < 100; i++) {
        isWebhookRateLimited("wh-rate");
      }
      expect(isWebhookRateLimited("wh-rate")).toBe(true);
    });

    it("different webhook IDs have independent limits", () => {
      for (let i = 0; i < 100; i++) {
        isWebhookRateLimited("wh-A");
      }
      expect(isWebhookRateLimited("wh-A")).toBe(true);
      expect(isWebhookRateLimited("wh-B")).toBe(false);

      resetCircuitBreaker("wh-A");
      resetCircuitBreaker("wh-B");
    });
  });

  describe("redactDeliveryLog — sensitive data redaction", () => {
    it("redacts password fields", () => {
      const result = redactDeliveryLog({ password: "hunter2", username: "admin" }) as any;
      expect(result.password).toBe("[REDACTED]");
      expect(result.username).toBe("admin");
    });

    it("redacts secret fields", () => {
      const result = redactDeliveryLog({ clientSecret: "abc123", clientId: "pub-123" }) as any;
      expect(result.clientSecret).toBe("[REDACTED]");
      expect(result.clientId).toBe("pub-123");
    });

    it("redacts token fields", () => {
      const result = redactDeliveryLog({ accessToken: "eyJhbGci...", refreshToken: "rt-abc" }) as any;
      expect(result.accessToken).toBe("[REDACTED]");
      expect(result.refreshToken).toBe("[REDACTED]");
    });

    it("redacts apikey and api_key fields", () => {
      const result = redactDeliveryLog({ apikey: "ak-123", api_key: "ak-456" }) as any;
      expect(result.apikey).toBe("[REDACTED]");
      expect(result.api_key).toBe("[REDACTED]");
    });

    it("redacts authorization fields", () => {
      const result = redactDeliveryLog({ authorization: "Bearer abc123" }) as any;
      expect(result.authorization).toBe("[REDACTED]");
    });

    it("redacts credential and private_key fields", () => {
      const result = redactDeliveryLog({
        credential: "cred-abc",
        private_key: "-----BEGIN RSA PRIVATE KEY-----",
        privateKey: "pk-123",
      }) as any;
      expect(result.credential).toBe("[REDACTED]");
      expect(result.private_key).toBe("[REDACTED]");
      expect(result.privateKey).toBe("[REDACTED]");
    });

    it("handles nested objects", () => {
      const result = redactDeliveryLog({
        config: { password: "secret", host: "example.com" },
        name: "test",
      }) as any;
      expect(result.config.password).toBe("[REDACTED]");
      expect(result.config.host).toBe("example.com");
      expect(result.name).toBe("test");
    });

    it("handles arrays", () => {
      const result = redactDeliveryLog([
        { password: "sec1", user: "a" },
        { password: "sec2", user: "b" },
      ]) as any[];
      expect(result[0].password).toBe("[REDACTED]");
      expect(result[0].user).toBe("a");
      expect(result[1].password).toBe("[REDACTED]");
    });

    it("redacts Bearer tokens in strings", () => {
      const result = redactDeliveryLog("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc") as string;
      expect(result).toContain("Bearer [REDACTED]");
      expect(result).not.toContain("eyJhbGci");
    });

    it("redacts SecureNexus API keys in strings", () => {
      const result = redactDeliveryLog("key=snx_" + "a".repeat(64) + " is active") as string;
      expect(result).toContain("snx_[REDACTED]");
      expect(result).not.toContain("snx_" + "a".repeat(64));
    });

    it("redacts GitHub PATs in strings", () => {
      const result = redactDeliveryLog("token=ghp_" + "A".repeat(36) + " done") as string;
      expect(result).toContain("ghp_[REDACTED]");
    });

    it("redacts AWS access key IDs in strings", () => {
      const result = redactDeliveryLog("aws_key=AKIAIOSFODNN7EXAMPLE done") as string;
      expect(result).toContain("AKIA[REDACTED]");
      expect(result).not.toContain("AKIAIOSFODNN7EXAMPLE");
    });

    it("handles null and undefined", () => {
      expect(redactDeliveryLog(null)).toBeNull();
      expect(redactDeliveryLog(undefined)).toBeUndefined();
    });

    it("handles primitive types", () => {
      expect(redactDeliveryLog(42)).toBe(42);
      expect(redactDeliveryLog(true)).toBe(true);
    });
  });

  describe("getOutboundSecurityStats", () => {
    it("returns stats with open circuits", () => {
      for (let i = 0; i < 5; i++) {
        recordDeliveryFailure("stats-webhook");
      }

      const stats = getOutboundSecurityStats();
      expect(stats.activeCircuitBreakers).toBeGreaterThanOrEqual(1);
      expect(stats.openCircuits).toContain("stats-webhook");

      resetCircuitBreaker("stats-webhook");
    });

    it("returns zero open circuits when all healthy", () => {
      const stats = getOutboundSecurityStats();
      expect(stats.openCircuits.length).toBe(0);
    });
  });
});
