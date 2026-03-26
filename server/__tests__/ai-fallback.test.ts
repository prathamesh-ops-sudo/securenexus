import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock model-gateway before importing fallback
vi.mock("../ai/model-gateway", () => ({
  getCircuitBreakerStatus: vi.fn(),
}));

// Mock logger
vi.mock("../logger", () => ({
  logger: {
    child: () => ({
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
      debug: vi.fn(),
    }),
  },
}));

import {
  withAiFallback,
  isAiAvailable,
  clearFallbackCache,
  getFallbackCacheSize,
} from "../ai/fallback";
import { getCircuitBreakerStatus } from "../ai/model-gateway";

const mockGetCircuitBreakerStatus = vi.mocked(getCircuitBreakerStatus);

describe("AI Fallback Wrapper", () => {
  beforeEach(() => {
    clearFallbackCache();
    vi.clearAllMocks();
  });

  describe("isAiAvailable", () => {
    it("returns true when no circuit breakers are tracked", () => {
      mockGetCircuitBreakerStatus.mockReturnValue({});
      expect(isAiAvailable()).toBe(true);
    });

    it("returns true when at least one circuit is closed", () => {
      mockGetCircuitBreakerStatus.mockReturnValue({
        "bedrock:model-a": { failures: 5, isOpen: true, resetAt: "2099-01-01T00:00:00Z" },
        "bedrock:model-b": { failures: 0, isOpen: false, resetAt: null },
      });
      expect(isAiAvailable()).toBe(true);
    });

    it("returns false when all model circuits are open", () => {
      mockGetCircuitBreakerStatus.mockReturnValue({
        "bedrock:model-a": { failures: 5, isOpen: true, resetAt: "2099-01-01T00:00:00Z" },
        "bedrock:model-b": { failures: 5, isOpen: true, resetAt: "2099-01-01T00:00:00Z" },
      });
      expect(isAiAvailable()).toBe(false);
    });
  });

  describe("withAiFallback", () => {
    it("returns { data: result, source: 'live' } when AI call succeeds", async () => {
      mockGetCircuitBreakerStatus.mockReturnValue({});
      const fn = vi.fn().mockResolvedValue({ severity: "high", score: 0.9 });

      const result = await withAiFallback("test:1", fn);

      expect(result).toEqual({
        data: { severity: "high", score: 0.9 },
        source: "live",
      });
      expect(fn).toHaveBeenCalledOnce();
    });

    it("caches successful results keyed by cacheKey", async () => {
      mockGetCircuitBreakerStatus.mockReturnValue({});
      const fn = vi.fn().mockResolvedValue({ severity: "high" });

      await withAiFallback("test:cache", fn);
      expect(getFallbackCacheSize()).toBe(1);

      // Different key creates new entry
      await withAiFallback("test:cache2", fn);
      expect(getFallbackCacheSize()).toBe(2);
    });

    it("returns { data: cachedResult, source: 'cached', cachedAt } when circuit is open and cache has entry", async () => {
      // First, populate cache with a successful call
      mockGetCircuitBreakerStatus.mockReturnValue({});
      const fn = vi.fn().mockResolvedValue({ narrative: "attack story" });
      await withAiFallback("narrative:1", fn);

      // Now simulate all circuits open
      mockGetCircuitBreakerStatus.mockReturnValue({
        "bedrock:model-a": { failures: 5, isOpen: true, resetAt: "2099-01-01T00:00:00Z" },
      });

      const result = await withAiFallback("narrative:1", fn);
      expect(result.source).toBe("cached");
      expect(result.data).toEqual({ narrative: "attack story" });
      expect(result.cachedAt).toBeDefined();
      // fn should NOT have been called again (short-circuits before attempting)
      expect(fn).toHaveBeenCalledTimes(1);
    });

    it("returns { data: null, source: 'unavailable' } when circuit is open and no cache entry", async () => {
      mockGetCircuitBreakerStatus.mockReturnValue({
        "bedrock:model-a": { failures: 5, isOpen: true, resetAt: "2099-01-01T00:00:00Z" },
      });
      const fn = vi.fn().mockResolvedValue({ data: "should not be called" });

      const result = await withAiFallback("no-cache-key", fn);
      expect(result).toEqual({ data: null, source: "unavailable" });
      expect(fn).not.toHaveBeenCalled();
    });

    it("returns cached result when AI call throws (even if circuit not explicitly open)", async () => {
      // Populate cache
      mockGetCircuitBreakerStatus.mockReturnValue({});
      const fn = vi.fn().mockResolvedValueOnce({ triage: "result" });
      await withAiFallback("triage:err", fn);

      // Second call throws but circuit is not open
      fn.mockRejectedValueOnce(new Error("Bedrock timeout"));
      const result = await withAiFallback("triage:err", fn);

      expect(result.source).toBe("cached");
      expect(result.data).toEqual({ triage: "result" });
      expect(result.cachedAt).toBeDefined();
    });

    it("returns unavailable when AI call throws and no cache exists", async () => {
      mockGetCircuitBreakerStatus.mockReturnValue({});
      const fn = vi.fn().mockRejectedValue(new Error("Bedrock down"));

      const result = await withAiFallback("no-cache", fn);
      expect(result).toEqual({ data: null, source: "unavailable" });
    });
  });
});
