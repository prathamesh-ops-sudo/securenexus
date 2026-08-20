import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const { bedrockSend } = vi.hoisted(() => ({
  bedrockSend: vi.fn(),
}));

vi.mock("@aws-sdk/client-bedrock-runtime", () => ({
  BedrockRuntimeClient: class {
    send = bedrockSend;
  },
  ConverseCommand: class {
    input: unknown;

    constructor(input: unknown) {
      this.input = input;
    }
  },
  ConverseStreamCommand: class {
    input: unknown;

    constructor(input: unknown) {
      this.input = input;
    }
  },
}));

vi.mock("@aws-sdk/client-sagemaker-runtime", () => ({
  SageMakerRuntimeClient: class {},
  InvokeEndpointCommand: class {},
}));

process.env.DATABASE_URL ||= "postgresql://localhost/securenexus-test";
process.env.SESSION_SECRET ||= "test-session-secret-with-at-least-32-characters";
process.env.S3_BUCKET_NAME ||= "test-bucket";
process.env.AWS_REGION ||= "us-east-1";

describe("Bedrock model gateway", () => {
  let invokeModel: typeof import("../ai/model-gateway").invokeModel;
  let buildCacheKey: typeof import("../ai/model-gateway").buildCacheKey;
  let withAiFallback: typeof import("../ai/fallback").withAiFallback;
  let config: typeof import("../config").config;

  beforeAll(async () => {
    ({ invokeModel, buildCacheKey } = await import("../ai/model-gateway"));
    ({ withAiFallback } = await import("../ai/fallback"));
    ({ config } = await import("../config"));
  });

  beforeEach(() => {
    bedrockSend.mockReset();
  });

  const options = {
    modelId: "amazon.nova-pro-v1:0",
    backend: "bedrock" as const,
    systemPrompt: "You are a security analyst.",
    userMessage: "Summarize the supplied evidence.",
    maxTokens: 100,
    temperature: 0.1,
    topP: 0.9,
    skipCache: true,
  };

  it("uses reachable Nova defaults for each AI tier", () => {
    expect(config.ai.modelId).toBe("us.openai.gpt-5.6-terra");
    expect(config.ai.triage.modelId).toBe("us.amazon.nova-2-lite-v1:0");
    expect(config.ai.investigation.modelId).toBe("us.openai.gpt-5.6-terra");
  });

  it("returns the Nova response and usage metadata on success", async () => {
    bedrockSend.mockResolvedValue({
      output: { message: { content: [{ text: "Evidence-backed response" }] } },
      usage: { inputTokens: 12, outputTokens: 7 },
    });

    const result = await invokeModel(options);

    expect(result.modelId).toBe("amazon.nova-pro-v1:0");
    expect(result.text).toBe("Evidence-backed response");
    expect(result.inputTokensEstimate).toBe(12);
    expect(result.outputTokensEstimate).toBe(7);
    expect(bedrockSend).toHaveBeenCalledOnce();
  });

  it("requires organization scope and isolates cache keys by organization", () => {
    expect(buildCacheKey({ ...options, orgId: undefined })).toBeNull();
    const first = buildCacheKey({ ...options, orgId: "org-a" });
    const second = buildCacheKey({ ...options, orgId: "org-b" });
    expect(first).not.toBe(second);
    expect(first).toMatch(/^mc:[a-f0-9]{64}$/);
  });

  it("returns an explicit unavailable result for Bedrock access denial", async () => {
    bedrockSend.mockRejectedValue(
      Object.assign(new Error("INVALID_PAYMENT_INSTRUMENT"), { name: "AccessDeniedException" }),
    );

    const result = await withAiFallback("test:access-denied", () => invokeModel(options));

    expect(result).toEqual({ data: null, source: "unavailable" });
    expect(bedrockSend).toHaveBeenCalledOnce();
  });

  it("returns an explicit unavailable result after Bedrock throttling retries", async () => {
    bedrockSend.mockRejectedValue(Object.assign(new Error("rate limit"), { name: "ThrottlingException" }));

    const result = await withAiFallback("test:throttled", () => invokeModel(options));

    expect(result).toEqual({ data: null, source: "unavailable" });
    expect(bedrockSend).toHaveBeenCalledTimes(9);
  }, 10_000);
});
