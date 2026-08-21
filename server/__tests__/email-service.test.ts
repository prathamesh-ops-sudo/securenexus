import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  send: vi.fn(),
  clientConfig: undefined as Record<string, unknown> | undefined,
  info: vi.fn(),
  error: vi.fn(),
}));

vi.mock("@aws-sdk/client-sesv2", () => ({
  SESv2Client: class {
    constructor(config: Record<string, unknown>) {
      mocks.clientConfig = config;
    }

    send(...args: unknown[]) {
      return mocks.send(...args);
    }
  },
  SendEmailCommand: class {
    constructor(input: Record<string, unknown>) {
      Object.assign(this, input);
    }
  },
}));
vi.mock("../config", () => ({
  config: { nodeEnv: "production", aws: { region: "us-east-1" } },
}));
vi.mock("../logger", () => ({
  logger: { child: () => ({ info: mocks.info, error: mocks.error }) },
}));

import {
  EMAIL_CONNECTION_TIMEOUT_MS,
  EMAIL_OVERALL_TIMEOUT_MS,
  EMAIL_REQUEST_TIMEOUT_MS,
  EMAIL_SOCKET_TIMEOUT_MS,
  sendEmailWithStatus,
} from "../email-service";

describe("email provider timeouts", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();
  });

  it("turns a hanging provider call into a failed delivery", async () => {
    mocks.send.mockReturnValue(new Promise(() => {}));

    const resultPromise = sendEmailWithStatus({
      to: "recipient@example.com",
      subject: "Test",
      html: "<p>Test</p>",
    });

    await vi.advanceTimersByTimeAsync(EMAIL_OVERALL_TIMEOUT_MS);

    await expect(resultPromise).resolves.toEqual({ accepted: false, status: "failed" });
    expect(mocks.clientConfig).toEqual(
      expect.objectContaining({
        requestHandler: {
          connectionTimeout: EMAIL_CONNECTION_TIMEOUT_MS,
          socketTimeout: EMAIL_SOCKET_TIMEOUT_MS,
          requestTimeout: EMAIL_REQUEST_TIMEOUT_MS,
          throwOnRequestTimeout: true,
        },
      }),
    );
    expect(mocks.error).toHaveBeenCalledWith(
      "Failed to send email",
      expect.objectContaining({
        error: `Error: Email provider deadline exceeded after ${EMAIL_OVERALL_TIMEOUT_MS}ms`,
      }),
    );
  });

  it("keeps bounded transport timeout settings centralized in the email service", () => {
    expect(EMAIL_CONNECTION_TIMEOUT_MS).toBe(3_000);
    expect(EMAIL_SOCKET_TIMEOUT_MS).toBe(5_000);
    expect(EMAIL_REQUEST_TIMEOUT_MS).toBe(10_000);
    expect(EMAIL_OVERALL_TIMEOUT_MS).toBe(15_000);
  });

  afterEach(() => {
    vi.useRealTimers();
  });
});
