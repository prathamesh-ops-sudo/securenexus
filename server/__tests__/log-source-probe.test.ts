import { describe, expect, it } from "vitest";
import { buildHttpPushProbeResult, mapCloudWatchProbeError } from "../log-source-probe";

describe("log source probe result mapping", () => {
  it("preserves CloudWatch permission failures", () => {
    expect(
      mapCloudWatchProbeError({
        name: "AccessDeniedException",
        message: "User is not authorized to perform: logs:DescribeLogGroups",
      }),
    ).toEqual({
      reasonCode: "permission",
      message: "CloudWatch permission denied: User is not authorized to perform: logs:DescribeLogGroups",
    });
  });

  it("maps missing CloudWatch credentials to authentication", () => {
    expect(
      mapCloudWatchProbeError({ name: "CredentialsProviderError", message: "Unable to load credentials" }),
    ).toEqual({
      reasonCode: "authentication",
      message: "CloudWatch authentication failed: Unable to load credentials",
    });
  });

  it("preserves CloudWatch network failures", () => {
    expect(mapCloudWatchProbeError({ code: "ETIMEDOUT", message: "socket timed out" })).toEqual({
      reasonCode: "network",
      message: "CloudWatch network request failed: socket timed out",
    });
    expect(mapCloudWatchProbeError({ name: "TimeoutError", message: "request timed out" })).toEqual({
      reasonCode: "network",
      message: "CloudWatch network request failed: request timed out",
    });
  });

  it("reports HTTP push as receiver-side unverifiable and includes receipt evidence", () => {
    const result = buildHttpPushProbeResult({
      sourceType: "http_push",
      httpEndpoint: "/api/native/log-sources/ingest/token",
      eventsReceived: 2,
      lastEventAt: "2026-04-01T00:00:00.000Z",
    });
    expect(result.status).toBe("unavailable");
    expect(result.tested).toBe(false);
    expect(result.eventReceipt).toEqual({
      eventsReceived: 2,
      lastEventAt: "2026-04-01T00:00:00.000Z",
      everReceived: true,
    });
    expect(result.message).toContain("Cannot verify an HTTP push source from this side");
    expect(result.message).toContain("2 event(s) have arrived");
  });
});
