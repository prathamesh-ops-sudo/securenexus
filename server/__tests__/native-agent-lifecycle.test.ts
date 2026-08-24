import { describe, expect, it } from "vitest";
import { createSensorAgentKey } from "../agent-auth";
import { getSensorLifecycleState } from "../native-sensor-lifecycle";

describe("native sensor agent lifecycle", () => {
  it("derives evidence-based enrollment and telemetry states", () => {
    const createdAt = new Date();
    expect(getSensorLifecycleState({ createdAt, revokedAt: null, lastHeartbeat: null, lastTelemetryAt: null })).toBe(
      "enrolled-but-never-heartbeated",
    );

    const heartbeat = new Date();
    expect(
      getSensorLifecycleState({ createdAt, revokedAt: null, lastHeartbeat: heartbeat, lastTelemetryAt: null }),
    ).toBe("online-but-zero-telemetry");
    expect(
      getSensorLifecycleState({ createdAt, revokedAt: null, lastHeartbeat: heartbeat, lastTelemetryAt: heartbeat }),
    ).toBe("receiving-telemetry");
    expect(
      getSensorLifecycleState({
        createdAt,
        revokedAt: null,
        lastHeartbeat: new Date(Date.now() - 120_000),
        lastTelemetryAt: heartbeat,
      }),
    ).toBe("degraded");
    expect(
      getSensorLifecycleState({
        createdAt,
        revokedAt: null,
        lastHeartbeat: new Date(Date.now() - 360_000),
        lastTelemetryAt: heartbeat,
      }),
    ).toBe("offline");
    expect(
      getSensorLifecycleState({
        createdAt,
        revokedAt: new Date(),
        lastHeartbeat: heartbeat,
        lastTelemetryAt: heartbeat,
      }),
    ).toBe("revoked");
    expect(
      getSensorLifecycleState({
        createdAt,
        status: "superseded",
        revokedAt: null,
        lastHeartbeat: heartbeat,
        lastTelemetryAt: heartbeat,
      }),
    ).toBe("superseded");
  });

  it("creates a credential bound to the sensor id without exposing the hash", () => {
    const sensorId = "9f1c2b40-90ae-4abf-a190-6a3e4c849a27";
    const credential = createSensorAgentKey(sensorId);
    expect(credential.key).toMatch(new RegExp(`^snx_agent_${sensorId}_[a-f0-9]{64}$`));
    expect(credential.hash).toHaveLength(64);
    expect(credential.hash).not.toBe(credential.key);
  });
});
