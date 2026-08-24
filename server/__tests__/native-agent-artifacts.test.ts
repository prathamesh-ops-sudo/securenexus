import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { getDeploymentScript } from "../native-collectors-engine";

process.env.APP_URL = "http://127.0.0.1:5513";

describe("native agent artifacts", () => {
  it("ships real Linux sensor observations through the agent surface", () => {
    const installer = readFileSync("server/agent/install.sh", "utf8");

    expect(installer).toContain("/api/agent/v1/sensors/$SENSOR_ID/events");
    expect(installer).toContain("ps ");
    expect(installer).toContain("/var/log/auth.log");
    expect(installer).toContain("ss ");
    expect(installer).toContain("sha256sum");
    expect(installer).toContain("apt-get install -y -qq jq");
    expect(installer).toContain("AUTH_STATE_DIR");
    expect(installer).toContain('authResult:"failure"');
    expect(installer).toContain("(Failed\\ password|Invalid\\ user).*from");
    expect(installer).toContain('dd if="$auth_log"');
    expect(installer).not.toContain("tail -n 20");
    expect(installer).not.toContain("cpuUsage:0");
    expect(installer).not.toContain('agent:"ats-sensor"');
  });

  it("ships real Linux collector observations through a persistent worker", () => {
    const script = getDeploymentScript("endpoint-agent-linux", "collector-id", "enrollment-token");

    expect(script).toContain("/api/agent/v1/collectors/events");
    expect(script).toContain("ps ");
    expect(script).toContain("ss ");
    expect(script).toContain("/var/log/auth.log");
    expect(script).toContain("systemd");
    expect(script).toContain("sha256sum");
    expect(script).toContain("cpuCount");
    expect(script).toContain("memoryGb");
    expect(script).toContain("apt-get install -y -qq jq");
    expect(script).toContain("AUTH_STATE_DIR");
    expect(script).toContain('authResult:"failure"');
    expect(script).toContain("(Failed password|Invalid user).*from");
    expect(script).toContain('dd if="$auth_log"');
    expect(script).not.toContain("tail -n 20");
    expect(script).not.toContain('ipAddress:"127.0.0.1"');
    expect(script).not.toContain('arch:"unknown"');
    expect(script).not.toContain("memoryGb:0");
  });

  it("ships real Windows collector observations through a persistent worker", () => {
    const script = getDeploymentScript("endpoint-agent-windows", "collector-id", "enrollment-token");

    expect(script).toContain("/api/agent/v1/collectors/events");
    expect(script).toContain("Get-Process");
    expect(script).toContain("Get-NetTCPConnection");
    expect(script).toContain("Get-WinEvent");
    expect(script).toContain("Get-FileHash");
    expect(script).toContain("Register-ScheduledTask");
    expect(script).toContain("NumberOfLogicalProcessors");
    expect(script).toContain("TotalPhysicalMemory");
    expect(script).not.toContain('ipAddress = "127.0.0.1"');
    expect(script).not.toContain("memoryGb = 0");
  });
});
