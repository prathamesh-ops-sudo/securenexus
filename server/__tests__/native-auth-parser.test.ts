import { describe, expect, it } from "vitest";
import { parseLinuxAuthLogLine } from "../native-collectors-engine";

describe("parseLinuxAuthLogLine", () => {
  it("classifies failed SSH passwords and extracts the account and source", () => {
    expect(
      parseLinuxAuthLogLine(
        "Mar 24 12:34:56 host sshd[1234]: Failed password for invalid user admin from 203.0.113.7 port 48210 ssh2",
        "/var/log/secure",
      ),
    ).toMatchObject({
      authAction: "login",
      authResult: "failure",
      authMethod: "ssh",
      userName: "admin",
      srcIp: "203.0.113.7",
      logSource: "/var/log/secure",
    });
  });

  it("classifies successful public-key authentication", () => {
    expect(
      parseLinuxAuthLogLine(
        "Mar 24 12:35:01 host sshd[1234]: Accepted publickey for ec2-user from 198.51.100.8 port 48210 ssh2",
        "/var/log/secure",
      ),
    ).toMatchObject({
      authAction: "login",
      authResult: "success",
      authMethod: "publickey",
      userName: "ec2-user",
      srcIp: "198.51.100.8",
    });
  });

  it("does not turn unrelated authentication log lines into verdicts", () => {
    expect(
      parseLinuxAuthLogLine(
        "Mar 24 12:35:01 host sshd[1234]: Server listening on 0.0.0.0 port 22.",
        "/var/log/auth.log",
      ),
    ).toBeNull();
    expect(
      parseLinuxAuthLogLine(
        "Mar 24 12:35:01 host sudo: ubuntu : COMMAND=/usr/bin/grep 'Invalid user' /var/log/auth.log",
        "/var/log/auth.log",
      ),
    ).toBeNull();
  });
});
