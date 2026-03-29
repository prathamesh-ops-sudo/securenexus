/**
 * Auto-Start — register app to start on OS boot
 */

import { app } from "electron";
import * as fs from "fs";
import * as path from "path";
import { execSync } from "child_process";
import { AgentLogger } from "./logger";

const log = new AgentLogger("auto-start");

export class AutoStart {
  static async enable(): Promise<void> {
    const platform = process.platform;
    const appPath = app.getPath("exe");

    try {
      if (platform === "win32") {
        // Windows: add to registry Run key
        execSync(
          `reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v "ATSSensor" /t REG_SZ /d "${appPath}" /f`,
        );
        log.info("Auto-start enabled (Windows Registry)");
      } else if (platform === "darwin") {
        // macOS: create LaunchAgent plist
        const plistDir = path.join(process.env.HOME || "/tmp", "Library", "LaunchAgents");
        const plistPath = path.join(plistDir, "com.aricatech.ats-sensor.plist");

        if (!fs.existsSync(plistDir)) {
          fs.mkdirSync(plistDir, { recursive: true });
        }

        const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.aricatech.ats-sensor</string>
  <key>ProgramArguments</key>
  <array>
    <string>${appPath}</string>
    <string>--hidden</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/var/log/ats-sensor/stdout.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/ats-sensor/stderr.log</string>
</dict>
</plist>`;
        fs.writeFileSync(plistPath, plist);
        execSync(`launchctl load -w "${plistPath}" 2>/dev/null || true`);
        log.info("Auto-start enabled (macOS LaunchAgent)");
      } else {
        // Linux: create systemd user service
        const serviceDir = path.join(process.env.HOME || "/tmp", ".config", "systemd", "user");
        const servicePath = path.join(serviceDir, "ats-sensor.service");

        if (!fs.existsSync(serviceDir)) {
          fs.mkdirSync(serviceDir, { recursive: true });
        }

        const service = `[Unit]
Description=ATS Sensor Agent — SecureNexus Security Monitor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${appPath} --hidden
Restart=always
RestartSec=10
Environment=DISPLAY=:0
Environment=XAUTHORITY=${process.env.HOME}/.Xauthority

[Install]
WantedBy=default.target
`;
        fs.writeFileSync(servicePath, service);
        execSync("systemctl --user daemon-reload 2>/dev/null || true");
        execSync("systemctl --user enable ats-sensor.service 2>/dev/null || true");
        log.info("Auto-start enabled (systemd user service)");
      }
    } catch (err) {
      log.error(`Failed to enable auto-start: ${err}`);
      throw err;
    }
  }

  static async disable(): Promise<void> {
    const platform = process.platform;

    try {
      if (platform === "win32") {
        execSync(
          'reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v "ATSSensor" /f 2>nul || exit 0',
        );
      } else if (platform === "darwin") {
        const plistPath = path.join(
          process.env.HOME || "/tmp",
          "Library",
          "LaunchAgents",
          "com.aricatech.ats-sensor.plist",
        );
        execSync(`launchctl unload -w "${plistPath}" 2>/dev/null || true`);
        if (fs.existsSync(plistPath)) {
          fs.unlinkSync(plistPath);
        }
      } else {
        execSync("systemctl --user disable ats-sensor.service 2>/dev/null || true");
        const servicePath = path.join(process.env.HOME || "/tmp", ".config", "systemd", "user", "ats-sensor.service");
        if (fs.existsSync(servicePath)) {
          fs.unlinkSync(servicePath);
        }
      }
      log.info("Auto-start disabled");
    } catch (err) {
      log.error(`Failed to disable auto-start: ${err}`);
    }
  }

  static isEnabled(): boolean {
    const platform = process.platform;
    try {
      if (platform === "win32") {
        execSync('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v "ATSSensor" 2>nul');
        return true;
      } else if (platform === "darwin") {
        const plistPath = path.join(
          process.env.HOME || "/tmp",
          "Library",
          "LaunchAgents",
          "com.aricatech.ats-sensor.plist",
        );
        return fs.existsSync(plistPath);
      } else {
        const servicePath = path.join(process.env.HOME || "/tmp", ".config", "systemd", "user", "ats-sensor.service");
        return fs.existsSync(servicePath);
      }
    } catch {
      return false;
    }
  }
}
