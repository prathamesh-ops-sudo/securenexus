/**
 * USB Collector — monitors USB device connections and removals
 */

import { execSync } from "child_process";
import { AgentLogger } from "../logger";
import type { Collector, SensorEvent } from "./index";

const log = new AgentLogger("usb-collector");

interface UsbDevice {
  id: string;
  vendor: string;
  product: string;
  serial: string;
}

export class UsbCollector implements Collector {
  name = "usb";
  private knownDevices = new Map<string, UsbDevice>();
  private initialized = false;

  async collect(): Promise<SensorEvent[]> {
    const events: SensorEvent[] = [];
    const now = new Date().toISOString();

    try {
      const currentDevices = this.getUsbDevices();
      const currentIds = new Set<string>();

      for (const device of currentDevices) {
        currentIds.add(device.id);

        if (!this.knownDevices.has(device.id) && this.initialized) {
          events.push({
            eventType: "usb_connect",
            timestamp: now,
            logMessage: `USB device connected: ${device.vendor} ${device.product}`,
            logSource: "usb_monitor",
            rawData: JSON.stringify(device),
          });
          log.info(`USB connected: ${device.vendor} ${device.product}`);
        }
        this.knownDevices.set(device.id, device);
      }

      // Detect removals
      if (this.initialized) {
        for (const [id, device] of this.knownDevices) {
          if (!currentIds.has(id)) {
            events.push({
              eventType: "usb_disconnect",
              timestamp: now,
              logMessage: `USB device removed: ${device.vendor} ${device.product}`,
              logSource: "usb_monitor",
              rawData: JSON.stringify(device),
            });
            this.knownDevices.delete(id);
          }
        }
      }

      if (!this.initialized) {
        this.initialized = true;
        log.info(`Baseline: ${this.knownDevices.size} USB devices`);
      }
    } catch (err) {
      log.warn(`USB collection error: ${err}`);
    }

    return events;
  }

  private getUsbDevices(): UsbDevice[] {
    try {
      if (process.platform === "linux") {
        return this.getLinuxUsb();
      } else if (process.platform === "darwin") {
        return this.getMacUsb();
      } else if (process.platform === "win32") {
        return this.getWindowsUsb();
      }
    } catch {
      // Ignore
    }
    return [];
  }

  private getLinuxUsb(): UsbDevice[] {
    const devices: UsbDevice[] = [];
    try {
      const output = execSync("lsusb 2>/dev/null || cat /sys/bus/usb/devices/*/product 2>/dev/null", {
        timeout: 5000,
        encoding: "utf-8",
      });
      for (const line of output.trim().split("\n")) {
        if (!line.trim()) continue;
        // lsusb format: Bus 001 Device 002: ID 1234:5678 Vendor Product
        const match = line.match(/ID\s+([0-9a-f]+):([0-9a-f]+)\s+(.*)/i);
        if (match) {
          devices.push({
            id: `${match[1]}:${match[2]}`,
            vendor: match[1],
            product: match[3] || match[2],
            serial: "",
          });
        }
      }
    } catch {
      // Ignore
    }
    return devices;
  }

  private getMacUsb(): UsbDevice[] {
    const devices: UsbDevice[] = [];
    try {
      const output = execSync("system_profiler SPUSBDataType -detailLevel mini 2>/dev/null | head -100", {
        timeout: 10000,
        encoding: "utf-8",
      });
      // Simple parsing — look for product names
      const lines = output.split("\n");
      let currentDevice: Partial<UsbDevice> = {};
      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed.endsWith(":") && !trimmed.startsWith("USB") && !trimmed.startsWith("Host")) {
          if (currentDevice.id) {
            devices.push(currentDevice as UsbDevice);
          }
          currentDevice = { id: trimmed.replace(":", ""), vendor: "", product: trimmed.replace(":", ""), serial: "" };
        }
        if (trimmed.startsWith("Vendor ID:")) {
          currentDevice.vendor = trimmed.split(":")[1]?.trim() || "";
          currentDevice.id = `${currentDevice.vendor}:${currentDevice.product}`;
        }
        if (trimmed.startsWith("Serial Number:")) {
          currentDevice.serial = trimmed.split(":")[1]?.trim() || "";
        }
      }
      if (currentDevice.id) {
        devices.push(currentDevice as UsbDevice);
      }
    } catch {
      // Ignore
    }
    return devices;
  }

  private getWindowsUsb(): UsbDevice[] {
    const devices: UsbDevice[] = [];
    try {
      const output = execSync("wmic path Win32_USBHub get DeviceID,Name,Status /format:csv 2>nul", {
        timeout: 5000,
        encoding: "utf-8",
      });
      for (const line of output.trim().split("\n")) {
        if (!line.trim() || line.includes("Node,")) continue;
        const parts = line.split(",");
        if (parts.length < 3) continue;
        devices.push({
          id: parts[1] || "",
          vendor: "",
          product: parts[2] || "",
          serial: "",
        });
      }
    } catch {
      // Ignore
    }
    return devices;
  }
}
