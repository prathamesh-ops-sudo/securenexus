/**
 * Preload script — exposes safe IPC bridge to renderer
 */

import { contextBridge, ipcRenderer } from "electron";
import * as os from "os";

const currentHostname = os.hostname();

contextBridge.exposeInMainWorld("atsAgent", {
  // Configuration
  getConfig: () => ipcRenderer.invoke("get-config"),
  saveConfig: (config: Record<string, unknown>) => ipcRenderer.invoke("save-config", config),
  registerSensor: (data: { serverUrl: string; hostname: string; platform: string; enrollmentToken: string }) =>
    ipcRenderer.invoke("register-sensor", data),

  // Agent control
  getStatus: () => ipcRenderer.invoke("get-status"),
  startAgent: () => ipcRenderer.invoke("start-agent"),

  // Auto-start
  setAutoStart: (enabled: boolean) => ipcRenderer.invoke("set-auto-start", enabled),
  getAutoStart: () => ipcRenderer.invoke("get-auto-start"),

  // Permissions
  requestPermissions: () => ipcRenderer.invoke("request-permissions"),

  // Utilities
  openExternal: (url: string) => ipcRenderer.invoke("open-external", url),

  // Platform info
  platform: process.platform,
  arch: process.arch,
  hostname: currentHostname,
});
