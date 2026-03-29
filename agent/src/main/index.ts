/**
 * ATS Sensor Agent — Main Process
 * Electron desktop application for system security monitoring
 *
 * Collects: process events, network connections, file changes,
 * auth events, USB devices, DNS queries, system logs
 *
 * Sends telemetry to SecureNexus platform via native sensor API
 */

import { app, BrowserWindow, Tray, Menu, nativeImage, ipcMain, dialog, shell } from "electron";
import * as path from "path";
import { AgentConfig, loadConfig, saveConfig, isConfigured } from "./config";
import { CollectorManager } from "./collectors";
import { ApiClient } from "./api-client";
import { AutoStart } from "./auto-start";
import { AgentLogger } from "./logger";

const log = new AgentLogger("main");

let mainWindow: BrowserWindow | null = null;
let tray: Tray | null = null;
let collectorManager: CollectorManager | null = null;
let apiClient: ApiClient | null = null;
let isQuitting = false;

// Prevent multiple instances
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
}

app.on("second-instance", () => {
  if (mainWindow) {
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.focus();
  }
});

// ── Window Management ──────────────────────────────────────────────────────

function createMainWindow(): void {
  mainWindow = new BrowserWindow({
    width: 720,
    height: 600,
    minWidth: 600,
    minHeight: 500,
    resizable: true,
    maximizable: false,
    title: "ATS Sensor — Setup",
    icon: getIconPath(),
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, "../preload/index.js"),
    },
    show: false,
    autoHideMenuBar: true,
  });

  mainWindow.once("ready-to-show", () => {
    mainWindow?.show();
  });

  // Load the renderer
  if (process.env.ELECTRON_RENDERER_URL) {
    mainWindow.loadURL(process.env.ELECTRON_RENDERER_URL);
  } else {
    mainWindow.loadFile(path.join(__dirname, "../renderer/index.html"));
  }

  mainWindow.on("close", (e) => {
    // Minimize to tray instead of quitting (unless app is shutting down)
    if (!isQuitting && isConfigured()) {
      e.preventDefault();
      mainWindow?.hide();
    }
  });

  mainWindow.on("closed", () => {
    mainWindow = null;
  });
}

function getIconPath(): string {
  const iconName = process.platform === "win32" ? "icon.ico" : process.platform === "darwin" ? "icon.icns" : "icon.png";
  return path.join(__dirname, "../../src/assets", iconName);
}

// ── System Tray ────────────────────────────────────────────────────────────

function createTray(): void {
  const iconPath = path.join(__dirname, "../../src/assets/tray-icon.png");
  let trayIcon: Electron.NativeImage;
  try {
    trayIcon = nativeImage.createFromPath(iconPath).resize({ width: 16, height: 16 });
  } catch {
    // Fallback: create a simple colored icon
    trayIcon = nativeImage.createEmpty();
  }

  tray = new Tray(trayIcon);
  tray.setToolTip("ATS Sensor — Monitoring");
  updateTrayMenu("connecting");

  tray.on("click", () => {
    if (mainWindow) {
      if (mainWindow.isVisible()) {
        mainWindow.hide();
      } else {
        mainWindow.show();
      }
    } else {
      createMainWindow();
    }
  });
}

function updateTrayMenu(status: "online" | "offline" | "error" | "connecting"): void {
  if (!tray) return;

  const statusLabels: Record<string, string> = {
    online: "Connected — Monitoring Active",
    offline: "Disconnected",
    error: "Error — Check Logs",
    connecting: "Connecting...",
  };

  const contextMenu = Menu.buildFromTemplate([
    { label: `ATS Sensor v${app.getVersion()}`, enabled: false },
    { type: "separator" },
    { label: statusLabels[status] || "Unknown", enabled: false },
    { type: "separator" },
    {
      label: "Open Dashboard",
      click: () => {
        const config = loadConfig();
        if (config.serverUrl) {
          shell.openExternal(config.serverUrl);
        }
      },
    },
    {
      label: "View Logs",
      click: () => {
        shell.openPath(AgentLogger.getLogDir());
      },
    },
    { type: "separator" },
    {
      label: "Settings",
      click: () => {
        if (mainWindow) {
          mainWindow.show();
        } else {
          createMainWindow();
        }
      },
    },
    { type: "separator" },
    {
      label: "Quit ATS Sensor",
      click: () => {
        app.quit();
      },
    },
  ]);

  tray.setContextMenu(contextMenu);
  tray.setToolTip(`ATS Sensor — ${statusLabels[status]}`);
}

// ── Agent Lifecycle ────────────────────────────────────────────────────────

async function startAgent(): Promise<void> {
  const config = loadConfig();
  if (!config.serverUrl || !config.sensorId || !config.apiKey) {
    log.warn("Agent not configured — showing setup wizard");
    createMainWindow();
    return;
  }

  log.info("Starting ATS Sensor agent...");
  log.info(`Server: ${config.serverUrl}`);
  log.info(`Sensor ID: ${config.sensorId}`);

  // Stop any existing agent before re-initializing
  await stopAgent();

  // Initialize API client
  apiClient = new ApiClient(config);

  // Test connection
  const connected = await apiClient.testConnection();
  if (!connected) {
    log.error("Failed to connect to server — showing setup wizard");
    updateTrayMenu("error");
    createMainWindow();
    return;
  }

  updateTrayMenu("online");

  // Start collectors
  collectorManager = new CollectorManager(apiClient, config);
  await collectorManager.start();

  // Start heartbeat
  apiClient.startHeartbeat();

  log.info("Agent started successfully — monitoring active");
}

async function stopAgent(): Promise<void> {
  log.info("Stopping ATS Sensor agent...");
  await collectorManager?.stop();
  apiClient?.stopHeartbeat();
  log.info("Agent stopped");
}

// ── IPC Handlers ───────────────────────────────────────────────────────────

function registerIpcHandlers(): void {
  // Setup wizard: save configuration
  ipcMain.handle("save-config", async (_event, config: Partial<AgentConfig>) => {
    try {
      saveConfig(config);
      log.info("Configuration saved");
      return { success: true };
    } catch (err) {
      log.error(`Failed to save config: ${err}`);
      return { success: false, error: String(err) };
    }
  });

  // Setup wizard: test connection to server
  ipcMain.handle("test-connection", async (_event, config: { serverUrl: string; sensorId: string; apiKey: string }) => {
    try {
      const client = new ApiClient(config as AgentConfig);
      const connected = await client.testConnection();
      return { success: connected };
    } catch (err) {
      return { success: false, error: String(err) };
    }
  });

  // Setup wizard: register sensor with server
  ipcMain.handle(
    "register-sensor",
    async (_event, data: { serverUrl: string; hostname: string; platform: string; orgToken: string }) => {
      try {
        const response = await fetch(`${data.serverUrl}/api/native-sensors/register`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${data.orgToken}`,
          },
          body: JSON.stringify({
            hostname: data.hostname,
            platform: data.platform,
            osVersion: `${process.platform} ${process.arch}`,
          }),
          signal: AbortSignal.timeout(15000),
        });

        if (!response.ok) {
          const errBody = await response.text();
          return { success: false, error: `Server returned ${response.status}: ${errBody}` };
        }

        const result = await response.json();
        return {
          success: true,
          sensorId: result.sensor?.id,
          apiKey: result.apiKey,
        };
      } catch (err) {
        return { success: false, error: String(err) };
      }
    },
  );

  // Get current config
  ipcMain.handle("get-config", async () => {
    return loadConfig();
  });

  // Get agent status
  ipcMain.handle("get-status", async () => {
    return {
      configured: isConfigured(),
      collecting: collectorManager?.isRunning() ?? false,
      connected: apiClient?.isConnected() ?? false,
      eventsCollected: collectorManager?.getStats().totalEvents ?? 0,
      eventsSent: apiClient?.getStats().eventsSent ?? 0,
      lastHeartbeat: apiClient?.getStats().lastHeartbeat ?? null,
      version: app.getVersion(),
    };
  });

  // Start agent after setup
  ipcMain.handle("start-agent", async () => {
    try {
      await startAgent();
      return { success: true };
    } catch (err) {
      return { success: false, error: String(err) };
    }
  });

  // Enable/disable auto-start
  ipcMain.handle("set-auto-start", async (_event, enabled: boolean) => {
    try {
      if (enabled) {
        await AutoStart.enable();
      } else {
        await AutoStart.disable();
      }
      return { success: true };
    } catch (err) {
      return { success: false, error: String(err) };
    }
  });

  // Get auto-start status
  ipcMain.handle("get-auto-start", async () => {
    return AutoStart.isEnabled();
  });

  // Request elevated permissions
  ipcMain.handle("request-permissions", async () => {
    const perms = await checkPermissions();
    return perms;
  });

  // Open external URL
  ipcMain.handle("open-external", async (_event, url: string) => {
    shell.openExternal(url);
  });
}

async function checkPermissions(): Promise<{ admin: boolean; fullDisk: boolean; network: boolean }> {
  const isAdmin = process.platform === "win32" ? process.env.ELEVATED === "true" : process.getuid?.() === 0;

  return {
    admin: !!isAdmin,
    fullDisk: true, // Would need macOS TCC check
    network: true,
  };
}

// ── App Lifecycle ──────────────────────────────────────────────────────────

app.whenReady().then(async () => {
  log.info("ATS Sensor starting...");
  log.info(`Platform: ${process.platform} ${process.arch}`);
  log.info(`Electron: ${process.versions.electron}`);

  registerIpcHandlers();
  createTray();

  if (isConfigured()) {
    // Already configured — start monitoring in background
    await startAgent();
  } else {
    // First run — show setup wizard
    createMainWindow();
  }
});

app.on("window-all-closed", () => {
  // Don't quit on macOS / when configured (runs in tray)
  if (!isConfigured()) {
    app.quit();
  }
});

app.on("activate", () => {
  if (!mainWindow) {
    createMainWindow();
  }
});

app.on("before-quit", (event) => {
  if (isQuitting) return;
  event.preventDefault();
  isQuitting = true;
  stopAgent().finally(() => app.quit());
});

// Handle uncaught errors
process.on("uncaughtException", (err) => {
  log.error(`Uncaught exception: ${err.message}\n${err.stack}`);
});

process.on("unhandledRejection", (reason) => {
  log.error(`Unhandled rejection: ${reason}`);
});
