# ATS Sensor Agent

Cross-platform desktop security monitoring agent for SecureNexus.

## What it does

- **Process Monitoring** — Tracks new/suspicious processes, process trees, command-line args
- **Network Connections** — Monitors active connections, suspicious ports, traffic patterns
- **File System Changes** — Watches sensitive files (passwd, shadow, hosts, SSH config, etc.)
- **Authentication Events** — Tracks logins, failures, privilege escalation (sudo, UAC)
- **USB Device Monitoring** — Detects USB connections and removals
- **DNS Query Monitoring** — Watches for suspicious domain lookups (DGA, tunneling, C2)
- **System Logs** — Collects kernel warnings, firewall events, service errors

## Quick Start

1. In SecureNexus, go to **Settings > Native Sensors** and create a new sensor
2. Copy the **Sensor ID** and **API Key**
3. Download and install ATS Sensor for your platform
4. Enter your server URL, Sensor ID, and API Key in the setup wizard
5. Click **Start Monitoring**

## Building from Source

```bash
cd agent/
npm install
npm run build
npm run package        # Build for current platform
npm run package:all    # Build for Windows, macOS, Linux
```

## Platform Installers

| Platform | Format             | Architecture           |
| -------- | ------------------ | ---------------------- |
| Windows  | MSI, NSIS          | x64, arm64             |
| macOS    | DMG, PKG           | x64, arm64 (Universal) |
| Linux    | DEB, RPM, AppImage | x64, arm64             |

## Code Signing

Set these environment variables before building:

### Windows (EV Code Signing)

```
CSC_LINK=path/to/certificate.pfx
CSC_KEY_PASSWORD=your-password
```

### macOS (Apple Developer)

```
CSC_LINK=path/to/certificate.p12
CSC_KEY_PASSWORD=your-password
APPLE_ID=developer@example.com
APPLE_APP_SPECIFIC_PASSWORD=xxxx-xxxx-xxxx-xxxx
APPLE_TEAM_ID=XXXXXXXXXX
```

## Architecture

```
agent/
├── src/
│   ├── main/           # Electron main process
│   │   ├── index.ts        # App lifecycle, tray, IPC
│   │   ├── config.ts       # Persistent config (JSON on disk)
│   │   ├── api-client.ts   # SecureNexus API communication
│   │   ├── auto-start.ts   # OS boot registration
│   │   ├── logger.ts       # File + console logging
│   │   └── collectors/     # System event collectors
│   │       ├── index.ts            # Collector manager
│   │       ├── process-collector.ts
│   │       ├── network-collector.ts
│   │       ├── file-collector.ts
│   │       ├── auth-collector.ts
│   │       ├── usb-collector.ts
│   │       ├── dns-collector.ts
│   │       └── syslog-collector.ts
│   ├── preload/        # Context bridge (IPC)
│   │   └── index.ts
│   └── renderer/       # Setup wizard UI
│       └── index.html
├── build/              # Build resources
│   └── entitlements.mac.plist
├── electron-vite.config.ts
├── package.json
├── tsconfig.json
└── sign.js             # Code signing hook
```

## Security

- Config files are stored with restricted permissions (600/700)
- API key is never logged or displayed after setup
- Agent runs with minimal required privileges
- All API communication uses HTTPS
- Events are batched and flushed every 10 seconds
