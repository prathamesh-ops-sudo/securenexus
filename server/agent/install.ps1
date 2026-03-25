# =============================================================================
# ATS Sensor Agent — Install Script (Windows)
# Arica Tech Solutions — SecureNexus Platform
#
# Usage:
#   $env:SENSOR_ID='...'; $env:API_KEY='...'; $env:SERVER_URL='...'; .\install.ps1
# =============================================================================

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

# ── Validation ──────────────────────────────────────────────────────────────

if (-not $env:SENSOR_ID -or -not $env:API_KEY -or -not $env:SERVER_URL) {
    Write-Error "SENSOR_ID, API_KEY, and SERVER_URL environment variables are required."
    exit 1
}

$AgentVersion = "1.0.0"
$InstallDir = "C:\Program Files\ATS-Sensor"
$LogDir = "$InstallDir\logs"
$ConfigFile = "$InstallDir\config.env"
$AgentScript = "$InstallDir\ats-agent.ps1"
$ServiceName = "ATSSensor"

Write-Host "============================================"
Write-Host " ATS Sensor Agent Installer v$AgentVersion"
Write-Host " Arica Tech Solutions"
Write-Host "============================================"
Write-Host ""
Write-Host "Server URL:  $env:SERVER_URL"
Write-Host "Sensor ID:   $env:SENSOR_ID"
Write-Host "Install Dir: $InstallDir"
Write-Host ""

# ── Create directories ─────────────────────────────────────────────────────

Write-Host "[1/4] Creating directories..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
New-Item -ItemType Directory -Force -Path "$InstallDir\quarantine" | Out-Null

# ── Write config ────────────────────────────────────────────────────────────

Write-Host "[2/4] Writing configuration..."
@"
SENSOR_ID=$env:SENSOR_ID
API_KEY=$env:API_KEY
SERVER_URL=$env:SERVER_URL
AGENT_VERSION=$AgentVersion
HEARTBEAT_INTERVAL=30
EVENT_BATCH_SIZE=100
EVENT_FLUSH_INTERVAL=10
LOG_FILE=$LogDir\agent.log
PLATFORM=windows
"@ | Out-File -FilePath $ConfigFile -Encoding UTF8

# Restrict config file access
$acl = Get-Acl $ConfigFile
$acl.SetAccessRuleProtection($true, $false)
$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "Allow")
$systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "Allow")
$acl.AddAccessRule($adminRule)
$acl.AddAccessRule($systemRule)
Set-Acl -Path $ConfigFile -AclObject $acl

# ── Write agent script ─────────────────────────────────────────────────────

Write-Host "[3/4] Writing agent daemon..."

$agentCode = @'
# =============================================================================
# ATS Sensor Agent — Windows Daemon
# Collects security events and sends them to the SecureNexus platform
# =============================================================================

$ErrorActionPreference = "SilentlyContinue"

# Load config
$configPath = "C:\Program Files\ATS-Sensor\config.env"
$config = @{}
Get-Content $configPath | ForEach-Object {
    if ($_ -match '^([^=]+)=(.*)$') {
        $config[$Matches[1]] = $Matches[2]
    }
}

$SensorId = $config["SENSOR_ID"]
$ApiKey = $config["API_KEY"]
$ServerUrl = $config["SERVER_URL"]
$AgentVersion = $config["AGENT_VERSION"]
$LogFile = $config["LOG_FILE"]
$HeartbeatInterval = [int]($config["HEARTBEAT_INTERVAL"] ?? "30")
$EventBatchSize = [int]($config["EVENT_BATCH_SIZE"] ?? "100")

# ── Logging ─────────────────────────────────────────────────────────────────

function Write-Log {
    param([string]$Level, [string]$Message)
    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $entry = "$timestamp [$Level] $Message"
    Add-Content -Path $LogFile -Value $entry
}

# ── API Helpers ─────────────────────────────────────────────────────────────

function Invoke-ApiPost {
    param([string]$Path, [object]$Body)
    try {
        $headers = @{
            "Content-Type" = "application/json"
            "Authorization" = "Bearer $ApiKey"
        }
        $json = $Body | ConvertTo-Json -Depth 10 -Compress
        $response = Invoke-RestMethod -Uri "$ServerUrl$Path" -Method POST -Headers $headers -Body $json -TimeoutSec 15
        return $response
    } catch {
        Write-Log "WARN" "API POST $Path failed: $_"
        return $null
    }
}

function Invoke-ApiGet {
    param([string]$Path)
    try {
        $headers = @{ "Authorization" = "Bearer $ApiKey" }
        return Invoke-RestMethod -Uri "$ServerUrl$Path" -Method GET -Headers $headers -TimeoutSec 10
    } catch {
        return $null
    }
}

# ── Event buffer ────────────────────────────────────────────────────────────

$script:EventBuffer = [System.Collections.ArrayList]::new()

function Add-Event {
    param([hashtable]$Event)
    $Event["timestamp"] = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $script:EventBuffer.Add($Event) | Out-Null
}

function Send-Events {
    if ($script:EventBuffer.Count -eq 0) { return }

    $count = $script:EventBuffer.Count
    Write-Log "INFO" "Flushing $count events..."

    $payload = @{ events = $script:EventBuffer.ToArray() }
    $result = Invoke-ApiPost "/api/native-sensors/$SensorId/events" $payload

    if ($result -and $result.accepted) {
        Write-Log "INFO" "Events accepted: $($result.accepted), alerts: $($result.alertsCreated)"
        $script:EventBuffer.Clear()
    } else {
        Write-Log "WARN" "Event flush failed (retaining buffer)"
    }
}

# ── Process monitoring ──────────────────────────────────────────────────────

$script:KnownPids = @{}

function Collect-ProcessEvents {
    $processes = Get-Process -IncludeUserName 2>$null | Select-Object Id, ProcessName, Path, UserName, StartTime

    $suspiciousNames = @("nc", "ncat", "netcat", "nmap", "mimikatz", "psexec",
        "procdump", "rubeus", "sharphound", "bloodhound", "lazagne",
        "powershell_ise", "wscript", "cscript", "mshta", "certutil",
        "bitsadmin", "rundll32")

    foreach ($proc in $processes) {
        if (-not $proc.Id) { continue }
        $isSuspicious = $suspiciousNames -contains $proc.ProcessName.ToLower()
        $isNew = -not $script:KnownPids.ContainsKey($proc.Id)

        if ($isSuspicious -or $isNew) {
            Add-Event @{
                eventType = "process_start"
                processName = $proc.ProcessName
                processPath = ($proc.Path ?? $proc.ProcessName)
                pid = $proc.Id
                userName = ($proc.UserName ?? "SYSTEM")
            }
        }
        $script:KnownPids[$proc.Id] = $true
    }
}

# ── Network monitoring ──────────────────────────────────────────────────────

function Collect-NetworkEvents {
    $connections = Get-NetTCPConnection -State Established 2>$null |
        Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0)' } |
        Select-Object -First 50

    $suspiciousPorts = @(4444, 5555, 6666, 1337, 31337, 8888, 9999)

    foreach ($conn in $connections) {
        $isSuspicious = $suspiciousPorts -contains $conn.RemotePort

        if ($isSuspicious) {
            $proc = Get-Process -Id $conn.OwningProcess 2>$null
            Add-Event @{
                eventType = "network_connection"
                srcIp = $conn.LocalAddress
                srcPort = $conn.LocalPort
                dstIp = $conn.RemoteAddress
                dstPort = $conn.RemotePort
                protocol = "tcp"
                processName = ($proc.ProcessName ?? "unknown")
                pid = $conn.OwningProcess
            }
        }
    }
}

# ── Auth monitoring ─────────────────────────────────────────────────────────

$script:LastAuthCheck = (Get-Date).AddMinutes(-1)

function Collect-AuthEvents {
    $since = $script:LastAuthCheck
    $script:LastAuthCheck = Get-Date

    # Check Security event log for logon events
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id = @(4624, 4625, 4634, 4648, 4672)
        StartTime = $since
    } -MaxEvents 50 2>$null

    foreach ($evt in $events) {
        $authAction = switch ($evt.Id) {
            4624 { "login_success" }
            4625 { "login_failure" }
            4634 { "logoff" }
            4648 { "explicit_credential" }
            4672 { "privilege_escalation" }
            default { "unknown" }
        }

        $authResult = if ($evt.Id -eq 4625) { "failure" } else { "success" }
        $userName = ($evt.Properties[5].Value ?? "unknown")
        $srcIp = ($evt.Properties[18].Value ?? "")

        Add-Event @{
            eventType = "auth_event"
            authAction = $authAction
            authResult = $authResult
            authMethod = "windows_security"
            userName = $userName
            srcIp = $srcIp
            logMessage = $evt.Message.Substring(0, [Math]::Min(500, $evt.Message.Length))
            logSource = "windows_security_log"
        }
    }
}

# ── File monitoring ─────────────────────────────────────────────────────────

$script:FileChecksums = @{}

function Collect-FileEvents {
    $watchPaths = @(
        "C:\Windows\System32\drivers\etc\hosts",
        "C:\Windows\System32\config\SAM",
        "C:\Windows\System32\config\SYSTEM"
    )

    foreach ($fpath in $watchPaths) {
        if (-not (Test-Path $fpath)) { continue }
        $hash = (Get-FileHash $fpath -Algorithm SHA256 2>$null).Hash
        if (-not $hash) { continue }

        $prevHash = $script:FileChecksums[$fpath]
        if ($prevHash -and $hash -ne $prevHash) {
            $fileInfo = Get-Item $fpath
            Add-Event @{
                eventType = "file_modification"
                filePath = $fpath
                fileAction = "modified"
                fileHash = $hash
                fileSize = $fileInfo.Length
            }
            Write-Log "WARN" "Sensitive file modified: $fpath"
        }
        $script:FileChecksums[$fpath] = $hash
    }

    # Check for executables in temp dirs
    $tempDirs = @($env:TEMP, "C:\Windows\Temp", "C:\Users\Public")
    foreach ($dir in $tempDirs) {
        if (-not (Test-Path $dir)) { continue }
        Get-ChildItem -Path $dir -Filter "*.exe" -Recurse -Depth 1 -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-1) } |
            Select-Object -First 10 |
            ForEach-Object {
                Add-Event @{
                    eventType = "file_creation"
                    filePath = $_.FullName
                    fileAction = "created"
                    fileSize = $_.Length
                    logMessage = "New executable in temp directory"
                }
            }
    }
}

# ── Response action executor ────────────────────────────────────────────────

function Execute-PendingActions {
    $result = Invoke-ApiGet "/api/native-sensors/$SensorId/pending-actions"
    if (-not $result -or -not $result.actions -or $result.actions.Count -eq 0) { return }

    Write-Log "INFO" "Found $($result.actions.Count) pending actions"

    foreach ($action in $result.actions) {
        $actionId = $action.id
        $actionType = $action.actionType
        Write-Log "INFO" "Executing: $actionType (ID: $actionId)"

        $success = $false
        $output = ""

        switch ($actionType) {
            "kill_process" {
                $targetPid = $action.targetPid
                $targetName = $action.targetProcessName
                if ($targetPid) {
                    Stop-Process -Id $targetPid -Force 2>$null
                    $output = "Process $targetPid terminated"
                    $success = $true
                } elseif ($targetName) {
                    Stop-Process -Name $targetName -Force 2>$null
                    $output = "Process $targetName terminated"
                    $success = $true
                }
            }
            "block_ip" {
                $targetIp = $action.targetIp
                if ($targetIp) {
                    New-NetFirewallRule -DisplayName "ATS Block $targetIp" -Direction Inbound -RemoteAddress $targetIp -Action Block 2>$null
                    New-NetFirewallRule -DisplayName "ATS Block $targetIp Out" -Direction Outbound -RemoteAddress $targetIp -Action Block 2>$null
                    $output = "IP $targetIp blocked via Windows Firewall"
                    $success = $true
                }
            }
            "quarantine_file" {
                $targetFile = $action.targetFilePath
                if ($targetFile -and (Test-Path $targetFile)) {
                    $quarantinePath = "C:\Program Files\ATS-Sensor\quarantine\$(Split-Path $targetFile -Leaf).$(Get-Date -Format 'yyyyMMddHHmmss')"
                    Move-Item $targetFile $quarantinePath -Force
                    $output = "File quarantined to $quarantinePath"
                    $success = $true
                }
            }
            "disable_user" {
                $targetUser = $action.targetUserName
                if ($targetUser) {
                    net user $targetUser /active:no 2>$null
                    $output = "User $targetUser disabled"
                    $success = $true
                }
            }
            "block_domain" {
                $targetDomain = $action.targetDomain
                if ($targetDomain) {
                    Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "`n127.0.0.1 $targetDomain"
                    ipconfig /flushdns | Out-Null
                    $output = "Domain $targetDomain sinkholed"
                    $success = $true
                }
            }
            "isolate_host" {
                # Isolate host via Windows Firewall — preserve management channel to server
                try {
                    $serverHost = ([System.Uri]$ServerUrl).Host
                    $serverIp = [System.Net.Dns]::GetHostAddresses($serverHost) | Select-Object -First 1 -ExpandProperty IPAddressToString

                    # Remove any previous ATS isolation rules
                    Get-NetFirewallRule -DisplayName "ATS Isolate*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

                    # Allow inbound/outbound to management server
                    New-NetFirewallRule -DisplayName "ATS Isolate Allow Server In" -Direction Inbound -RemoteAddress $serverIp -Action Allow -Profile Any 2>$null
                    New-NetFirewallRule -DisplayName "ATS Isolate Allow Server Out" -Direction Outbound -RemoteAddress $serverIp -Action Allow -Profile Any 2>$null

                    # Allow loopback
                    New-NetFirewallRule -DisplayName "ATS Isolate Allow Loopback In" -Direction Inbound -RemoteAddress 127.0.0.1 -Action Allow -Profile Any 2>$null
                    New-NetFirewallRule -DisplayName "ATS Isolate Allow Loopback Out" -Direction Outbound -RemoteAddress 127.0.0.1 -Action Allow -Profile Any 2>$null

                    # Block all other traffic via profile defaults (explicit Block rules override Allow rules in Windows Firewall)
                    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block

                    $output = "Host isolated via Windows Firewall (management channel to $serverIp preserved)"
                    $success = $true
                } catch {
                    $output = "Failed to isolate host: $_"
                }
            }
            default {
                $output = "Unknown action type: $actionType"
            }
        }

        $statusVal = if ($success) { "completed" } else { "failed" }
        $reportPayload = @{ status = $statusVal; resultOutput = $output }
        Invoke-ApiPost "/api/native-sensors/$SensorId/action-result/$actionId" $reportPayload | Out-Null
        Write-Log "INFO" "Action $actionId -> ${statusVal}: $output"
    }
}

# ── Main loop ───────────────────────────────────────────────────────────────

Write-Log "INFO" "ATS Sensor Agent starting (v$AgentVersion)"
Write-Log "INFO" "Server: $ServerUrl, Sensor: $SensorId"

$heartbeatCounter = 0
$actionCounter = 0
$cycleCount = 0

while ($true) {
    try {
        Collect-ProcessEvents
        Collect-NetworkEvents
        Collect-AuthEvents

        $cycleCount++

        # File monitoring every 3rd cycle
        if ($cycleCount % 3 -eq 0) {
            Collect-FileEvents
        }

        # Flush events if buffer is large enough or every other cycle
        if ($script:EventBuffer.Count -ge $EventBatchSize -or $cycleCount % 2 -eq 0) {
            Send-Events
        }

        # Heartbeat
        $heartbeatCounter += 10
        if ($heartbeatCounter -ge $HeartbeatInterval) {
            $heartbeatCounter = 0
            $cpu = (Get-CimInstance Win32_Processor 2>$null | Measure-Object -Property LoadPercentage -Average).Average ?? 0
            $mem = (Get-CimInstance Win32_OperatingSystem 2>$null | ForEach-Object { [math]::Round((($_.TotalVisibleMemorySize - $_.FreePhysicalMemory) / $_.TotalVisibleMemorySize) * 100, 1) }) ?? 0
            $disk = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" 2>$null | ForEach-Object { [math]::Round((($_.Size - $_.FreeSpace) / $_.Size) * 100, 1) }) ?? 0

            Invoke-ApiPost "/api/native-sensors/$SensorId/heartbeat" @{
                cpuUsage = $cpu
                memoryUsage = $mem
                diskUsage = $disk
                agentVersion = $AgentVersion
            } | Out-Null
        }

        # Poll for actions every 30s
        $actionCounter += 10
        if ($actionCounter -ge 30) {
            $actionCounter = 0
            Execute-PendingActions
        }
    } catch {
        Write-Log "ERROR" "Agent cycle error: $_"
    }

    Start-Sleep -Seconds 10
}
'@

$agentCode | Out-File -FilePath $AgentScript -Encoding UTF8

# ── Install as Windows service ──────────────────────────────────────────────

Write-Host "[4/4] Installing Windows service..."

# Use NSSM if available, otherwise use Task Scheduler
$nssmPath = Get-Command nssm -ErrorAction SilentlyContinue

if ($nssmPath) {
    & nssm install $ServiceName powershell.exe "-ExecutionPolicy Bypass -File `"$AgentScript`""
    & nssm set $ServiceName AppDirectory $InstallDir
    & nssm set $ServiceName Description "ATS Sensor Agent - SecureNexus Security Monitoring"
    & nssm set $ServiceName Start SERVICE_AUTO_START
    & nssm start $ServiceName
} else {
    # Fallback: use Task Scheduler for persistence
    $taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$AgentScript`""
    $taskTrigger = New-ScheduledTaskTrigger -AtStartup
    $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    Register-ScheduledTask -TaskName $ServiceName -Action $taskAction -Trigger $taskTrigger -Settings $taskSettings -Principal $taskPrincipal -Description "ATS Sensor Agent" -Force

    Start-ScheduledTask -TaskName $ServiceName
}

Write-Host ""
Write-Host "============================================"
Write-Host " Installation Complete!"
Write-Host "============================================"
Write-Host ""
Write-Host "Service: Get-ScheduledTask -TaskName $ServiceName"
Write-Host "Logs:    Get-Content '$LogDir\agent.log' -Tail 50"
Write-Host "Config:  $ConfigFile"
Write-Host ""
Write-Host "Sensor ID: $env:SENSOR_ID"
Write-Host "Server:    $env:SERVER_URL"
Write-Host ""
