#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($env:SERVER_URL) -or [string]::IsNullOrWhiteSpace($env:ENROLLMENT_TOKEN)) {
    throw "SERVER_URL and ENROLLMENT_TOKEN environment variables are required."
}

$ServerUrl = $env:SERVER_URL.TrimEnd("/")
$InstallDir = "C:\Program Files\SecureNexus-Sensor"
$ConfigFile = Join-Path $InstallDir "config.json"
$AgentScript = Join-Path $InstallDir "agent.ps1"
$AgentVersion = "1.0.0"
$payload = @{
    enrollmentToken = $env:ENROLLMENT_TOKEN
    hostname = $env:COMPUTERNAME
    platform = "windows"
    osVersion = [Environment]::OSVersion.VersionString
    agentVersion = $AgentVersion
} | ConvertTo-Json -Compress

$response = Invoke-RestMethod -Uri "$ServerUrl/api/agent/v1/enroll" -Method Post -ContentType "application/json" -Body $payload
$SensorId = $response.data.sensorId
$ApiKey = $response.data.apiKey
if ([string]::IsNullOrWhiteSpace($SensorId) -or $ApiKey -notlike "snx_agent_*") {
    throw "Enrollment response did not contain a sensor credential."
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$config = @{ sensorId = $SensorId; apiKey = $ApiKey; serverUrl = $ServerUrl; agentVersion = $AgentVersion }
$config | ConvertTo-Json | Set-Content -Path $ConfigFile -Encoding UTF8
$acl = Get-Acl $ConfigFile
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "Allow")))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "Allow")))
Set-Acl -Path $ConfigFile -AclObject $acl

$worker = @'
$ErrorActionPreference = "Stop"
$config = Get-Content "C:\Program Files\SecureNexus-Sensor\config.json" -Raw | ConvertFrom-Json
$serverUrl = $config.serverUrl
$sensorId = $config.sensorId
$apiKey = $config.apiKey
$lastPackageSent = [DateTimeOffset]::MinValue

function Invoke-AgentPost([string]$Path, [hashtable]$Body) {
    $headers = @{ Authorization = "Bearer $apiKey" }
    Invoke-RestMethod -Uri "$serverUrl$Path" -Method Post -Headers $headers -ContentType "application/json" -Body ($Body | ConvertTo-Json -Depth 12 -Compress)
}

function Get-Heartbeat {
    $body = @{
        agentVersion = $config.agentVersion
    }
    $processor = Get-CimInstance Win32_Processor | Select-Object -First 1
    if ($null -ne $processor.LoadPercentage) { $body.cpuUsage = [double]$processor.LoadPercentage }
    $memory = Get-CimInstance Win32_OperatingSystem
    if ($null -ne $memory.TotalVisibleMemorySize -and $memory.TotalVisibleMemorySize -gt 0) {
        $body.memoryUsage = [math]::Round(($memory.TotalVisibleMemorySize - $memory.FreePhysicalMemory) * 100 / $memory.TotalVisibleMemorySize, 1)
    }
    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
    if ($null -ne $disk.Size -and $disk.Size -gt 0) {
        $body.diskUsage = [math]::Round(($disk.Size - $disk.FreeSpace) * 100 / $disk.Size, 1)
    }
    $ip = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
        $_.IPAddress -notlike "127.*" -and $_.IPAddress -ne "0.0.0.0"
    } | Select-Object -First 1
    if ($null -ne $ip) { $body.ipAddress = $ip.IPAddress }
    return $body
}

function Get-ObservedEvents {
    $events = [System.Collections.Generic.List[object]]::new()
    $source = $env:COMPUTERNAME
    Get-Process | Select-Object -First 200 | ForEach-Object {
        $events.Add(@{
            eventType = "process"
            processName = $_.ProcessName
            pid = $_.Id
            userName = $source
            rawData = @{
                processName = $_.ProcessName
                pid = $_.Id
                timestamp = [DateTime]::UtcNow.ToString("o")
            }
        })
    }
    Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object -First 100 | ForEach-Object {
        $events.Add(@{
            eventType = "network"
            srcIp = $_.LocalAddress
            srcPort = $_.LocalPort
            dstIp = $_.RemoteAddress
            dstPort = $_.RemotePort
            protocol = "tcp"
            rawData = @{
                state = [string]$_.State
                timestamp = [DateTime]::UtcNow.ToString("o")
            }
        })
    }
    Get-WinEvent -LogName Security -MaxEvents 20 -ErrorAction SilentlyContinue | ForEach-Object {
        $events.Add(@{
            eventType = "auth"
            authAction = "log"
            authResult = "observed"
            logSource = "Security"
            logMessage = $_.Message
            rawData = @{
                eventId = $_.Id
                timestamp = $_.TimeCreated.ToUniversalTime().ToString("o")
            }
        })
    }
    foreach ($path in @(
        "C:\Windows\System32\drivers\etc\hosts",
        "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    )) {
        if (Test-Path $path) {
            $file = Get-Item $path
            $events.Add(@{
                eventType = "file"
                filePath = $path
                fileAction = "snapshot"
                fileHash = (Get-FileHash -Algorithm SHA256 -Path $path).Hash
                fileSize = [int64]$file.Length
                rawData = @{
                    filePath = $path
                    timestamp = [DateTime]::UtcNow.ToString("o")
                }
            })
        }
    }
    return @($events)
}

function Get-PackageInventory {
    $packages = @()
    if ($null -ne (Get-Command Get-Package -ErrorAction SilentlyContinue)) {
        $packages += @(Get-Package -ErrorAction Stop | ForEach-Object {
            if ($_.Name -and $_.Version) {
                @{
                    packageManager = "windows"
                    packageName = [string]$_.Name
                    installedVersion = [string]$_.Version
                    source = "Get-Package"
                }
            }
        })
    }
    foreach ($root in @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )) {
        $packages += @(Get-ItemProperty $root -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.DisplayName -and $_.DisplayVersion) {
                @{
                    packageManager = "windows-registry"
                    packageName = [string]$_.DisplayName
                    installedVersion = [string]$_.DisplayVersion
                    source = "uninstall-registry"
                }
            }
        })
    }
    return @($packages | Select-Object -First 5000)
}

while ($true) {
    Invoke-AgentPost "/api/agent/v1/sensors/$sensorId/heartbeat" (Get-Heartbeat) | Out-Null
    $events = @(Get-ObservedEvents)
    if ($events.Count -gt 0) {
        Invoke-AgentPost "/api/agent/v1/sensors/$sensorId/events" @{
            batchId = "sensor-$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())-$PID"
            events = $events
        } | Out-Null
    }
    if ([DateTimeOffset]::UtcNow -ge $lastPackageSent.AddHours(6)) {
        $packages = @(Get-PackageInventory)
        if ($packages.Count -gt 0) {
            Invoke-AgentPost "/api/agent/v1/sensors/$sensorId/packages" @{
                batchId = "packages-$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())"
                host = @{
                    osId = "windows"
                    versionId = [Environment]::OSVersion.Version.ToString()
                    platform = "windows"
                }
                packages = $packages
            } | Out-Null
            $lastPackageSent = [DateTimeOffset]::UtcNow
        }
    }
    Start-Sleep -Seconds 30
}
'@
$worker | Set-Content -Path $AgentScript -Encoding UTF8
$agentAcl = Get-Acl $AgentScript
$agentAcl.SetAccessRuleProtection($true, $false)
$agentAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "Allow")))
$agentAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "Allow")))
Set-Acl -Path $AgentScript -AclObject $agentAcl

$taskName = "SecureNexus Sensor $SensorId"
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$AgentScript`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -User "SYSTEM" -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName $taskName

Write-Host "SecureNexus sensor enrolled and persistent telemetry collection started. Credential stored in $ConfigFile."
