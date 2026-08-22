#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($env:SERVER_URL) -or [string]::IsNullOrWhiteSpace($env:ENROLLMENT_TOKEN)) {
    throw "SERVER_URL and ENROLLMENT_TOKEN environment variables are required."
}

$ServerUrl = $env:SERVER_URL.TrimEnd("/")
$InstallDir = "C:\Program Files\SecureNexus-Sensor"
$ConfigFile = Join-Path $InstallDir "config.json"
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

$headers = @{ Authorization = "Bearer $ApiKey" }
$heartbeat = @{
    cpuUsage = 0
    memoryUsage = 0
    diskUsage = 0
    agentVersion = $AgentVersion
} | ConvertTo-Json -Compress
Invoke-RestMethod -Uri "$ServerUrl/api/agent/v1/sensors/$SensorId/heartbeat" -Method Post -Headers $headers -ContentType "application/json" -Body $heartbeat | Out-Null

Write-Host "SecureNexus sensor enrolled successfully. Credential stored in $ConfigFile."
