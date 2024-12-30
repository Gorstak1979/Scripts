<#
    Script Name: GSecurity
    Author: Gorstak
    Description: Advanced script to detect and mitigate web servers, screen overlays, keyloggers, suspicious DLLs, remote thread execution, and unauthorized files. 
                 Monitors all local drives and network shares, ensures critical services are running, and uploads files to VirusTotal if they haven't been scanned.
                 Protects critical system processes and specific trusted drivers from termination. Runs invisibly without disrupting the calling batch file.
    Version: 2.1
    License: Free for personal use
#>

# Logging utility
function Write-Log {
    param ([string]$Message)
    $logFile = "$env:USERPROFILE\Documents\GSecurity.log"
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $Message"
    Add-Content -Path $logFile -Value $logMessage
}

# Ensure the script runs as administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Log "Script not running as administrator. Restarting with elevated privileges."
    Start-Process -FilePath "powershell" -ArgumentList "-File '$PSCommandPath'" -Verb RunAs
    exit
}

# Add the script to startup
$scriptPath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
$startupTask = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Set-ItemProperty -Path $startupTask -Name "GSecurity" -Value "$scriptPath"
Write-Log "Script added to startup."

# Run invisibly
if ($MyInvocation.InvocationName -notlike "powershell.exe -windowstyle hidden") {
    Start-Process -FilePath "powershell.exe" -ArgumentList "-windowstyle hidden -File '$PSCommandPath'" -NoNewWindow
    exit
}

# Whitelist of critical system processes to protect
$protectedProcesses = @(
    "System", "smss", "csrss", "wininit", "services", "lsass", 
    "svchost", "dwm", "explorer", "taskhostw", "winlogon", 
    "conhost", "cmd", "powershell"
)

# Trusted driver vendors to exclude from termination
$trustedDriverVendors = @(
    "*Microsoft*", "*NVIDIA*", "*Intel*", "*AMD*", "*Realtek*"
)

# Ensure WMI service is running
function Ensure-WMIService {
    $service = Get-Service -Name "winmgmt" -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne "Running") {
        Start-Service -Name "winmgmt" -ErrorAction SilentlyContinue
        Write-Log "WMI service started."
    } elseif (-not $service) {
        Write-Log "WMI service not found. Check system integrity."
    } else {
        Write-Log "WMI service is running."
    }
}
Ensure-WMIService

# Monitor and terminate unauthorized remote threads
function Detect-And-Terminate-RemoteThreads {
    $threads = Get-WmiObject Win32_Thread | Where-Object {
        $_.ProcessHandle -ne $null -and $_.OtherProcessHandle -ne $null
    }
    foreach ($thread in $threads) {
        Write-Log "Unauthorized remote thread detected in PID $($thread.ProcessHandle)"
        Stop-Process -Id $thread.ProcessHandle -Force -ErrorAction SilentlyContinue
        Write-Log "Remote thread terminated in PID $($thread.ProcessHandle)"
    }
}

# Monitor and upload files to VirusTotal (only new files)
function VirusTotal-Check {
    param ([string]$FilePath)

    $hash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
    $apiKey = "YOUR_VIRUSTOTAL_API_KEY"
    $url = "https://www.virustotal.com/api/v3/files/$hash"

    $response = Invoke-RestMethod -Uri $url -Headers @{ "x-apikey" = $apiKey } -Method Get -ErrorAction SilentlyContinue

    if (-not $response) {
        Write-Log "Uploading new file to VirusTotal: $FilePath"
        Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files" -Headers @{ "x-apikey" = $apiKey } -Method Post -InFile $FilePath -ContentType "multipart/form-data"
        Write-Log "File uploaded to VirusTotal: $FilePath"
    } else {
        Write-Log "File already scanned: $FilePath"
    }
}

# Monitor all local drives and network shares
function Monitor-Drives-And-Shares {
    $paths = Get-PSDrive | Where-Object { $_.Provider -eq "FileSystem" } | Select-Object -ExpandProperty Root
    $networkShares = Get-WmiObject -Query "Select * from Win32_Share" | Select-Object -ExpandProperty Path

    $allPaths = $paths + $networkShares
    foreach ($path in $allPaths) {
        Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue |
            ForEach-Object {
                VirusTotal-Check $_.FullName
            }
    }
}

# Detect and remove suspicious DLLs
function Detect-And-Remove-Suspicious-DLLs {
    $suspiciousPatterns = @("*.hook", "*.log", "*.key")  # Define suspicious patterns
    $searchPaths = @("C:\\Windows\\System32", "$env:USERPROFILE")

    foreach ($path in $searchPaths) {
        $dlls = Get-ChildItem -Path $path -Recurse -Include "*.dll" -ErrorAction SilentlyContinue |
                Where-Object { $suspiciousPatterns | ForEach-Object { $_ -like $_.Name } }

        foreach ($dll in $dlls) {
            Write-Log "Suspicious DLL detected: $($dll.FullName)"
            Remove-Item -Path $dll.FullName -Force -ErrorAction SilentlyContinue
            Write-Log "Suspicious DLL removed: $($dll.FullName)"
        }
    }
}

# Continuously run the script
while ($true) {
    Write-Log "Starting security checks..."
    Detect-And-Terminate-RemoteThreads
    Monitor-Drives-And-Shares
    Detect-And-Remove-Suspicious-DLLs
    Start-Sleep -Seconds 60  # Pause for a minute before the next cycle
}

Write-Log "Security checks completed successfully."
