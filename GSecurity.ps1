<#
    Script Name: GSecurity
    Author: Gorstak
    Description: Advanced script to detect and mitigate web servers, screen overlays, keyloggers, suspicious DLLs, remote thread execution, and unauthorized files. 
                 Monitors all local drives and network shares, ensures critical services are running, and uploads files to VirusTotal if they haven't been scanned.
                 Protects critical system processes and specific trusted drivers from termination. Runs invisibly without disrupting the calling batch file.
    Version: 2.1
    License: Free for personal use
#>

# Set your VirusTotal public API key here
$VirusTotalApiKey = "YOUR_VIRUSTOTAL_API_KEY"

# Set the polling interval (in seconds) for the monitoring loop
$PollingInterval = 300  # Adjusted to reduce CPU usage

# Dictionary to cache scanned file hashes (with clean results)
$scannedFiles = @{}

# Function to log actions and events
function Write-Log {
    param (
        [string]$Message
    )
    $logFile = "$env:USERPROFILE\Documents\GSecurity.log"
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp - $Message"
    Add-Content -Path $logFile -Value $logEntry
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

# Set the polling interval (in seconds) for the monitoring loop
$PollingInterval = 300  # Adjusted to reduce CPU usage

# Dictionary to cache scanned file hashes (with clean results)
$scannedFiles = @{}

# Trusted driver vendors to exclude from termination
$trustedDriverVendors = @(
    "*Microsoft*", "*NVIDIA*", "*Intel*", "*AMD*", "*Realtek*"
)

# Whitelist of critical processes (system-related)
$whitelistedProcesses = @(
    "explorer",    # File Explorer and Desktop
    "winlogon",    # Windows Logon Process
    "taskhostw",   # Task Host Window
    "csrss",       # Client/Server Runtime
    "services",    # Windows Services
    "lsass",       # Local Security Authority
    "dwm",         # Desktop Window Manager
    "svchost",     # Generic Host Process for Services
    "smss",        # Session Manager Subsystem
    "wininit",     # Windows Initialization Process
    "System",      # System Process
    "conhost",     # Console Window Host
    "cmd",         # Command Prompt
    "powershell"   # PowerShell itself
)

# Function to ensure WMI (Winmgmt) service is running and set to Automatic
function Ensure-WMIService {
    $wmiService = Get-Service -Name "winmgmt"
    if ($wmiService.Status -ne 'Running') {
        Write-Log "Starting WMI (winmgmt) service..."
        Set-Service -Name "winmgmt" -StartupType Automatic
        Start-Service -Name "winmgmt"
        Write-Log "WMI (winmgmt) service started."
    }
}

# Consolidated Monitor-AllFiles Function
function Monitor-AllFiles {
    # Define the drives to monitor
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { 
        $_.DriveType -in @('Fixed', 'Removable', 'Network') 
    }

    foreach ($drive in $drives) {
        $path = $drive.Root
        Write-Log "Starting to monitor: $path"

        $fileWatcher = New-Object System.IO.FileSystemWatcher
        $fileWatcher.Path = $path
        $fileWatcher.IncludeSubdirectories = $true
        $fileWatcher.EnableRaisingEvents = $true

        # Monitor created files
        Register-ObjectEvent $fileWatcher "Created" -Action {
            $filePath = $Event.SourceEventArgs.FullPath
            Write-Log "File created: $filePath"

            # Check file certificate
            if (-not (Check-FileCertificate -FilePath $filePath)) {
                Block-Execution -FilePath $filePath -Reason "Untrusted certificate"
                return
            }

            # Check with VirusTotal
            VirusTotal-Check -FilePath $filePath
        } | Out-Null

        # Monitor modified files
        Register-ObjectEvent $fileWatcher "Changed" -Action {
            $filePath = $Event.SourceEventArgs.FullPath
            Write-Log "File modified: $filePath"

            # Check file certificate
            if (-not (Check-FileCertificate -FilePath $filePath)) {
                Block-Execution -FilePath $filePath -Reason "Untrusted certificate"
                return
            }

            # Check with VirusTotal
            VirusTotal-Check -FilePath $filePath
        } | Out-Null
    }
}

# Function to monitor file changes
function Monitor-Path {
    param ([string]$Path)
    $fileWatcher = New-Object System.IO.FileSystemWatcher
    $fileWatcher.Path = $Path
    $fileWatcher.IncludeSubdirectories = $true
    $fileWatcher.EnableRaisingEvents = $true
    Register-ObjectEvent $fileWatcher "Created" -Action {
        $filePath = $Event.SourceEventArgs.FullPath
        Write-Log "New file created: $filePath"
        if (-not (Check-FileCertificate -FilePath $filePath)) {
            Block-Execution -FilePath $filePath -Reason "Untrusted certificate"
        } else {
            $scanResults = Get-VirusTotalScan -FilePath $filePath
            if ($scanResults -and $scanResults.data.attributes.last_analysis_stats.malicious -gt 0) {
                Block-Execution -FilePath $filePath -Reason "File detected as malware on VirusTotal"
            }
        }
    } | Out-Null
    Register-ObjectEvent $fileWatcher "Changed" -Action {
        $filePath = $Event.SourceEventArgs.FullPath
        Write-Log "File modified: $filePath"
    } | Out-Null
}

# Function to check if the file has already been scanned and is clean
function Check-FileInVirusTotalCache {
    param (
        [string]$fileHash
    )
    if ($scannedFiles.ContainsKey($fileHash)) {
        Write-Log "File hash $fileHash found in cache (clean)."
        return $true
    } else {
        return $false
    }
}

# Function to send the file to VirusTotal if it's not in cache and check scan results
function Get-VirusTotalScan {
    param (
        [string]$FilePath
    )
    # Calculate the file hash
    $fileHash = Get-FileHash -Algorithm SHA256 -Path $FilePath
    if (Check-FileInVirusTotalCache -fileHash $fileHash.Hash) {
        return $null
    }
    # Query VirusTotal to see if the file was already uploaded and analyzed
    $url = "https://www.virustotal.com/api/v3/files/$($fileHash.Hash)"
    $headers = @{"x-apikey" = $VirusTotalApiKey}
    $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction SilentlyContinue
    if ($response -and $response.data.attributes.last_analysis_stats.malicious -eq 0) {
        Write-Log "File $FilePath is clean, already scanned."
        $scannedFiles[$fileHash.Hash] = $true
        return $response
    } elseif ($response) {
        return $response
    } else {
        Write-Log "VirusTotal did not return any results for $FilePath. It may not have been uploaded yet."
        return $null
    }
}

# Function to block execution of a file
function Block-Execution {
    param (
        [string]$FilePath,
        [string]$Reason
    )
    # Remove all permissions from the file
    $acl = Get-Acl -Path $FilePath
    $acl.SetAccessRuleProtection($true, $false) # Protect the ACL
    $acl.Access | ForEach-Object {
        $acl.RemoveAccessRule($_)
    }
    Set-Acl -Path $FilePath -AclObject $acl
    Write-Log "Blocked file ${FilePath}: ${Reason}"
}

# Function to check the file certificate
function Check-FileCertificate {
    param (
        [string]$FilePath
    )
    try {
        $signature = Get-AuthenticodeSignature -FilePath $FilePath
        switch ($signature.Status) {
            'Valid' {
                return $true
            }
            'NotSigned' {
                Write-Log "File $FilePath is not digitally signed."
                Block-Execution -FilePath $FilePath -Reason "Not signed"
                return $false
            }
            'UnknownError' {
                Write-Log "Unknown error while verifying signature of $FilePath."
                return $false
            }
            default {
                Write-Log "File $FilePath has an invalid or untrusted signature: $($signature.Status)"
                Block-Execution -FilePath $FilePath -Reason "Invalid signature"
                return $false
            }
        }
    } catch {
        Write-Log "Error checking certificate for ${FilePath}: $($_.Exception.Message)"
        return $false
    }
}

# Advanced keylogger detection: look for suspicious processes but skip whitelisted ones
function Monitor-Keyloggers {
    $suspiciousProcesses = Get-Process | Where-Object {
        ($_.ProcessName -match 'hook|log|key|capture|sniff') -or
        ($_.Description -like "*keyboard*") -and
        (-not $whitelistedProcesses -contains $_.ProcessName)
    }
    foreach ($process in $suspiciousProcesses) {
        Write-Log "Potential keylogger detected: $($process.ProcessName)"
        try {
            Stop-Process -Id $process.Id -Force
            Write-Log "Keylogger process terminated: $($process.ProcessName)"
        } catch {
            Write-Log "Failed to terminate process: $($process.ProcessName)"
        }
    }
}

# Function to monitor for suspicious screen overlays
function Monitor-Overlays {
    $windows = Get-Process | Where-Object {
        $_.MainWindowTitle -ne "" -and
        (-not $whitelistedProcesses -contains $_.ProcessName)
    }
    foreach ($window in $windows) {
        Write-Log "Potential screen overlay or UI hijacker detected: $($window.ProcessName)"
        try {
            Stop-Process -Id $window.Id -Force
            Write-Log "Overlay process terminated: $($window.ProcessName)"
        } catch {
            Write-Log "Failed to terminate process: $($window.ProcessName)"
        }
    }
}

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
    Ensure-WMIService
    Detect-And-Terminate-RemoteThreads
    Monitor-AllFiles
    Monitor-Keyloggers
    Monitor-Overlays
    Detect-And-Remove-Suspicious-DLLs
    Start-Sleep -Seconds 60  # Pause for a minute before the next cycle
}

Write-Log "Security checks completed successfully."


Write-Log "Security checks completed successfully."
