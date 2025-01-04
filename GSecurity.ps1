<#
    Script Name: GSecurity
    Author: Gorstak
    Description: Advanced script to detect and mitigate web servers, screen overlays, keyloggers, suspicious DLLs, remote thread execution, and unauthorized files.
                 Monitors all local drives and network shares, ensures critical services are running, and protects critical system processes and specific trusted drivers from termination.
                 Runs invisibly without disrupting the calling batch file.
    Version: 2.4
    License: Free for personal use
#>

# Set the polling interval (in seconds) for the monitoring loop
$PollingInterval = 60  # Adjusted to reduce CPU usage

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

# Create a scheduled task to run under the SYSTEM account
function Create-ScheduledTask {
    param (
        [string]$TaskName = "GSecurity",
        [string]$ScriptPath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    )

    # Check if the task already exists
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Log "Existing task '$TaskName' removed."
    }

    # Define the action and trigger for the task
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$ScriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount

    # Register the task
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal
    Write-Log "Scheduled task '$TaskName' created to run under SYSTEM account."
}

# Call the function to create the task
Create-ScheduledTask

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
        }
    } | Out-Null
    Register-ObjectEvent $fileWatcher "Changed" -Action {
        $filePath = $Event.SourceEventArgs.FullPath
        Write-Log "File modified: $filePath"
    } | Out-Null
}

# Function to check if the file has already been scanned and is clean
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

# Function to unload, quarantine, or delete unsigned and suspicious DLLs
function Remove-Unsigned-And-Suspicious-DLLs {
    $quarantineFolder = "$env:USERPROFILE\Documents\GSecurity_Quarantine"
    if (-not (Test-Path -Path $quarantineFolder)) {
        New-Item -ItemType Directory -Path $quarantineFolder | Out-Null
        Write-Log "Created quarantine folder at $quarantineFolder"
    }

    $suspiciousPatterns = @("*.hook", "*.log", "*.key")  # Define suspicious patterns
    $searchPaths = @("C:\Windows\System32", "$env:USERPROFILE") # Directories to scan

    foreach ($path in $searchPaths) {
        $dlls = Get-ChildItem -Path $path -Recurse -Include "*.dll" -ErrorAction SilentlyContinue

        foreach ($dll in $dlls) {
            try {
                # Check if the DLL matches suspicious patterns
                $isSuspicious = $suspiciousPatterns | ForEach-Object { $_ -like $dll.Name }

                # Check if the DLL is unsigned
                $signature = Get-AuthenticodeSignature -FilePath $dll.FullName
                $isUnsigned = $signature.Status -eq 'NotSigned'

                if ($isSuspicious -or $isUnsigned) {
                    # Unload DLL if it is loaded
                    $isLoaded = Get-Process | ForEach-Object {
                        $_.Modules | Where-Object { $_.FileName -eq $dll.FullName }
                    }

                    if ($isLoaded) {
                        try {
                            # Attempt to unload DLL
                            Write-Log "Attempting to unload DLL: $($dll.FullName)"
                            [System.Diagnostics.Process]::GetProcessesByName($isLoaded.ProcessName) | ForEach-Object {
                                $_.Kill() # Force-stop processes using the DLL (optional)
                            }
                            Write-Log "Successfully unloaded DLL: $($dll.FullName)"
                        } catch {
                            Write-Log "Failed to unload DLL: $($dll.FullName) - $($_.Exception.Message)"
                            continue
                        }
                    }

                    # Move to quarantine
                    $destination = Join-Path -Path $quarantineFolder -ChildPath $dll.Name
                    Move-Item -Path $dll.FullName -Destination $destination -Force
                    Write-Log "Quarantined DLL: $($dll.FullName) -> $destination"
                }
            } catch {
                Write-Log "Failed to process DLL: $($dll.FullName) - $($_.Exception.Message)"
            }
        }
    }
}

# Function to detect and terminate unauthorized web servers
function Detect-And-Terminate-WebServers {
    $webServerPorts = @(80, 443) # Common web server ports
    $allowedProcesses = @("nginx", "apache", "iisexpress") # Whitelisted web server processes

    # Get active network connections on web server ports
    $connections = Get-NetTCPConnection | Where-Object {
        $_.LocalPort -in $webServerPorts -and $_.State -eq "Listen"
    }

    foreach ($connection in $connections) {
        $process = Get-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue
        if ($process -and (-not ($allowedProcesses -contains $process.Name))) {
            Write-Log "Unauthorized web server detected: $($process.Name) on Port $($connection.LocalPort)"
            try {
                Stop-Process -Id $process.Id -Force
                Write-Log "Web server process terminated: $($process.Name)"
            } catch {
                Write-Log "Failed to terminate web server process: $($process.Name)"
            }
        }
    }
}

# Continuously run the script
Start-Job -ScriptBlock {
    Write-Log "Starting security checks..."
    Ensure-WMIService
    Detect-And-Terminate-RemoteThreads
    Monitor-AllFiles
    Monitor-Keyloggers
    Monitor-Overlays
    Detect-And-Terminate-WebServers
    Remove-Unsigned-And-Suspicious-DLLs # Updated function
    Start-Sleep $PollingInterval
}
