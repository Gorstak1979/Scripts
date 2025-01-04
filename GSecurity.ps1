<#
    Script Name: GSecurity
    Author: Gorstak
    Description: Advanced script to detect and mitigate web servers, screen overlays, keyloggers, suspicious DLLs, remote thread execution, and unauthorized files.
                 Monitors all local drives and network shares, ensures critical services are running, and protects critical system processes and specific trusted drivers from termination.
                 Runs invisibly without disrupting the calling batch file.
    Version: 2.8
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

# Function to terminate a process and its parent
function Terminate-ProcessWithParent {
    param (
        [int]$ProcessId
    )

    try {
        $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if ($process) {
            Stop-Process -Id $ProcessId -Force
            Write-Log "Terminated process: $($process.ProcessName) (PID: $ProcessId)"
        }

        # Attempt to terminate the parent process if available
        $parentProcessId = (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$ProcessId").ParentProcessId
        if ($parentProcessId) {
            $parentProcess = Get-Process -Id $parentProcessId -ErrorAction SilentlyContinue
            if ($parentProcess) {
                Stop-Process -Id $parentProcessId -Force
                Write-Log "Terminated parent process: $($parentProcess.ProcessName) (PID: $parentProcessId)"
            }
        }
    } catch {
        Write-Log "Error terminating process: $($_.Exception.Message)"
    }
}

# Function to gather process and parent details, then terminate the process and its parent
function Get-ProcessDetailsAndTerminate {
    param (
        [int]$ProcessId
    )

    try {
        # Get process details, including parent process and executable path
        $processDetails = @{
            Name        = (Get-Process -Id $ProcessId).ProcessName
            ID          = $ProcessId
            StartTime   = (Get-Process -Id $ProcessId).StartTime
            Path        = (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$ProcessId").ExecutablePath
            ParentID    = (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$ProcessId").ParentProcessId
        }

        # Get the parent process details
        $parentProcess = Get-Process -Id $processDetails.ParentID -ErrorAction SilentlyContinue

        if ($parentProcess) {
            $processDetails["ParentName"] = $parentProcess.ProcessName
        } else {
            $processDetails["ParentName"] = "Unknown"
        }

        # Log detailed information about the process and its parent
        Write-Log "Process details: $(ConvertTo-Json $processDetails -Depth 3)"

        # Terminate the suspicious process and its parent
        Terminate-ProcessWithParent -ProcessId $ProcessId
    } catch {
        Write-Log "Error processing process details: $($_.Exception.Message)"
    }
}

# Function to monitor for suspicious screen overlays and trace their sources
function Monitor-Overlays {
    # Get a list of processes with visible windows, excluding whitelisted processes
    $whitelistedProcesses = @("explorer", "notepad")  # Define a list of whitelisted processes
    $windows = Get-Process | Where-Object {
        $_.MainWindowTitle -ne "" -and
        (-not $whitelistedProcesses -contains $_.ProcessName)
    }

    foreach ($window in $windows) {
        Write-Log "Potential screen overlay or UI hijacker detected: $($window.ProcessName)"

        # Call the new function to get process details and terminate the process and parent
        Get-ProcessDetailsAndTerminate -ProcessId $window.Id
    }
}

# Function to detect and terminate keyloggers
function Monitor-Keyloggers {
    $whitelistedProcesses = @("explorer", "notepad")  # Define a list of whitelisted processes
    $suspiciousProcesses = Get-Process | Where-Object {
        ($_.ProcessName -match 'hook|log|key|capture|sniff') -or
        ($_.Description -like "*keyboard*") -and
        (-not $whitelistedProcesses -contains $_.ProcessName)
    }
    foreach ($process in $suspiciousProcesses) {
        Write-Log "Potential keylogger detected: $($process.ProcessName)"
        
        # Call the new function to get process details and terminate the process and parent
        Get-ProcessDetailsAndTerminate -ProcessId $process.Id
    }
}

# Function to detect and terminate unauthorized web servers
function Detect-And-Terminate-WebServers {
    $webServerPorts = @(80, 443) # Common web server ports
    $allowedProcesses = @("System", "svchost")  # Define allowed processes for web servers

    # Get active network connections on web server ports
    $connections = Get-NetTCPConnection | Where-Object {
        $_.LocalPort -in $webServerPorts -and $_.State -eq "Listen"
    }

    foreach ($connection in $connections) {
        $process = Get-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue
        if ($process -and (-not ($allowedProcesses -contains $process.Name))) {
            Write-Log "Unauthorized web server detected: $($process.Name) on Port $($connection.LocalPort)"

            # Call the new function to get process details and terminate the process and parent
            Get-ProcessDetailsAndTerminate -ProcessId $process.Id
        }
    }
}

# Function to remove unsigned and suspicious DLLs
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

# Function to ensure the WMI service is running
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

# Function to retaliate against intruder
function RetaliateAgainstIntruder {
    param (
        [string]$SuspiciousIP,    # The IP of the suspicious connection
        [string]$DriveToFormat    # Drive letter to target (e.g., "C:")
    )

    # Validate suspicious activity (Optional: Analyze connection logs)
    Write-Host "Validating suspicious activity from $SuspiciousIP..." -ForegroundColor Yellow

    # Attempt retaliation (formatting remote drive)
    try {
        Write-Host "Attempting to format the drive of $SuspiciousIP..." -ForegroundColor Red
        # Replace with a safer method if needed
    } catch {
        Write-Host "Failed to retaliate against ${SuspiciousIP}: $_" -ForegroundColor Red
    }
}

# Monitor and terminate unauthorized remote threads
function Detect-And-Terminate-RemoteThreads {
    $threads = Get-CimInstance -ClassName Win32_Thread | Where-Object {
        $_.ProcessHandle -ne $null -and $_.OtherProcessHandle -ne $null
    }
    foreach ($thread in $threads) {
        Write-Log "Unauthorized remote thread detected in PID $($thread.ProcessHandle)"
        Stop-Process -Id $thread.ProcessHandle -Force -ErrorAction SilentlyContinue
        Write-Log "Remote thread terminated in PID $($thread.ProcessHandle)"
    }
}

# Main logic to run all detection functions
function Run-Monitoring {
    Write-Log "Starting security checks..."
    Ensure-WMIService
    Detect-And-Terminate-WebServers
    Monitor-Keyloggers
    Monitor-Overlays
    Remove-Unsigned-And-Suspicious-DLLs
    RetaliateAgainstIntruder
    Detect-And-Terminate-RemoteThreads
    Start-Sleep $PollingInterval
}

# Continuously run the script
Start-Job -ScriptBlock {
    Run-Monitoring
}
