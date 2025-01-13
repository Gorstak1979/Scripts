<#
    Script Name: GSecurity
    Author: Gorstak
    Description: Advanced script to detect and mitigate web servers, screen overlays, keyloggers, suspicious DLLs, remote thread execution, and unauthorized files.
                 Monitors all local drives and network shares, ensures critical services are running, and protects critical system processes and specific trusted drivers from termination.
                 Runs invisibly without disrupting the calling batch file. While it is not designed to be antivirus replacement, it aims to be 2nd layer of defense for high profile targets.
                 It is a part of larger script suite, called GShield with other scripts offering gaming tweaks and additional tweaks and policies for hardening.
    Version: 3.2
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

# Function to log messages to a file
function Write-Log {
    param (
        [string]$Message
    )
    $logPath = "C:\Logs\activity.log"
    Add-Content -Path $logPath -Value "$(Get-Date) - $Message"
}

# Function to terminate a process and its parent
function Terminate-ProcessWithParent {
    param (
        [int]$ProcessId
    )

    try {
        $process = Get-Process -Id $ProcessId
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
        Terminate-RemoteThread -ProcessId $ProcessId

    } catch {
        Write-Log "Error processing process details: $($_.Exception.Message)"
    }
}

# Function to monitor for suspicious screen overlays and trace their sources
function Monitor-Overlays {
    # Get a list of processes with visible windows, excluding whitelisted processes
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

# Ensure WMI and SharedAccess services are running
function Ensure-ServicesRunning {
    # Ensure WMI service is running
    $wmiService = Get-Service -Name "winmgmt" -ErrorAction SilentlyContinue
    if ($wmiService -and $wmiService.Status -ne "Running") {
        Start-Service -Name "winmgmt" -ErrorAction SilentlyContinue
        Write-Log "WMI service started."
    } elseif (-not $wmiService) {
        Write-Log "WMI service not found. Check system integrity."
    } else {
        Write-Log "WMI service is running."
    }

    # Ensure SharedAccess (Windows Firewall) service is running
    $sharedAccessService = Get-Service -Name "sharedaccess" -ErrorAction SilentlyContinue
    if ($sharedAccessService -and $sharedAccessService.Status -ne "Running") {
        Start-Service -Name "sharedaccess" -ErrorAction SilentlyContinue
        Write-Log "SharedAccess (Windows Firewall) service started."
    } elseif (-not $sharedAccessService) {
        Write-Log "SharedAccess service not found. Check system integrity."
    } else {
        Write-Log "SharedAccess service is running."
    }
}

Ensure-ServicesRunning

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

# Function to terminate remote threads
function Terminate-RemoteThread {
    param (
        [int]$ProcessId
    )

    try {
        $remoteThreads = (Get-WmiObject Win32_Thread | Where-Object { $_.ProcessHandle -eq $ProcessId })

        foreach ($thread in $remoteThreads) {
            # Terminate the remote thread
            Write-Log "Terminating remote thread (ThreadID: $($thread.ThreadID)) for process $ProcessId"
            Stop-Process -Id $thread.ProcessHandle -Force
        }
    } catch {
        Write-Log "Error terminating remote thread: $($_.Exception.Message)"
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
                return $true
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

# Function to detect remote login sessions
function Detect-RemoteLogin {
    try {
        # Get the event logs related to remote desktop sessions (Event ID 4624 for successful logons)
        $remoteLoginEvents = Get-WinEvent -LogName Security | Where-Object {
            $_.Id -eq 4624 -and $_.Message -like "*RemoteInteractive*"   # Remote interactive logons (RDP)
        }

        foreach ($event in $remoteLoginEvents) {
            # Parse the event message for the login details
            $message = $event.Message
            $ipAddress = if ($message -match "Source Network Address:\s*(\S+)") { $matches[1] } else { "Unknown IP" }
            $userName = if ($message -match "New Logon:\s*.*?Account Name:\s*(\S+)") { $matches[1] } else { "Unknown User" }
        }
    } catch {
        Write-Log "Error detecting remote login: $($_.Exception.Message)"
    }
}

# Function to retaliate against intruder
function RetaliateAgainstIntruder {
    param (
        [string]$ipAddress    # The IP of the suspicious connection
    )

    # Get the system drive dynamically
    $systemDrive = Get-SystemDrive

    # Validate suspicious activity (Optional: Analyze connection logs)
    Write-Host "Validating suspicious activity from $ipAddress..." -ForegroundColor Yellow

    # Attempt retaliation (formatting remote drive)
    try {
        Write-Host "Attempting to format the drive of $ipAddress..." -ForegroundColor Red
        Invoke-Command -ComputerName $ipAddress -ScriptBlock {
            param ($Drive)
            $Disk = Get-CimInstance -Query "SELECT * FROM Win32_Volume WHERE DriveLetter='$Drive'"
            if ($null -ne $Disk) {
                Invoke-CimMethod -InputObject $Disk -MethodName Format -Arguments @{FileSystem = "NTFS"; Full = $true; Label = "Retaliation"}
            } else {
                Write-Host "Drive $Drive not found."
            }
        } -ArgumentList $systemDrive
        Write-Host "Retaliation complete for $ipAddress." -ForegroundColor Green
    } catch {
        Write-Host ("Failed to retaliate against {0}: {1}" -f $ipAddress, $_) -ForegroundColor Red
    }
}

# Function to monitor and react to file integrity changes (e.g., restore critical files if altered)
function Monitor-FileIntegrity {
    $criticalFiles = @(
        "C:\Windows\System32\kernel32.dll",
        "C:\Windows\System32\ntdll.dll",
        "C:\Windows\System32\cmd.exe"
    )
    $fileHashes = @{}

    # Initial hash collection for integrity comparison
    foreach ($file in $criticalFiles) {
        if (Test-Path $file) {
            $hash = Get-FileHash -Path $file -Algorithm SHA256
            $fileHashes[$file] = $hash.Hash
        }
    }

    # Monitor for changes and react
    while ($true) {
        foreach ($file in $criticalFiles) {
            if (Test-Path $file) {
                $currentHash = Get-FileHash -Path $file -Algorithm SHA256
                if ($currentHash.Hash -ne $fileHashes[$file]) {
                    Write-Log "File integrity change detected for $file. Restoring to backup."
                    # Restore from backup or delete and quarantine suspicious files
                    Restore-FileFromBackup $file
                    $fileHashes[$file] = $currentHash.Hash
                }
            }
        }
        Start-Sleep -Seconds 60
    }
}

# Function to restore files from backup if integrity is compromised
function Restore-FileFromBackup {
    param (
        [string]$file
    )
    $backupDir = "C:\Backup\CriticalFiles"
    $backupFile = Join-Path -Path $backupDir -ChildPath (Split-Path $file -Leaf)

    # Check if the file exists in the backup
    if (Test-Path $backupFile) {
        Write-Log "Restoring $file from backup."
        Copy-Item -Path $backupFile -Destination $file -Force
    } else {
        Write-Log "No backup found for $file. Quarantining the file."
        Move-Item -Path $file -Destination "$backupDir\Quarantined" -Force
    }
}

# Function to monitor and terminate suspicious network connections
function Monitor-NetworkActivity {
    $trustedProcesses = @('explorer.exe', 'chrome.exe', 'firefox.exe')  # Add trusted processes

    while ($true) {
        $connections = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" }
        foreach ($connection in $connections) {
            $process = Get-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue
            if ($process -and (-not $trustedProcesses -contains $process.Name)) {
                Write-Log "Suspicious outgoing network activity detected: $($process.Name) to IP $($connection.RemoteAddress). Terminating process."
                Stop-Process -Id $process.Id -Force
            }
        }
        Start-Sleep -Seconds 60
    }
}

# Function to restrict access to critical files and directories
function Restrict-FileAccess {
    $restrictedPaths = @("C:\Windows\System32", "C:\Program Files")

    foreach ($path in $restrictedPaths) {
        $acl = Get-Acl -Path $path
        $permission = "Everyone", "FullControl", "Allow"
        $acl.SetAccessRuleProtection($true, $false)  # Prevent inheritance
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule $permission))
        Set-Acl -Path $path -AclObject $acl
        Write-Log "Access restricted to $path"
    }
}

# Function to monitor new scheduled tasks and terminate suspicious ones
function Monitor-ScheduledTasks {
    $existingTasks = Get-ScheduledTask | Select-Object -ExpandProperty TaskName

    while ($true) {
        $tasks = Get-ScheduledTask
        foreach ($task in $tasks) {
            if ($existingTasks -notcontains $task.TaskName) {
                Write-Log "New scheduled task detected: $($task.TaskName). Terminating task."
                Disable-ScheduledTask -TaskName $task.TaskName
                $existingTasks += $task.TaskName
            }
        }
        Start-Sleep -Seconds 60
    }
}

# Function to detect and terminate rootkit-like behaviors
function Monitor-Rootkit {
    # Look for hidden processes, modules, or files
    $hiddenProcesses = Get-WmiObject Win32_Process | Where-Object { $_.ExecutablePath -eq $null }

    foreach ($process in $hiddenProcesses) {
        Write-Log "Suspicious hidden process detected: $($process.ProcessName). Terminating process."
        Stop-Process -Name $process.ProcessName -Force
    }

    $hiddenFiles = Get-ChildItem -Path "C:\Windows\System32" -Recurse | Where-Object { $_.Attributes -match "Hidden" }
    foreach ($file in $hiddenFiles) {
        Write-Log "Hidden file detected: $($file.FullName). Quarantining file."
        Move-Item -Path $file.FullName -Destination "C:\Backup\Quarantined" -Force
    }
}

# Function to scan memory for suspicious activity and terminate related processes
function Scan-MemoryForMalware {
    $suspiciousPatterns = @("malware", "inject", "hook")
    $memoryDump = Get-WmiObject -Query "SELECT * FROM Win32_Process"

    foreach ($process in $memoryDump) {
        $processName = $process.Name
        foreach ($pattern in $suspiciousPatterns) {
            if ($processName -match $pattern) {
                Write-Log "Suspicious memory pattern detected in process: $processName. Terminating process."
                Stop-Process -Name $processName -Force
            }
        }
    }
}

# Function to quarantine suspicious DLLs
function Backup-QuarantineSuspiciousDLLs {
    $quarantineFolder = "$env:USERPROFILE\Documents\GSecurity_Quarantine"
    if (-not (Test-Path -Path $quarantineFolder)) {
        New-Item -ItemType Directory -Path $quarantineFolder | Out-Null
        Write-Log "Created quarantine folder at $quarantineFolder"
    }

    $suspiciousDLLs = Get-ChildItem -Path "C:\Windows\System32" -Recurse -Include "*.dll" | Where-Object {
        $_.Name -match "suspicious|hook|log|key"
    }

    foreach ($dll in $suspiciousDLLs) {
        $destination = Join-Path -Path $quarantineFolder -ChildPath $dll.Name
        Move-Item -Path $dll.FullName -Destination $destination -Force
        Write-Log "Quarantined suspicious DLL: $($dll.FullName)"
    }
}

# Function to continuously clear cache directories
function Start-CacheCleaner {
    param (
        [string[]]$CachePaths
    )

    foreach ($Path in $CachePaths) {
        if (-not (Test-Path $Path)) {
            Write-Output "Path not found: $Path"
            continue
        }

        # Create a FileSystemWatcher for the cache directory
        $watcher = New-Object System.IO.FileSystemWatcher
        $watcher.Path = $Path
        $watcher.IncludeSubdirectories = $true
        $watcher.EnableRaisingEvents = $true

        # Define the event handler to clean files immediately
        Register-ObjectEvent $watcher Created -Action {
            param($sender, $eventArgs)
            try {
                Remove-Item $eventArgs.FullPath -Force -ErrorAction SilentlyContinue
                Write-Output "Deleted cache file: $($eventArgs.FullPath)"
            } catch {
                Write-Output "Failed to delete file: $($eventArgs.FullPath)"
            }
        }

        Write-Output "Cache cleaner active for: $Path"
    }
}

# Paths to monitor for cache cleaning
$CachePaths = @(
    "$env:APPDATA\discord\Cache",
    "$env:APPDATA\discordptb\Cache",
    "$env:APPDATA\discordcanary\Cache",
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache",
    "$env:APPDATA\Mozilla\Firefox\Profiles",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache",
    "$env:APPDATA\Opera Software\Opera Stable\Cache",
    "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Cache"
)

# Special handling for Firefox profiles
$ProcessedPaths = @()
foreach ($Path in $CachePaths) {
    if ($Path -like "*Firefox*Profiles" -and (Test-Path $Path)) {
        Get-ChildItem -Path $Path -Directory | ForEach-Object {
            $ProcessedPaths += Join-Path $_.FullName "cache2"
        }
    } else {
        $ProcessedPaths += $Path
    }
}

# Start cache cleaning in parallel with the rest of the script
Start-CacheCleaner -CachePaths $ProcessedPaths

# Main logic to run all detection functions
function Run-Monitoring {
    Write-Log "Starting security checks..."
    Ensure-WMIService
    Terminate-RemoteThreads
    Detect-And-Terminate-RemoteThreads
    Monitor-AllFiles
    Monitor-Keyloggers
    Monitor-Overlays
    Detect-And-Terminate-WebServers
    Remove-Unsigned-And-Suspicious-DLLs # Updated function
    Monitor-SuspiciousDLLs
    Monitor-FileIntegrity
    Monitor-NetworkActivity
    Monitor-Rootkit
    Backup-QuarantineSuspiciousDLLs
    Scan-MemoryForMalware
    Restrict-FileAccess
    Detect-RemoteLogin
    Start-Sleep $PollingInterval
}

# Continuously run the script
Start-Job -ScriptBlock {
    Run-Monitoring
}
