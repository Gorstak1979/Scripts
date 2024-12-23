# Define log file location in the current user's Documents folder
$logPath = "$($env:USERPROFILE)\Documents\script_log.txt"

# Function to write log
function Write-Log {
    Param ([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$($timestamp): $($message)"
    Add-Content -Path $logPath -Value $logMessage
    Write-Host $logMessage  # Also print to console
}

# Check for elevation
function Elevate-Script {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Log "Script is not running as Administrator. Elevating..."
        Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File', "`"$PSCommandPath`"" -Verb RunAs
        Exit
    } else {
        Write-Log "Script is running with elevated privileges."
    }
}

# Function to add script to startup
function Add-ScriptToStartup {
    $startupPath = "$($env:APPDATA)\Microsoft\Windows\Start Menu\Programs\Startup"
    $scriptPath = $MyInvocation.MyCommand.Definition

    # Check if the script file exists
    if (-Not (Test-Path $scriptPath)) {
        Write-Log "Script file does not exist: $scriptPath"
        return
    }

    $shortcut = "$startupPath\MyScript.lnk"
    if (-not (Test-Path $shortcut)) {
        Write-Log "Adding script to startup..."
        $shell = New-Object -ComObject WScript.Shell
        $shortcutObject = $shell.CreateShortcut($shortcut)
        $shortcutObject.TargetPath = $scriptPath
        $shortcutObject.Save()
        Write-Log "Script added to startup."
    } else {
        Write-Log "Script already exists in startup."
    }
}

# Install Chocolatey if not installed
function Install-Choco {
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Log "Installing Chocolatey..."
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        Write-Log "Chocolatey installed."
    } else {
        Write-Log "Chocolatey is already installed."
    }
}

# Install 7-Zip via Chocolatey
function Install-7Zip {
    Write-Log "Installing 7-Zip via Chocolatey..."
    choco install 7zip -y
    Write-Log "7-Zip installed."
}

# Download FFmpeg
function Download-FFmpeg {
    $ffmpegUrl = "https://www.gyan.dev/ffmpeg/builds/ffmpeg-release-essentials.zip"
    $ffmpegZipPath = "$($env:TEMP)\ffmpeg.zip"
    $ffmpegExtractPath = "C:\ffmpeg"  # Change to C:\ffmpeg

    if (-not (Test-Path "$ffmpegExtractPath\ffmpeg.exe")) {
        Write-Log "Downloading FFmpeg..."
        try {
            Invoke-WebRequest -Uri $ffmpegUrl -OutFile $ffmpegZipPath -ErrorAction Stop
            Write-Log "Download completed. Extracting FFmpeg..."

            # Create the extraction directory if it doesn't exist
            if (-not (Test-Path $ffmpegExtractPath)) {
                New-Item -ItemType Directory -Path $ffmpegExtractPath | Out-Null
            }

            Expand-Archive -Path $ffmpegZipPath -DestinationPath $ffmpegExtractPath -Force
            Write-Log "FFmpeg installed at $ffmpegExtractPath."
        } catch {
            Write-Log "Error downloading or extracting FFmpeg: $_"
        }
    } else {
        Write-Log "FFmpeg is already installed."
    }
}

# Function to capture audio from all sources and apply a bandpass filter
function Capture-AudioWithBandpassFilter {
    Write-Log "Capturing audio from all sources and applying bandpass filter..."

    # Define the full path to the ffmpeg binary
    $ffmpegBinPath = "C:\ffmpeg\ffmpeg.exe"  # Adjust to point directly to ffmpeg.exe

    # Check if FFmpeg exists in the given directory
    if (-not (Test-Path -Path $ffmpegBinPath)) {
        Write-Log "FFmpeg executable not found at $ffmpegBinPath. Exiting."
        return
    }

    # Get available audio devices using FFmpeg
    $deviceList = & "$ffmpegBinPath" -list_devices true -f dshow -i dummy 2>&1 | Select-String "DirectShow audio devices"

    # Check if any devices are listed
    if ($deviceList.Count -eq 0) {
        Write-Log "No audio devices found. Exiting."
        return
    }

    # Define bandpass filter parameters
    $lowerCutoff = 20
    $upperCutoff = 20000
    $bandpassFilter = "highpass=f=$lowerCutoff,lowpass=f=$upperCutoff"

    # Capture from all available audio devices
    foreach ($device in $deviceList) {
        $deviceName = $device -replace ".*\[(.*?)\].*", '$1' # Extract the device name
        Write-Log "Capturing from device: $deviceName"

        # Start capturing and applying filters
        $ffmpegCommand = "& `"$ffmpegBinPath`" -f dshow -i audio=`"$deviceName`" -af $bandpassFilter -t 10 output_$deviceName.wav"
        Write-Log "Executing: $ffmpegCommand"
        Invoke-Expression $ffmpegCommand
    }
}

# Start logging
Write-Log "Script started."

# Elevate permissions
Elevate-Script

# Add script to startup
Add-ScriptToStartup

# Install Chocolatey
Install-Choco

# Install 7-Zip via Chocolatey
Install-7Zip

# Download and install FFmpeg
Download-FFmpeg

# Start the bandpass filter application as a background job
Start-Job -ScriptBlock { 
    Capture-AudioWithBandpassFilter 
}

Write-Log "Bandpass filter is now running in the background. You can run other commands."
Write-Log "Script completed."
