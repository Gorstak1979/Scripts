$webServerProcesses = @("inetinfo", "httpd", "nginx") 
while ($true) { 
    foreach ($processName in $webServerProcesses) { 
        $process = Get-Process -Name $processName -ErrorAction SilentlyContinue 
        if ($process) { 
            Stop-Process -Id $process.Id -Force 
            Write-Output "$processName process stopped." 
        } 
    } 
    Start-Sleep -Seconds 10  # Adjust the interval as needed 
} 
