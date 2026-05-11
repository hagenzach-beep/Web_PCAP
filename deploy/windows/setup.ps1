# PowerScale Analyzer - Windows Setup Script
# This script sets up the PowerScale PCAP & Log Analyzer on Windows systems

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "PowerScale Analyzer - Windows Setup" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    Write-Host "WARNING: Running as Administrator. This is not required but may be needed for some operations." -ForegroundColor Yellow
    Write-Host ""
}

# Check Python installation
Write-Host "Checking Python installation..." -ForegroundColor Green
try {
    $pythonVersion = python --version 2>&1
    Write-Host "Found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Python not found. Please install Python 3.8 or higher from https://www.python.org/downloads/" -ForegroundColor Red
    Write-Host "Make sure to check 'Add Python to PATH' during installation." -ForegroundColor Red
    exit 1
}

# Check Wireshark/TShark installation
Write-Host ""
Write-Host "Checking TShark installation..." -ForegroundColor Green
$tsharkPaths = @(
    "C:\Program Files\Wireshark\tshark.exe",
    "C:\Program Files (x86)\Wireshark\tshark.exe",
    "$env:LOCALAPPDATA\Wireshark\tshark.exe"
)

$tsharkFound = $false
foreach ($path in $tsharkPaths) {
    if (Test-Path $path) {
        Write-Host "Found TShark at: $path" -ForegroundColor Green
        $tsharkFound = $true
        break
    }
}

if (-not $tsharkFound) {
    Write-Host "WARNING: TShark not found in standard locations." -ForegroundColor Yellow
    Write-Host "Please install Wireshark from https://www.wireshark.org/download.html" -ForegroundColor Yellow
    Write-Host "The application will attempt to find TShark in PATH during runtime." -ForegroundColor Yellow
    Write-Host ""
    $installWireshark = Read-Host "Do you want to download Wireshark now? (y/n)"
    if ($installWireshark -eq 'y' -or $installWireshark -eq 'Y') {
        Start-Process "https://www.wireshark.org/download.html"
    }
}

# Create virtual environment
Write-Host ""
Write-Host "Creating Python virtual environment..." -ForegroundColor Green
try {
    python -m venv venv
    Write-Host "Virtual environment created successfully." -ForegroundColor Green
} catch {
    Write-Host "ERROR: Failed to create virtual environment." -ForegroundColor Red
    exit 1
}

# Activate virtual environment and install dependencies
Write-Host ""
Write-Host "Installing Python dependencies..." -ForegroundColor Green
& ".\venv\Scripts\Activate.ps1"
pip install --upgrade pip
pip install -r requirements.txt

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to install dependencies." -ForegroundColor Red
    exit 1
}

Write-Host "Dependencies installed successfully." -ForegroundColor Green

# Create necessary directories
Write-Host ""
Write-Host "Creating necessary directories..." -ForegroundColor Green
New-Item -ItemType Directory -Force -Path "pcap_files" | Out-Null
New-Item -ItemType Directory -Force -Path "logs" | Out-Null

# Create startup script
Write-Host ""
Write-Host "Creating startup script..." -ForegroundColor Green
$startupScript = @"
@echo off
echo Starting PowerScale Analyzer...
call venv\Scripts\activate.bat
streamlit run app.py
pause
"@
$startupScript | Out-File -FilePath "start.bat" -Encoding ASCII

# Create startup script for background
$backgroundScript = @"
@echo off
echo Starting PowerScale Analyzer in background...
call venv\Scripts\activate.bat
start /B streamlit run app.py --server.port=8501
echo Application started. Access at http://localhost:8501
pause
"@
$backgroundScript | Out-File -FilePath "start-background.bat" -Encoding ASCII

Write-Host "Startup scripts created: start.bat and start-background.bat" -ForegroundColor Green

# Create desktop shortcut (optional)
Write-Host ""
$createShortcut = Read-Host "Do you want to create a desktop shortcut? (y/n)"
if ($createShortcut -eq 'y' -or $createShortcut -eq 'Y') {
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $shortcutPath = Join-Path $desktopPath "PowerScale Analyzer.lnk"
    $targetPath = Join-Path $PWD "start.bat"
    
    $WScriptShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WScriptShell.CreateShortcut($shortcutPath)
    $Shortcut.TargetPath = $targetPath
    $Shortcut.WorkingDirectory = $PWD
    $Shortcut.Description = "PowerScale PCAP & Log Analyzer"
    $Shortcut.Save()
    
    Write-Host "Desktop shortcut created." -ForegroundColor Green
}

# Finished
Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Setup complete!" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "To start the application:" -ForegroundColor Green
Write-Host "  - Double-click start.bat" -ForegroundColor White
Write-Host "  - Or run: start-background.bat (runs in background)" -ForegroundColor White
Write-Host "  - Or manually: venv\Scripts\activate.bat" -ForegroundColor White
Write-Host "                streamlit run app.py" -ForegroundColor White
Write-Host ""
Write-Host "Access the application at: http://localhost:8501" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
