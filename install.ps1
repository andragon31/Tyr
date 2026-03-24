$ErrorActionPreference = "Stop"

$REPO = "andragon31/Tyr"
$BIN = "tyr-windows-amd64.exe"
$URL = "https://github.com/$REPO/releases/latest/download/$BIN"
$INSTALL_DIR = "$env:LOCALAPPDATA\Programs\tyr"
$EXE_PATH = "$INSTALL_DIR\tyr.exe"

$VERSION = "v1.0.0"

Clear-Host
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "  Tyr Installer $VERSION" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  >> Security, Validation & Standards <<" -ForegroundColor Gray
Write-Host "  ----------------------------------------" -ForegroundColor Gray
Write-Host ""

if (Test-Path $EXE_PATH) {
    Write-Host "Tyr already installed. Updating..." -ForegroundColor Yellow
}

Write-Host "[1/3] Downloading Tyr..." -ForegroundColor DarkCyan
$TMP = "$env:TEMP\tyr_install_$PID.exe"
try {
    Invoke-WebRequest -Uri $URL -OutFile $TMP -UseBasicParsing
} catch {
    Write-Host "Error downloading: $_" -ForegroundColor Red
    Write-Host "Make sure the release asset '$BIN' exists in GitHub!" -ForegroundColor Gray
    exit 1
}

Write-Host "[2/3] Installing to $INSTALL_DIR..." -ForegroundColor DarkCyan
New-Item -ItemType Directory -Force -Path $INSTALL_DIR | Out-Null
Copy-Item -Path $TMP -Destination $EXE_PATH -Force -ErrorAction Stop
Remove-Item -Path $TMP -Force -ErrorAction SilentlyContinue

Write-Host "[3/3] Adding to PATH..." -ForegroundColor DarkCyan

$currentMachinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
$currentUserPath = [Environment]::GetEnvironmentVariable("Path", "User")

$alreadyInMachine = $currentMachinePath -split ";" | Where-Object { $_.Trim() -eq $INSTALL_DIR }
$alreadyInUser = $currentUserPath -split ";" | Where-Object { $_.Trim() -eq $INSTALL_DIR }

$pathAdded = $false

if (-not $alreadyInMachine) {
    try {
        [Environment]::SetEnvironmentVariable("Path", "$INSTALL_DIR;$currentMachinePath", "Machine")
        Write-Host "  Added to System PATH (Machine)" -ForegroundColor Green
        $pathAdded = $true
    } catch {
        Write-Host "  No admin rights - using User PATH" -ForegroundColor Yellow
    }
}

if (-not $alreadyInUser) {
    [Environment]::SetEnvironmentVariable("Path", "$INSTALL_DIR;$currentUserPath", "User")
    Write-Host "  Added to User PATH" -ForegroundColor Green
    $pathAdded = $true
}

$env:Path = "$INSTALL_DIR;$currentMachinePath;$currentUserPath"

Write-Host ""
Write-Host "  [ Verification ]" -ForegroundColor DarkCyan
Write-Host "  ----------------" -ForegroundColor Gray
Write-Host ""

try {
    & $EXE_PATH version
} catch {
    Write-Host "Version check failed: $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "Next steps:" -ForegroundColor Green
Write-Host "  tyr init            # Initialize Tyr"
Write-Host "  tyr mcp            # Start MCP server"
Write-Host ""

if ($pathAdded) {
    Write-Host "NOTE: If 'tyr' is not found, open a new PowerShell window." -ForegroundColor Yellow
} else {
    Write-Host "IMPORTANT: Run as Administrator to install to System PATH" -ForegroundColor Red
}
