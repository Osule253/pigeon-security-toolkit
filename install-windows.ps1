$ErrorActionPreference = "Stop"

$SourceDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$AppDir = Join-Path $env:LOCALAPPDATA "PigeonSecurityToolkit"
$BinDir = Join-Path $env:LOCALAPPDATA "Programs\PST"

$Python = Get-Command python -ErrorAction SilentlyContinue
$PythonArgs = @()

if (-not $Python) {
    $Python = Get-Command py -ErrorAction SilentlyContinue
    if ($Python) {
        $PythonArgs = @("-3")
    }
}

if (-not $Python) {
    throw "Python 3.11 or later is required."
}

$PythonCommand = $Python.Source
if (-not $PythonCommand) {
    $PythonCommand = $Python.Path
}

if (-not $PythonCommand) {
    throw "Could not locate the Python executable."
}

$VersionOutput = & $PythonCommand @PythonArgs -c "import sys; print('%s.%s' % sys.version_info[:2])"

if ($LASTEXITCODE -ne 0 -or $VersionOutput -notmatch '^\d+\.\d+$') {
    throw "Could not determine the Python version."
}

$VersionParts = $VersionOutput.Split(".")
if ([int]$VersionParts[0] -lt 3 -or
    ([int]$VersionParts[0] -eq 3 -and [int]$VersionParts[1] -lt 11)) {
    throw "Python 3.11 or later is required. Found $VersionOutput"
}

$RequiredFiles = @("pst.py", "pigeon_portscan.py", "pigeon_history.py")

foreach ($File in $RequiredFiles) {
    if (-not (Test-Path (Join-Path $SourceDir $File))) {
        throw "Missing required file: $File"
    }
}

New-Item -ItemType Directory -Force -Path $AppDir, $BinDir | Out-Null

foreach ($File in $RequiredFiles) {
    Copy-Item (Join-Path $SourceDir $File) $AppDir -Force
}

foreach ($File in @("README.md", "LICENSE")) {
    $Path = Join-Path $SourceDir $File
    if (Test-Path $Path) {
        Copy-Item $Path $AppDir -Force
    }
}

$PythonLauncher = $PythonCommand.Replace([string][char]34, ([string][char]34) + ([string][char]34))
$Launcher = "@echo off`r`n`"$PythonLauncher`" $($PythonArgs -join " ") `"$AppDir\pst.py`" %*`r`n"

Set-Content -Path (Join-Path $BinDir "pst.cmd") -Value $Launcher -Encoding ASCII

& $PythonCommand @PythonArgs -m py_compile `
    (Join-Path $AppDir "pst.py") `
    (Join-Path $AppDir "pigeon_portscan.py") `
    (Join-Path $AppDir "pigeon_history.py")

if ($LASTEXITCODE -ne 0) {
    throw "PST compilation failed."
}

$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
$PathEntries = @($UserPath -split ";" | Where-Object { $_ })

if ($PathEntries -notcontains $BinDir) {
    $NewPath = (@($PathEntries) + $BinDir) -join ";"
    [Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
}

Write-Host "PST installed successfully."
Write-Host "Application: $AppDir"
Write-Host "Launcher: $(Join-Path $BinDir 'pst.cmd')"
Write-Host "Open a new terminal and run: pst --version"
