<#
.SYNOPSIS
  Axeno relay setup for Windows.

.DESCRIPTION
  Downloads the prebuilt relay binary from GitHub Releases, generates an
  at-rest encryption key, and optionally installs the relay as an
  auto-starting scheduled task that runs under the low-privilege LOCAL SERVICE
  account. Run from an elevated (Administrator) PowerShell to install the task.

  Linux is the recommended platform for a production relay. Windows works but
  is intended for testing.

.EXAMPLE
  irm https://raw.githubusercontent.com/axenochat/axeno-relay/main/scripts/setup-relay.ps1 | iex

.PARAMETER NoService
  Set up the binary and config but do not install an auto-starting task.

.PARAMETER Bind
  Listen address (default 127.0.0.1:8787; a loopback bind enables Tor).
#>
[CmdletBinding()]
param(
  [switch]$NoService,
  [string]$Bind = "127.0.0.1:8787"
)

$ErrorActionPreference = "Stop"

# Force TLS 1.2+ for the download; older Windows PowerShell (5.1) can default to
# TLS 1.0/1.1, which GitHub rejects.
[Net.ServicePointManager]::SecurityProtocol = `
  [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# Repository that publishes releases. Update this if the project moves to an org.
$Repo = "axenochat/axeno-relay"

function Info($m) { Write-Host "==> $m" -ForegroundColor Green }
function Warn($m) { Write-Host "WARN: $m" -ForegroundColor Yellow }

Warn "Running a relay on Windows is not recommended for production - Linux is strongly advised."

# Pick the binary matching this machine's architecture.
$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
switch ($arch) {
  "Arm64" { $slug = "windows-aarch64" }
  "X64"   { $slug = "windows-x86_64" }
  default { throw "unsupported Windows architecture: $arch" }
}
$asset   = "axeno-relay-$slug.zip"
$url     = "https://github.com/$Repo/releases/latest/download/$asset"
$sumsUrl = "https://github.com/$Repo/releases/latest/download/SHA256SUMS"
$sigUrl  = "https://github.com/$Repo/releases/latest/download/SHA256SUMS.sig"

# Public key for verifying release signatures (RSA-3072 / SHA-256), in .NET XML
# form so it imports on stock Windows PowerShell. The matching private key
# (RELAY_SIGNING_KEY) signs SHA256SUMS in CI; see .github/workflows/release.yml.
$ReleasePubKeyXml = '<RSAKeyValue><Modulus>umgXLrFiBelXGnDNSem8DfotHj4SBAOFso+R/IVIsmFoO9NQkTN1Yn6m3CKF16i5cLO9AGM+mWe6u+jV/2DdVtaXUVfieIvkxstnu1KdFE9D5KFzxwFV0Jlc3Y5zZRNF9zJ9U+YTNq/A4ZTh2S+1ujFNnhYwdT6XMpf7qK5RlVtphcxSut4wKciMwBivPquGC6eJAOVj8OZHq6Z0MdNDQuyegwZGHvulfbEYqv2t0xfaZrOJY24LHn2fxpyX9qfp/T4qgL7MweSHtUg5lFVUPsz2/Kv8Zg7ucxH6YgTvLAzU+v7f6pjqTZ89QIn38ubfTYrWr+05Lzw0UY2DrPKUkXAiN6wNenAsb7TtBgMa69PzdFdU7IDOqFTNJYIWKkQEDX0vkolJ2qEg29TBg2TixTvQYjC3Ob/EtAQ2vV0D7NeOYXY/dwjAoQs/7vRPv9ob/JdOu2yktYojQPNSX0yyJfY/tFEOiAK8gYrPeZHQADqowZqRCy4OEDe6fUC8wACB</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>'

# Verify the signed SHA256SUMS and the archive's hash before unpacking. Fails
# closed (throws) on any problem.
function Assert-ReleaseSignature {
  param([string]$ArchivePath, [string]$SumsPath, [string]$SigPath, [string]$AssetName)
  $seed = New-Object System.Security.Cryptography.RSACryptoServiceProvider
  $seed.FromXmlString($ReleasePubKeyXml)
  $params = $seed.ExportParameters($false)
  # The default CSP from FromXmlString can't do SHA-256; re-import into the
  # PROV_RSA_AES (24) provider, which can.
  $csp = New-Object System.Security.Cryptography.CspParameters 24
  $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider $csp
  $rsa.ImportParameters($params)
  $sumsBytes = [System.IO.File]::ReadAllBytes($SumsPath)
  $sigBytes  = [System.IO.File]::ReadAllBytes($SigPath)
  if (-not $rsa.VerifyData($sumsBytes, "SHA256", $sigBytes)) {
    throw "SHA256SUMS signature is INVALID - refusing to install a possibly tampered binary."
  }
  $line = Get-Content $SumsPath | Where-Object { $_ -match ([regex]::Escape($AssetName) + '$') } | Select-Object -First 1
  if (-not $line) { throw "no checksum entry for $AssetName in the signed SHA256SUMS." }
  $want = (($line -split '\s+')[0]).ToLower()
  $got  = (Get-FileHash -Algorithm SHA256 -Path $ArchivePath).Hash.ToLower()
  if ($want -ne $got) { throw "checksum mismatch for $AssetName (signed $want, got $got)." }
}

if (-not (Get-Command tor -ErrorAction SilentlyContinue)) {
  Warn "The 'tor' binary is not on PATH. The relay needs it to publish a .onion address. Install the Tor Expert Bundle and add tor.exe to PATH before running in production."
}

function New-Key {
  $bytes = New-Object 'byte[]' 32
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  -join ($bytes | ForEach-Object { $_.ToString('x2') })
}

# --- Download and unpack -------------------------------------------------
$tmp = Join-Path $env:TEMP ("axeno-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  Info "Downloading $asset ..."
  $zip = Join-Path $tmp $asset
  Invoke-WebRequest -Uri $url -OutFile $zip

  Info "Verifying signature ..."
  $sums = Join-Path $tmp "SHA256SUMS"
  $sig  = Join-Path $tmp "SHA256SUMS.sig"
  Invoke-WebRequest -Uri $sumsUrl -OutFile $sums
  Invoke-WebRequest -Uri $sigUrl  -OutFile $sig
  Assert-ReleaseSignature -ArchivePath $zip -SumsPath $sums -SigPath $sig -AssetName $asset
  Info "Signature and checksum verified."

  Expand-Archive -Path $zip -DestinationPath $tmp -Force
  $exe = Join-Path $tmp "axeno-relay.exe"
  if (-not (Test-Path $exe)) { throw "archive did not contain axeno-relay.exe" }

  # --- No-service: local folder + launcher --------------------------------
  if ($NoService) {
    $dest = Join-Path (Get-Location) "axeno-relay"
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    Copy-Item $exe (Join-Path $dest "axeno-relay.exe") -Force
    $launcher = Join-Path $dest "run-relay.cmd"
    if (-not (Test-Path $launcher)) {
      $key = New-Key
      @"
@echo off
set "AXENO_KEY=$key"
set "AXENO_BIND=$Bind"
"%~dp0axeno-relay.exe"
"@ | Set-Content -Path $launcher -Encoding ASCII
    }
    Info "Installed to $dest"
    Info "Start it by running: $launcher"
    Warn "run-relay.cmd holds your at-rest key - keep it private and back it up."
    return
  }

  # --- Service (scheduled task) requires elevation ------------------------
  $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
  if (-not $isAdmin) { throw "installing the auto-start task needs an elevated PowerShell (Run as administrator)." }

  $installDir = Join-Path $env:ProgramFiles "Axeno"
  $dataDir    = Join-Path $env:ProgramData "Axeno"
  New-Item -ItemType Directory -Path $installDir -Force | Out-Null
  New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
  Copy-Item $exe (Join-Path $installDir "axeno-relay.exe") -Force

  # Launcher carries the environment; the relay (LOCAL SERVICE) reads it at start.
  $launcher = Join-Path $dataDir "run-relay.cmd"
  if (Test-Path $launcher) {
    Warn "$launcher exists; keeping the existing AXENO_KEY."
  } else {
    $key = New-Key
    @"
@echo off
set "AXENO_KEY=$key"
set "AXENO_BIND=$Bind"
set "AXENO_DATA_DIR=$dataDir"
"$installDir\axeno-relay.exe"
"@ | Set-Content -Path $launcher -Encoding ASCII
    Info "Generated at-rest key in $launcher. Back this file up."
  }

  # Lock down the launcher (holds the key) and data dir to SYSTEM /
  # Administrators / LOCAL SERVICE only.
  & icacls $launcher /inheritance:r /grant "SYSTEM:(R)" "Administrators:(R)" "LOCAL SERVICE:(R)" | Out-Null
  & icacls $dataDir  /inheritance:r /grant "SYSTEM:(F)" "Administrators:(F)" "LOCAL SERVICE:(M)" /T | Out-Null

  Info "Registering auto-start task 'AxenoRelay' as LOCAL SERVICE ..."
  $action    = New-ScheduledTaskAction -Execute $launcher
  $trigger   = New-ScheduledTaskTrigger -AtStartup
  $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\LOCAL SERVICE" -LogonType ServiceAccount -RunLevel Limited
  $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                 -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
  Register-ScheduledTask -TaskName "AxenoRelay" -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null
  Start-ScheduledTask -TaskName "AxenoRelay"

  Info "Installed and started."
  Info "Manage it:     Get-ScheduledTask AxenoRelay ; Stop-ScheduledTask AxenoRelay"
  Info "Onion address: Get-Content '$dataDir\onion_address.txt'   (once Tor publishes it)"
}
finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
