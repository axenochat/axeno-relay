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
  [switch]$Reset,
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
  $sumsBytes = [System.IO.File]::ReadAllBytes($SumsPath)
  $sigBytes  = [System.IO.File]::ReadAllBytes($SigPath)
  $verified = $false
  try {
    # Primary path: provider-agnostic RSA. Works on PowerShell 7 (.NET 5+) and on
    # modern Windows PowerShell 5.1 (.NET Framework 4.7.2+). RSASignaturePadding
    # .Pkcs1 + SHA-256 matches the relay CI's `openssl dgst -sha256 -sign`.
    $rsa = [System.Security.Cryptography.RSA]::Create()
    $rsa.FromXmlString($ReleasePubKeyXml)
    $verified = $rsa.VerifyData($sumsBytes, $sigBytes,
      [System.Security.Cryptography.HashAlgorithmName]::SHA256,
      [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
  } catch {
    # Fallback for older Windows PowerShell 5.1, whose default RSACryptoServiceProvider
    # can't do SHA-256 through the modern API: re-import into the PROV_RSA_AES (24)
    # provider and use the legacy string-hash overload. Windows-only (needs CAPI).
    $seed = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $seed.FromXmlString($ReleasePubKeyXml)
    $params = $seed.ExportParameters($false)
    $csp = New-Object System.Security.Cryptography.CspParameters 24
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider $csp
    $rsa.ImportParameters($params)
    $verified = $rsa.VerifyData($sumsBytes, "SHA256", $sigBytes)
  }
  if (-not $verified) {
    throw "SHA256SUMS signature is INVALID - refusing to install a possibly tampered binary."
  }
  $line = Get-Content $SumsPath | Where-Object { $_ -match ([regex]::Escape($AssetName) + '$') } | Select-Object -First 1
  if (-not $line) { throw "no checksum entry for $AssetName in the signed SHA256SUMS." }
  $want = (($line -split '\s+')[0]).ToLower()
  $got  = (Get-FileHash -Algorithm SHA256 -Path $ArchivePath).Hash.ToLower()
  if ($want -ne $got) { throw "checksum mismatch for $AssetName (signed $want, got $got)." }
}

# Windows has no standard package manager for a standalone tor.exe (the Tor
# Expert Bundle is a manual download), so unlike Linux/macOS this script cannot
# install it automatically. Flag it clearly. The scheduled task runs as LOCAL
# SERVICE, which only sees the system PATH, so tor.exe must be on the system PATH.
$torOk = [bool](Get-Command tor -ErrorAction SilentlyContinue)
if (-not $torOk) {
  Warn "Tor is not on PATH. The relay needs it to publish a .onion address."
  Warn "Install the Tor Expert Bundle and add tor.exe to the system-wide PATH,"
  Warn "then restart the relay."
}

function New-Key {
  $bytes = New-Object 'byte[]' 32
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  -join ($bytes | ForEach-Object { $_.ToString('x2') })
}

# Poll for the published onion address for up to ~90s and print it, else fall
# back to an instruction.
function Wait-Onion {
  param([string]$File)
  Write-Host "==> Waiting for Tor to publish the hidden service (first run can take ~30-90s)" -NoNewline -ForegroundColor Green
  $onion = $null
  for ($i = 0; $i -lt 30; $i++) {
    if ((Test-Path $File) -and ((Get-Item $File).Length -gt 0)) {
      $onion = (Get-Content -Raw $File).Trim(); break
    }
    Start-Sleep -Seconds 3; Write-Host "." -NoNewline
  }
  Write-Host ""
  if ($onion) {
    Info "Relay address (share this with the people who will use it):"
    Write-Host "    $onion" -ForegroundColor Green
  } else {
    Warn "Not published yet. Check again shortly:  Get-Content '$File'"
  }
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
set "AXENO_DATA_DIR=%~dp0axeno-relay-data"
"%~dp0axeno-relay.exe"
"@ | Set-Content -Path $launcher -Encoding ASCII
    }
    Info "Installed to $dest"
    if (-not $torOk) {
      Warn "Tor is not on PATH. Install the Tor Expert Bundle and add tor.exe to PATH;"
      Warn "the relay needs it to publish a .onion address."
    }
    Info "Next steps:"
    Info "  1. Start it:  $launcher"
    Info "  2. Wait ~30-90s, then read your address:  Get-Content '$dest\axeno-relay-data\onion_address.txt'"
    Info "  3. Share that ws://...onion/ws address; add it in the Axeno desktop app (Settings)."
    Warn "run-relay.cmd holds your at-rest key. Keep it private and back it up."
    return
  }

  # --- Service (scheduled task) requires elevation ------------------------
  $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
  if (-not $isAdmin) { throw "installing the auto-start task needs an elevated PowerShell (Run as administrator)." }

  $installDir = Join-Path $env:ProgramFiles "Axeno"
  $dataDir    = Join-Path $env:ProgramData "Axeno"

  if ($Reset) {
    Warn "Reset requested: removing the existing task, key, and state."
    Unregister-ScheduledTask -TaskName "AxenoRelay" -Confirm:$false -ErrorAction SilentlyContinue
    if (Test-Path $dataDir) { Remove-Item -Recurse -Force $dataDir -ErrorAction SilentlyContinue }
  }

  New-Item -ItemType Directory -Path $installDir -Force | Out-Null
  New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
  Copy-Item $exe (Join-Path $installDir "axeno-relay.exe") -Force

  # Launcher carries the environment; the relay (LOCAL SERVICE) reads it at start.
  # Its output is redirected to relay.log so a startup failure can be diagnosed
  # (a scheduled task otherwise discards stdout/stderr).
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
"$installDir\axeno-relay.exe" >> "%~dp0relay.log" 2>&1
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

  # Confirm it stays up instead of reporting success over a crash loop. A last
  # result that is neither "running" (267009) nor success usually means leftover
  # state from an earlier install sealed under a different at-rest key.
  Start-Sleep -Seconds 3
  $res = (Get-ScheduledTaskInfo -TaskName "AxenoRelay").LastTaskResult
  if ($res -ne 267009 -and $res -ne 0) {
    Warn "The relay did not stay running (last result $res). Recent log:"
    $log = Join-Path $dataDir "relay.log"
    if (Test-Path $log) { Get-Content -Tail 15 $log | ForEach-Object { Write-Host "    $_" } }
    Warn "If the log mentions decrypting relay keys, leftover state is sealed under a"
    Warn "different key. Re-run with -Reset to wipe it and start fresh."
    throw "relay failed to start"
  }

  Info "Installed and started."
  if ($torOk) { Wait-Onion (Join-Path $dataDir "onion_address.txt") }

  Write-Host ""
  Info "Next steps:"
  Info "  1. Share your ws://...onion/ws address (above) with the people who will use this relay."
  Info "  2. In the Axeno desktop app: Settings -> add that relay -> set it as your default."
  Info "  3. Use Add Contact to generate and exchange a connection code, then start messaging."
  Info "Manage the relay:"
  Info "  Get-ScheduledTask AxenoRelay              # status"
  Info "  Start-ScheduledTask AxenoRelay            # start (e.g. after installing Tor)"
  Info "  Stop-ScheduledTask AxenoRelay             # stop"
  Info "  Get-Content '$dataDir\onion_address.txt'  # your address"
}
finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
