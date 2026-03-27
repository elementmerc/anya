$ErrorActionPreference = 'Stop'
$toolsDir = "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)"
$version  = $env:chocolateyPackageVersion

# ── GitHub release URLs ────────────────────────────────────────────────────────
$msiUrl = "https://github.com/elementmerc/anya/releases/download/v${version}/Anya_${version}_x64_en-US.msi"
$cliUrl = "https://github.com/elementmerc/anya/releases/download/v${version}/anya-v${version}-x86_64-pc-windows-msvc.zip"

# ── Checksums (stamped by CI at release time — do not leave empty) ─────────────
$msiChecksum = '@@MSI_CHECKSUM@@'
$cliChecksum = '@@CLI_CHECKSUM@@'

# ── Install GUI (.msi) ────────────────────────────────────────────────────────
Install-ChocolateyPackage 'anya' 'msi' '/quiet /norestart' `
    -Url64bit $msiUrl `
    -Checksum64 $msiChecksum `
    -ChecksumType64 'sha256' `
    -ValidExitCodes @(0, 1641, 3010)

# ── Install CLI (zip → shimmed by Chocolatey) ─────────────────────────────────
Install-ChocolateyZipPackage 'anya-cli' `
    -Url64bit $cliUrl `
    -UnzipLocation $toolsDir `
    -Checksum64 $cliChecksum `
    -ChecksumType64 'sha256'

# Chocolatey auto-shims anya.exe found in $toolsDir, making it available on PATH.
