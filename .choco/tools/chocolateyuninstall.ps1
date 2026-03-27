$ErrorActionPreference = 'Stop'
$toolsDir = "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)"

# ── Uninstall GUI (MSI) ───────────────────────────────────────────────────────
# Find the MSI product code from the registry
$uninstallKey = Get-ItemProperty -Path @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
) -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like 'Anya*' }

if ($uninstallKey) {
    $silentArgs = '/quiet /norestart'
    $file = $uninstallKey.UninstallString -replace 'msiexec.exe /i','msiexec.exe' -replace 'msiexec.exe /x','msiexec.exe'

    Uninstall-ChocolateyPackage 'anya' 'msi' $silentArgs $uninstallKey.PSChildName
}

# ── Clean up CLI files ─────────────────────────────────────────────────────────
Remove-Item -Path (Join-Path $toolsDir 'anya.exe') -Force -ErrorAction SilentlyContinue
