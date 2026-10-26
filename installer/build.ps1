<#
  Builds the Windows installer: publishes a self-contained win-x64 build, then runs Inno Setup.
  Output: artifacts\TraceMe-Setup-<version>.exe
  Needs the .NET 10 SDK and Inno Setup 6 (winget install JRSoftware.InnoSetup).
#>
param([string]$Version)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

if (-not $Version) {
    $Version = ([xml](Get-Content src\TraceMe.csproj)).Project.PropertyGroup.Version | Where-Object { $_ } | Select-Object -First 1
}
Write-Host "Building TraceMe $Version"

$publish = Join-Path $root 'artifacts\publish'
if (Test-Path $publish) { Remove-Item $publish -Recurse -Force }
dotnet publish src -c Release -r win-x64 --self-contained true -p:Version=$Version -o $publish
if ($LASTEXITCODE -ne 0) { throw 'dotnet publish failed' }

$iscc = (Get-Command iscc -ErrorAction SilentlyContinue).Source
if (-not $iscc) {
    $iscc = @("$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe", "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe") |
        Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $iscc) { throw 'Inno Setup 6 was not found. Install it with: winget install JRSoftware.InnoSetup' }

& $iscc "/DAppVersion=$Version" "/DSourceDir=$publish" (Join-Path $PSScriptRoot 'TraceMe.iss')
if ($LASTEXITCODE -ne 0) { throw 'Inno Setup failed' }
Get-ChildItem (Join-Path $root "artifacts\TraceMe-Setup-$Version.exe") | Select-Object Name, @{n='MB';e={[math]::Round($_.Length/1MB,1)}}
