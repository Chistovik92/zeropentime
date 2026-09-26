# SPDX-License-Identifier: MPL-2.0
#
# Собирает MSI узла zeropentime (Windows, WiX Toolset 5):
#   dotnet tool install --global wix --version 5.0.2
#   wix extension add -g WixToolset.Util.wixext/5.0.2
#   bash scripts/fetch-wintun.sh
#   pwsh scripts/build-msi.ps1 -Version 0.6.0 -Arch amd64 -Out dist
param(
  [Parameter(Mandatory = $true)][string]$Version,
  [ValidateSet("amd64", "arm64")][string]$Arch = "amd64",
  [string]$Out = "dist"
)
$ErrorActionPreference = "Stop"
$src = (Resolve-Path "$PSScriptRoot\..").Path
$bin = Join-Path $src "dist\msi-$Arch"
New-Item -ItemType Directory -Force $bin, $Out | Out-Null

$env:GOOS = "windows"; $env:GOARCH = $Arch; $env:CGO_ENABLED = "0"
go build -trimpath -ldflags "-s -w -X main.version=$Version" -o "$bin\zpt.exe" "$src\cmd\zpt"
if ($LASTEXITCODE -ne 0) { throw "go build" }
go build -trimpath -ldflags "-s -w -H windowsgui -X main.version=$Version" -o "$bin\zpt-tray.exe" "$src\cmd\zpt-tray"
if ($LASTEXITCODE -ne 0) { throw "go build zpt-tray" }
Remove-Item Env:GOOS, Env:GOARCH

Copy-Item "$src\third_party\wintun\bin\$Arch\wintun.dll" "$bin\wintun.dll"
Copy-Item "$src\third_party\wintun\LICENSE.txt" "$bin\wintun-LICENSE.txt"

# MSI знает только числовую версию x.y.z.
$msiVersion = ($Version -replace '[-+].*$', '')
$wixArch = @{ amd64 = "x64"; arm64 = "arm64" }[$Arch]
$msi = Join-Path $Out "zpt_${Version}_windows_$Arch.msi"
wix build "$src\deploy\packaging\windows\zpt.wxs" -arch $wixArch -ext WixToolset.Util.wixext `
  -d "Version=$msiVersion" -d "BinDir=$bin" -d "SrcDir=$src" -o $msi
if ($LASTEXITCODE -ne 0) { throw "wix build" }
Write-Output $msi
