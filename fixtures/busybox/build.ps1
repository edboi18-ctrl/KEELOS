# Builds the fixture with Docker Desktop on Windows (PowerShell).
# Output in out\: busybox, busybox.sha256, busybox.config, applets.txt,
# testsuite.tar, testsuite.sha256, busybox-1.37.0.tar.bz2, packages.txt
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
docker build --output type=local,dest=out .
Get-Content out\busybox.sha256
Get-Content out\testsuite.sha256
Get-Content out\packages.txt
