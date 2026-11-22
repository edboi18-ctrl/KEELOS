# Builds the fixture with Docker Desktop on Windows (PowerShell).
# Output: out\hello, out\packages.txt, out\hello.sha256
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
docker build --output type=local,dest=out .
Get-Content out\hello.sha256
Get-Content out\packages.txt
