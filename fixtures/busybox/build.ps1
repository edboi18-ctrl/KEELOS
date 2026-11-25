# Builds the fixture with Docker Desktop on Windows (PowerShell).
#
#   .\build.ps1                          first build, into out\
#   .\build.ps1 -NoCache -Out out2       the rebuild from scratch, to compare
#
# Output: busybox, busybox.sha256, busybox.config, applets.txt,
# testsuite.tar, testsuite.sha256, busybox-1.37.0.tar.bz2, packages.txt
#
# A proxy set in this window ($env:HTTP_PROXY, $env:HTTPS_PROXY,
# $env:NO_PROXY) is passed to the build: Docker does not hand the shell's
# environment to it, only the predefined proxy build arguments, which it
# also keeps out of the image history and the cache (Dockerfile reference,
# "Predefined ARGs").
param(
    [string]$Out = "out",
    [switch]$NoCache
)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$dockerArgs = @("build")
if ($NoCache) { $dockerArgs += "--no-cache" }
foreach ($name in "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY") {
    $value = [Environment]::GetEnvironmentVariable($name)
    if ($value) {
        # Both spellings: apk and curl read the lower-case ones.
        $dockerArgs += "--build-arg", "$name=$value"
        $dockerArgs += "--build-arg", "$($name.ToLower())=$value"
    }
}
$dockerArgs += "--output", "type=local,dest=$Out", "."
& docker @dockerArgs
if ($LASTEXITCODE -ne 0) {
    throw "docker build failed (exit code $LASTEXITCODE); see the output above"
}
Get-Content (Join-Path $Out "busybox.sha256")
Get-Content (Join-Path $Out "testsuite.sha256")
Get-Content (Join-Path $Out "packages.txt")
