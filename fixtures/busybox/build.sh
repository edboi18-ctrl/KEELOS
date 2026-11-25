#!/bin/sh
# Builds the fixture with Docker (Linux, WSL).
# Output in out/: busybox, busybox.sha256, busybox.config, applets.txt,
# testsuite.tar, testsuite.sha256, busybox-1.37.0.tar.bz2, packages.txt
set -eu
cd "$(dirname "$0")"
docker build --output type=local,dest=out .
cat out/busybox.sha256 out/testsuite.sha256 out/packages.txt
