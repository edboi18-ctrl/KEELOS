#!/bin/sh
# Builds the fixture with Docker (Linux, WSL).
# Output: out/hello, out/packages.txt, out/hello.sha256
set -eu
cd "$(dirname "$0")"
docker build --output type=local,dest=out .
cat out/hello.sha256 out/packages.txt
