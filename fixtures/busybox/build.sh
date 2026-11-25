#!/bin/sh
# Builds the fixture with Docker (Linux, WSL).
#
#   ./build.sh                    first build, into out/
#   ./build.sh --no-cache out2    the rebuild from scratch, to compare
#
# Output: busybox, busybox.sha256, busybox.config, applets.txt,
# testsuite.tar, testsuite.sha256, busybox-1.37.0.tar.bz2, packages.txt
#
# A proxy in the environment (HTTP_PROXY, HTTPS_PROXY, NO_PROXY, either
# case) is passed to the build as Docker's predefined proxy build
# arguments, which it keeps out of the image history and the cache.
set -eu
cd "$(dirname "$0")"
cache=
if [ "${1:-}" = "--no-cache" ]; then
    cache=--no-cache
    shift
fi
out=${1:-out}
set --
for name in HTTP_PROXY HTTPS_PROXY NO_PROXY; do
    lower=$(echo "$name" | tr A-Z a-z)
    value=$(printenv "$name" || printenv "$lower" || true)
    if [ -n "$value" ]; then
        set -- "$@" --build-arg "$name=$value" --build-arg "$lower=$value"
    fi
done
docker build $cache "$@" --output "type=local,dest=$out" .
cat "$out/busybox.sha256" "$out/testsuite.sha256" "$out/packages.txt"
