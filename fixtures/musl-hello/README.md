# musl "hello world" fixture (Phase 1 acceptance item 1)

A C program statically linked against musl, to run as PID 1 on Keel.

## Build

Needs Docker (Docker Desktop on Windows, or Docker in WSL/Linux).

    .\build.ps1        # Windows PowerShell
    ./build.sh         # Linux or WSL

The image is pinned by digest (`alpine:3.24.4@sha256:f59abe65...71bf`).
The build writes `out/hello`, `out/packages.txt` (exact gcc, musl and
binutils versions) and `out/hello.sha256`.

## Reproducing

A second build from the same recipe must give the same SHA-256. The
committed `hello.sha256` and `packages.txt` record the reference build;
compare yours against them before the binary is accepted.

Status: recipe written; reference binary not built yet.
