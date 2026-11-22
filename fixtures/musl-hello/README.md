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

Reference build: SHA-256
`aa498cc9628951fd43f59f4bf8fdd77fd77a5d6ef2380d7ca4d2f2c73cd139db`
(committed `hello`, `hello.sha256`). The first build's `packages.txt`
lacks versions (the recipe used `apk info -v`, which in apk-tools 3 prints
descriptions); the recipe now uses `apk list --installed`.
