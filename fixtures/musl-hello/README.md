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
(committed `hello`, `hello.sha256`), built by the owner with Docker
Desktop on Windows. A second build with `--no-cache` gave the same hash,
so the recipe is reproducible. Toolchain (from that rebuild's
`packages.txt`): gcc 15.2.0-r5, musl 1.2.6-r3, binutils 2.45.1-r1 on
Alpine 3.24.4.

## Licences of what the binary contains

- musl, statically linked: MIT. Its notice is in `LICENSE-musl.txt`
  (musl's `COPYRIGHT` at tag v1.2.6, from git.musl-libc.org), as the MIT
  licence requires for copies.
- GCC's start-up objects and runtime support: covered by the GCC Runtime
  Library Exception 3.1 (`COPYING.RUNTIME` in the GCC 15.2.0 sources),
  which permits distributing the compiled program under any terms.
- `hello.c` itself: this repository's licence (MIT OR Apache-2.0).

The binary is used only by tests and is not part of release images.
