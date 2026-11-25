# Static BusyBox fixture (P3-T13 part 2; Phase 3 acceptance item 3)

BusyBox 1.37.0, statically linked against musl. On Keel it is the
optional second shell (`sh`) and a large set of utilities. Its own test
suite (`testsuite/` in the source) is a free conformance suite for
Keel's Linux personality.

## Build

Needs Docker (Docker Desktop on Windows, or Docker in WSL or Linux).

    .\build.ps1        # Windows PowerShell
    ./build.sh         # Linux or WSL

Everything is pinned:

- **The image:** `alpine:3.24.4@sha256:f59abe65...71bf`, the same image
  as `fixtures/musl-hello`.
- **The source:** `busybox-1.37.0.tar.bz2` from busybox.net, checked
  against SHA-256
  `3311dff32e746499f4df0d5df04d7eb396382d7e108bb9250e7b519b837043a4`.
  That is busybox.net's published hash, and the tarball also matches the
  SHA-512 in Alpine 3.24's APKBUILD (`ad8fd06f...e18467e`). The tarball
  is signed by the BusyBox maintainer (`busybox-1.37.0.tar.bz2.sig`, key
  of vda.linux@googlemail.com); the build checks the hash, not the
  signature.
- **The configuration:** `busyboxconfig` is Alpine 3.24's
  (`main/busybox/busyboxconfig` on aports' `3.24-stable` branch, fetched
  2026-11-25, SHA-256
  `65b29f6085cd79ab5f032d7e4299534a86c3efad240e78c16186a19bf847fcca`).
  The Dockerfile makes it static with the same `sed` Alpine uses for its
  busybox.static.

The build writes these to `out/`:

| File | What it is |
| --- | --- |
| `busybox` | The static executable (stripped, no build ID, no build time) |
| `busybox.sha256` | Its SHA-256 |
| `busybox.config` | The final `.config` (the test suite reads it to skip tests of options that are off) |
| `applets.txt` | `busybox --list`, sorted |
| `testsuite.tar` | The source's `testsuite/` directory (sorted, mtime 0, owner 0) |
| `testsuite.sha256` | Its SHA-256 |
| `busybox-1.37.0.tar.bz2` | The source the binary was built from (see Licences) |
| `packages.txt` | Every package in the build image, with its version |

## Reproducing

A second build from the same recipe must give the same `busybox.sha256`
and `testsuite.sha256`. Build twice (the second time with
`docker build --no-cache --output type=local,dest=out2 .`) and compare
the hashes before committing anything.

To commit, copy from `out/` into this directory: `busybox`,
`busybox.sha256`, `busybox.config`, `applets.txt`, `testsuite.tar`,
`testsuite.sha256`, `busybox-1.37.0.tar.bz2` and `packages.txt`.

Reference build: not made yet (the owner builds it).

## Licences of what the binary contains

- **BusyBox:** GPL-2.0-only. Its licence is in `LICENSE-busybox.txt`
  (the `LICENSE` file of the 1.37.0 tarball). GPL-2.0 section 3(a) asks
  that the complete source go with the executable. That source is the
  pinned tarball (committed beside the binary), `busyboxconfig`, and this
  Dockerfile, which gives the exact build steps.
- **musl,** statically linked: MIT. Its notice is in `LICENSE-musl.txt`
  (musl's `COPYRIGHT` at v1.2.6), as for `fixtures/musl-hello`.
- **GCC's start-up objects and runtime support:** the GCC Runtime Library
  Exception 3.1.
- **The test suite** (`testsuite.tar`): part of BusyBox, GPL-2.0-only.

The binary is used only by tests and is not part of release images.
