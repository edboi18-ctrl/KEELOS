# Static BusyBox fixture (P3-T13 part 2; Phase 3 acceptance item 3)

BusyBox 1.37.0, statically linked against musl. On Keel it is the
optional second shell (`sh`) and a large set of utilities. Its own test
suite (`testsuite/` in the source) is a free conformance suite for
Keel's Linux personality.

## Build

Needs Docker (Docker Desktop on Windows, or Docker in WSL or Linux).

    .\build.ps1        # Windows PowerShell
    ./build.sh         # Linux or WSL

Behind a proxy, set it in the same window first (for example
`$env:HTTPS_PROXY = 'http://host:port'` and `$env:HTTP_PROXY`); the
scripts pass it to the build. Docker does not hand a shell's environment
to `docker build`, so without that the build's `apk` and `curl` try to
connect directly. Docker Desktop's own proxy setting (Settings,
Resources, Proxies) also works.

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
| `busybox` | The static executable (static PIE, stripped, no build ID, no build time) |
| `busybox.sha256` | Its SHA-256 |
| `busybox.config` | The final `.config` (the test suite reads it to skip tests of options that are off) |
| `applets.txt` | `busybox --list`, sorted |
| `testsuite.tar` | The source's `testsuite/` directory (sorted, mtime 0, owner 0) |
| `testsuite.sha256` | Its SHA-256 |
| `busybox-1.37.0.tar.bz2` | The source the binary was built from (see Licences) |
| `packages.txt` | Every package in the build image, with its version |

## Reproducing

A second build from the same recipe must give the same `busybox.sha256`
and `testsuite.sha256`. Build twice, the second time from scratch
(`.\build.ps1 -NoCache -Out out2`, or `./build.sh --no-cache out2`), and
compare the hashes before committing anything.

To commit, copy from `out/` into this directory: `busybox`,
`busybox.sha256`, `busybox.config`, `applets.txt`, `testsuite.tar`,
`testsuite.sha256`, `busybox-1.37.0.tar.bz2` and `packages.txt`.

Reference build (2026-11-25), by the owner with Docker Desktop on
Windows; a second build with `-NoCache` gave the same hashes, so the
recipe is reproducible:

- `busybox`: SHA-256
  `a7f90ab1edb39515bda299a0fa312aca27977c880850aac34784d63e28690116`
- `testsuite.tar`: SHA-256
  `ab4c2bed59b98a5a1f10eea7d3c7f262105b54ab6769fde8384b30915bf9dcd3`

Toolchain (from `packages.txt`): gcc 15.2.0-r5, musl 1.2.6-r3, binutils
2.45.1-r1 and linux-headers 7.0.0-r1 on Alpine 3.24.4.

The executable is static PIE (`file`: "static-pie linked"), although
the configuration turns PIE off: with this toolchain, BusyBox's `-static`
link (without `-no-pie`) gave a static PIE. It needs no interpreter, and
Keel loads it at a random bias.

## The test suite on Keel (ADR 0034)

`cargo xtask test` runs BusyBox's own test suite on Keel in a phase 3
boot of its own (`--phase 3 --scenario busybox_testsuite` runs that boot
alone). Two files in this directory go with it:

- **`linux-results.txt`:** the reference, the outcome lines `runtest`
  printed under Linux 6.18 as root. It was made as follows:
  - a directory with `bin/` holding `busybox` and a symbolic link to it
    for every applet in `applets.txt` (`bin/sh` among them), `dev/` with
    `null`, `zero`, `full`, `random` and `urandom`, `tmp/` (mode 1777),
    and `bb/` holding `busybox`, `busybox.config` as `.config`, and
    `testsuite.tar` unpacked;
  - run with `unshare --mount --pid --fork --mount-proc=DIR/proc chroot
    DIR /bin/sh -c 'cd /bb/testsuite && PATH=/bin HOME=/tmp ./runtest'`,
    so the tests run as root but cannot reach the host's files, mounts
    or processes.

  Result: 909 PASS, 14 FAIL, 12 SKIPPED, 1 UNTESTED, in 92 seconds.
- **`keel-expected.txt`:** the tests that must pass on Keel: every PASS
  above except those its header lists, with what Keel lacks for each.

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
