# Wine build and trace (P4-T1, P3-T1)

`Dockerfile` builds a minimal console-only Wine on Alpine (musl) and traces
`wine cmd /c echo hello` with `strace` on a real Linux kernel. The
`wine-image` workflow runs it; locally (Docker):

    docker build --output type=local,dest=out wine/build

## Output

| File | What |
| --- | --- |
| `wine-11.0-musl-x86_64.tar.xz` | The installed tree (`/opt/wine`) |
| `trace.txt` | `strace -f` of `wine cmd /c echo hello`, warm prefix |
| `counts.txt` | `strace -f -c` of the same: calls and errors per system call |
| `prefix-trace.txt` | `strace -f` of `wineboot --init` (creating the prefix) |
| `hello-stdout.txt`, `prefix-stdout.txt` | Their output and exit status |
| `packages.txt` | Every Alpine package installed, with its exact version |
| `kernel.txt` | `uname -srm` of the kernel the trace ran on |
| `SHA256SUMS` | Hashes of all of the above |

## Pins

- Base image: `alpine:3.24.4@sha256:f59abe65...71bf`, the same pin as
  `fixtures/musl-hello`.
- Wine 11.0 (stable, released 2026-01-13),
  `https://dl.winehq.org/wine/source/11.0/wine-11.0.tar.xz`, SHA-256
  `c07a6857933c1fc60dff5448d79f39c92481c1e9db5aa628db9d0358446e0701`.
  When the pin was made (2026-11-22) the upstream detached signature
  `wine-11.0.tar.xz.sign` verified as a good signature from Alexandre
  Julliard's key, fingerprint
  `DA23 579A 74D4 AD9A F9D3 F945 CEFA C8EA AF17 519D`, fetched from
  keyserver.ubuntu.com. The key itself was not independently certified
  (trust on first use, as for Limine in `docs/DEPENDENCIES.md`). The build
  checks the SHA-256.
- Configure flags: each is listed by Wine 11.0's `./configure --help`.
  64-bit only (`--enable-archs=x86_64`, which needs the MinGW-w64
  cross-compiler, `mingw-w64-gcc`), no tests, no Win16, no X11 or Wayland,
  and every optional library off.

## Notes on musl

- Wine's Unix libraries get an `$ORIGIN` rpath. Without it musl's dynamic
  linker cannot resolve their `ntdll.so` dependency and Wine stops with
  `could not load kernel32.dll, status c0000135`; the Dockerfile comment
  cites the musl source. Setting `LD_LIBRARY_PATH` to
  `lib/wine/x86_64-unix` also works; the rpath needs no environment.
- `wineboot --init` reports `failed to start
  L"C:\\windows\\syswow64\\rundll32.exe": c0000135`. Expected: the build
  is 64-bit only, so there are no 32-bit (WoW64) programs to run.

## Package pins

Every package the build adds to the base image, dependencies included
(39 files), is pinned by SHA-256 in `packages.lock`. The build fetches
each by name, then `sha256sum -c` requires every pinned file name (the
name carries the exact version) with its hash, no extra file may be
present, and apk installs from those files alone with the network off,
so a missing dependency also fails. apk still checks Alpine's signature
on each package. Checked by tampering: a changed hash, a changed version
and a removed dependency each fail the build.

Alpine replaces a package in a stable branch when it ships a fix, and
the old file leaves the mirror, so in time the build fails to fetch a
pinned file. That is deliberate: renew the pins on purpose,

    docker build --target pins --output type=local,dest=wine/build wine/build

review the diff of `packages.lock` (which packages changed and why), and
commit it. The lock was made on 2026-11-23 and matches the versions CI's
`wine-image` run 4 installed.
