# Dynamically linked musl fixture (P3-T2)

A C "hello world" dynamically linked against musl (P3-T2), and a second
program, `greet`, linked against a shared library of its own,
`libkeelgreet.so` (P3-T7). It also carries musl's dynamic linker, which
is also musl's libc. On Keel the library is at `/lib/libkeelgreet.so`,
on musl's default search path. `greet` prints the library's string and a
count kept in the library's data segment, so its code, read-only data
and writable data all come through file mappings. Keel's loader loads both
(`PT_INTERP` names `/lib/ld-musl-x86_64.so.1`) and starts the dynamic
linker, which relocates itself and the program and runs it.

## Build

Needs Docker:

    docker build --output type=local,dest=out fixtures/musl-dynamic

The image is pinned by digest (`alpine:3.24.4@sha256:f59abe65...71bf`),
the same as `fixtures/musl-hello`. The build writes these files to `out/`:

- `hello`;
- `ld-musl-x86_64.so.1`, copied from the image's `/lib`;
- `hello.sha256` and `ld-musl.sha256`;
- `packages.txt`, the exact versions of every installed package;
- `ld-musl.owner`, the package that owns the dynamic linker:
  `musl-1.2.6-r3`;
- `greet` and `libkeelgreet.so`, with `greet.sha256` and
  `libkeelgreet.sha256`;
- `threads`, `signals`, `acceptance2` and `stress`, with
  `threads.sha256`, `signals.sha256`, `acceptance2.sha256` and
  `stress.sha256`.

## Reference build

These were built on 2026-11-23 and committed:

- `hello`: SHA-256
  `a53d658fc234ff80585cf8c11c4473767091e08f475b926587a27f7746ff7513`.
  It is a position-independent executable (`ET_DYN`) whose only
  `DT_NEEDED` is `libc.musl-x86_64.so.1`.
- `ld-musl-x86_64.so.1`: SHA-256
  `095b047c631447e4fa50401fa7ffce01f678587040d65ba18c574981dc630de5`,
  from `musl-1.2.6-r3`.

- `greet`: SHA-256
  `2ff5f08001454df0de68b46d20ceb5bdaddef3ae3fe4a3de6247bfcc06c487cc`.
  Its `DT_NEEDED` are `libkeelgreet.so` and `libc.musl-x86_64.so.1`,
  with no rpath.
- `libkeelgreet.so`: SHA-256
  `a0e3d47cfd52cd5a8d679a707c3ec77b54004909308dacd1d723f919f4f88ec3`.
- `threads` (P3-T4, musl pthreads; see the comments in `threads.c`):
  SHA-256
  `5f9a6dba8d4a4bd87868874b984f1ae605dd4a97ab4ab2d0845ba0b7d5206f57`.
- `signals` (P3-T6, signal delivery; see the comments in `signals.c`):
  SHA-256
  `57ac1a919156ed1a40d624171d7f84f7720c2304aba82cfccdb42d8a2c81ae6d`.
  Adding it changed no other output or `packages.txt`.

Two more builds with `--no-cache` gave the same hashes and the same
`packages.txt`. Adding `greet` changed neither `hello` nor the dynamic
linker. The toolchain was gcc 15.2.0-r5, musl 1.2.6-r3 and
binutils 2.45.1-r1, on Alpine 3.24.4. `cargo xtask build` refuses either
file if its hash differs.

- `acceptance2` (Phase 3 acceptance item 2: threads, signal handlers on
  each thread's alternate stack, and a Unix socket to a forked child; see
  the comments in `acceptance2.c`): SHA-256
  `7784073c339971e050451b0effd581eae76dd64d2918bb7cd5065cb80c3fbbd6`.
  Built on 2026-11-26, twice with `--no-cache`, giving the same hash.
  Every other output was byte-for-byte the same as before. Alpine had
  updated one toolchain dependency, zstd-libs 1.5.7-r2 to 1.6.0-r1, and
  `packages.txt` now records that build.
- `stress` (Phase 3 acceptance item 4, the fork, thread and signal
  stress test; see `stress.c` and ADR 0038): a static musl build (static
  PIE), so it needs no dynamic linker in the compartment it runs in.
  SHA-256 `c60e37f01f0acb1e99c234d9643fdf8ec1d8dc0f3c79932977241dd612d75083`,
  built twice with `--no-cache`, giving the same hash; no other output
  changed.

Under Linux, `cargo xtask test` runs each program as
`ld-musl-x86_64.so.1 program`, since musl's dynamic linker can be run as
a command. `LD_LIBRARY_PATH` names the copied fixture libraries, and
nothing else from the environment is passed. That gives the same lines,
and needs no musl installed on the host. There is deliberately no
`$ORIGIN` rpath: for the main program musl would resolve it with
`readlink("/proc/self/exe")`, and Keel has no procfs yet.

## Licences

- musl, the dynamic linker and libc: MIT. Its notice is in
  `LICENSE-musl.txt`, musl's `COPYRIGHT` at v1.2.6, the same file as in
  `fixtures/musl-hello`.
- GCC's start-up objects: covered by the GCC Runtime Library Exception
  3.1.
- `hello.c`: this repository's licence.

Both files are used only by tests and are not part of release images.
