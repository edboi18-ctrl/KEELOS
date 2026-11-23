# Dynamically linked musl fixture (P3-T2)

A C "hello world" dynamically linked against musl. It also carries musl's
dynamic linker, which is also musl's libc. Keel's loader loads both
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
  `musl-1.2.6-r3`.

## Reference build

These were built on 2026-11-23 and committed:

- `hello`: SHA-256
  `a53d658fc234ff80585cf8c11c4473767091e08f475b926587a27f7746ff7513`.
  It is a position-independent executable (`ET_DYN`) whose only
  `DT_NEEDED` is `libc.musl-x86_64.so.1`.
- `ld-musl-x86_64.so.1`: SHA-256
  `095b047c631447e4fa50401fa7ffce01f678587040d65ba18c574981dc630de5`,
  from `musl-1.2.6-r3`.

Two more builds with `--no-cache` gave the same hashes and the same
`packages.txt`. The toolchain was gcc 15.2.0-r5, musl 1.2.6-r3 and
binutils 2.45.1-r1, on Alpine 3.24.4. `cargo xtask build` refuses either
file if its hash differs.

Under Linux, `cargo xtask test` runs it as
`ld-musl-x86_64.so.1 hello`, since musl's dynamic linker can be run as a
command. That gives the same line, and needs no musl installed on the
host.

## Licences

- musl, the dynamic linker and libc: MIT. Its notice is in
  `LICENSE-musl.txt`, musl's `COPYRIGHT` at v1.2.6, the same file as in
  `fixtures/musl-hello`.
- GCC's start-up objects: covered by the GCC Runtime Library Exception
  3.1.
- `hello.c`: this repository's licence.

Both files are used only by tests and are not part of release images.
