# ADR 0001: xtask downloads with the system `curl` and unpacks with `tar`

Status: accepted (Phase 0)

## Context

`cargo xtask build` must fetch the pinned Limine binary release, a
gzip-compressed tar archive served over HTTPS, on a Windows host with no
Unix tools installed and on Linux CI (spec section 1, rule 5). Every crate
that enters the build has to be pinned, vendored, and reviewed (SR-29).

## Options

1. Rust crates for HTTPS and decompression (for example `ureq` + `rustls`
   + `flate2` + `tar`). Self-contained, but adds dozens of crates,
   including a TLS stack and Windows API bindings, to the vendored tree.
2. Shell out to `curl` and `tar`. Both are part of Windows 10 since
   Insider build 17063 (released as version 1803) and are present on every
   Linux CI image.
3. Commit the Limine binary to the repository. No download at all, but an
   opaque binary in git and a manual update path.

## Decision

Option 2. `xtask` runs `curl --proto =https --tlsv1.2 --fail --location`
to download and `tar -xzf` to extract, then trusts nothing but the pinned
SHA-256 of the archive and of each extracted file.

## Consequences

- The vendored dependency tree stays at 15 small crates.
- The download's integrity does not depend on TLS or on these tools: a
  wrong or tampered file fails the SHA-256 check and is deleted.
- Windows versions older than 10 1803 cannot build without installing
  curl and tar. Windows 10/11 are the only supported hosts.
- Not yet verified on a real Windows host from this development session;
  see docs/STATUS.md.

## Sources

- Microsoft, "Tar and Curl Come to Windows!":
  https://devblogs.microsoft.com/commandline/tar-and-curl-come-to-windows/
- curl project, "Microsoft's curl": https://curl.se/windows/microsoft.html
