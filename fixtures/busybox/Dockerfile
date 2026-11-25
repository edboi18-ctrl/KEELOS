# Build recipe for the static BusyBox fixture (P3-T13 part 2; Phase 3
# acceptance item 3: BusyBox `sh` on Keel's serial console).
#
# Pinned:
# - the base image by digest (SR-29), as fixtures/musl-hello;
# - the BusyBox 1.37.0 source tarball by SHA-256. busybox.net's own
#   busybox-1.37.0.tar.bz2.sha256 gives this hash, and Alpine 3.24's
#   APKBUILD (aports 3.24-stable, main/busybox, pkgver 1.37.0) gives a
#   SHA-512 the same tarball matches: two independent sources;
# - the configuration: Alpine 3.24's `busyboxconfig` (in this directory,
#   SHA-256 in README.md), made static the way Alpine makes its
#   busybox.static (APKBUILD `build()`: PIE off, every CONFIG_STATIC*
#   on). Alpine builds that configuration with this toolchain, so the
#   options that fail with it are already off: `tc` against current
#   kernel headers, and SHA hardware acceleration, which crashes with musl
#   on x86 (Alpine's patch 0023).
#
# Every installed package and its version goes to packages.txt, so a
# rebuild can be compared exactly.
FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS build
# curl fetches the source: BusyBox's own wget cannot go through a proxy
# to an https:// URL (networking/wget.c sends "GET https://..." to the
# proxy and never CONNECT), which a proxy may answer with a redirect loop.
RUN apk add --no-cache gcc musl-dev make linux-headers tar curl
WORKDIR /src
RUN curl -fsSLO --proto =https https://busybox.net/downloads/busybox-1.37.0.tar.bz2 \
 && echo "3311dff32e746499f4df0d5df04d7eb396382d7e108bb9250e7b519b837043a4  busybox-1.37.0.tar.bz2" \
    | sha256sum -c - \
 && tar -xjf busybox-1.37.0.tar.bz2
COPY busyboxconfig /src/
WORKDIR /src/busybox-1.37.0
# No build time in the banner (scripts/kconfig/confdata.c: an empty
# AUTOCONF_TIMESTAMP when KCONFIG_NOTIMESTAMP is set), so a rebuild gives
# the same bytes (SR-30).
ENV KCONFIG_NOTIMESTAMP=1
# -ffile-prefix-map and --build-id=none keep the build directory and
# machine out of the binary, as in fixtures/musl-hello. BusyBox's link
# step strips the result (`busybox_unstripped` -> `busybox`).
RUN sed -e 's/.*CONFIG_PIE.*/# CONFIG_PIE is not set/' \
        -e 's/.*CONFIG_STATIC\([A-Z_]*\).*/CONFIG_STATIC\1=y/' \
        /src/busyboxconfig > .config \
 && yes '' | make oldconfig > /dev/null \
 && make -j"$(nproc)" \
        CONFIG_EXTRA_CFLAGS="-ffile-prefix-map=/src/busybox-1.37.0=." \
        CONFIG_EXTRA_LDFLAGS="-Wl,--build-id=none" \
 && cp .config busybox.config \
 && ./busybox --list | sort > applets.txt \
 && tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
        -cf testsuite.tar testsuite \
 && cp /src/busybox-1.37.0.tar.bz2 . \
 && apk list --installed | sort > packages.txt \
 && sha256sum busybox > busybox.sha256 \
 && sha256sum testsuite.tar > testsuite.sha256

FROM scratch
COPY --from=build \
    /src/busybox-1.37.0/busybox \
    /src/busybox-1.37.0/busybox.sha256 \
    /src/busybox-1.37.0/busybox.config \
    /src/busybox-1.37.0/applets.txt \
    /src/busybox-1.37.0/testsuite.tar \
    /src/busybox-1.37.0/testsuite.sha256 \
    /src/busybox-1.37.0/busybox-1.37.0.tar.bz2 \
    /src/busybox-1.37.0/packages.txt \
    /
