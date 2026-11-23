# Minimal console-only Wine on musl (P4-T1, done early for P3-T1), and the
# system-call trace Phase 3 is planned from. Run by
# .github/workflows/wine-image.yml:
#     docker build --output type=local,dest=out wine/build
#
# Pinned and verified (SR-29): the base image by digest; the Wine source
# by SHA-256 (its upstream signature was checked when the pin was made,
# see README.md); every Alpine package the build adds by SHA-256, in
# packages.lock. To renew the package pins (Alpine replaces a package when
# it publishes a fix, and the old file leaves the mirror, so the build then
# fails until the pins are renewed on purpose):
#     docker build --target pins --output type=local,dest=. wine/build

# build-base: gcc, make, musl-dev. mingw-w64-gcc: the PE cross-compiler
# that --enable-archs requires for Wine's Windows-side DLLs. flex and
# bison: Wine's parsers. linux-headers: kernel UAPI headers. perl: build
# scripts. xz: compressing the output. strace: the trace.
ARG PACKAGES="build-base mingw-w64-gcc flex bison linux-headers perl xz strace"

FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS base

# Writes packages.lock: the SHA-256 and file name of every package
# `apk add $PACKAGES` installs on top of the base image, dependencies
# included. File names carry the exact version.
FROM base AS lock
ARG PACKAGES
WORKDIR /pins
RUN apk info -v | sort > /before \
 && apk add --no-cache ${PACKAGES} \
 && apk info -v | sort > /after \
 && comm -13 /before /after | sed 's/-[^-]*-r[0-9]*$//' > names \
 && apk fetch --no-cache $(cat names) \
 && sha256sum *.apk > packages.lock \
 && test "$(wc -l < packages.lock)" = "$(wc -l < names)"
FROM scratch AS pins
COPY --from=lock /pins/packages.lock /

# Installs exactly the pinned files: apk fetches each package by name,
# sha256sum -c then requires every pinned file name (so every version) and
# hash, no other file may be present, and apk installs from those files
# alone with no network (so every dependency must be among them). apk also
# checks each package's Alpine signature, as for any install.
FROM base AS build
WORKDIR /pkgs
COPY packages.lock .
RUN apk fetch --no-cache $(sed -e 's/^[0-9a-f]*  //' -e 's/-[^-]*-r[0-9]*\.apk$//' packages.lock) \
 && sha256sum -c packages.lock \
 && test "$(ls *.apk | wc -l)" = "$(wc -l < packages.lock)" \
 && apk add --no-cache --no-network ./*.apk \
 && cd / && rm -rf /pkgs

ARG WINE_VERSION=11.0
ARG WINE_SHA256=c07a6857933c1fc60dff5448d79f39c92481c1e9db5aa628db9d0358446e0701
WORKDIR /src
RUN wget -q "https://dl.winehq.org/wine/source/11.0/wine-${WINE_VERSION}.tar.xz" \
 && echo "${WINE_SHA256}  wine-${WINE_VERSION}.tar.xz" | sha256sum -c - \
 && tar -xJf "wine-${WINE_VERSION}.tar.xz"

# Console only, 64-bit only (spec P4-T1). Every option below is listed by
# Wine 11.0's `./configure --help`.
#
# The rpath: Wine's Unix libraries (ws2_32.so and the rest) name ntdll.so
# as a DT_NEEDED dependency, and Wine loads ntdll.so itself by full path.
# glibc reuses it; musl does not. musl 1.2.6 ldso/dynlink.c matches a bare
# name against loaded libraries only by "shortname" (lines 1110-1113),
# which a library loaded by explicit path does not get (lines 1225-1226),
# so the search fails and Wine stops with "could not load kernel32.dll,
# status c0000135" (seen in the first build). With an rpath of $ORIGIN the
# search finds ntdll.so beside the library, and musl sees it is the same
# file (device and inode) already loaded and reuses it (lines 1170-1176);
# musl expands $ORIGIN for libraries (lines 910-921). Wine's configure sets
# no rpath on Linux (configure line 11105; macOS gets @loader_path, line
# 11863). makedep writes UNIXLDFLAGS into each link rule when the Makefile
# is generated, but every Unix link rule ends with $(LDFLAGS), which make
# expands when it runs and configure leaves empty; so the rpath goes there
# ($$ is make's literal $, the quotes keep the shell from expanding it).
# The loader and wineserver get it too, which changes nothing for them.
WORKDIR /src/wine-${WINE_VERSION}
RUN ./configure --prefix=/opt/wine \
      --enable-archs=x86_64 --disable-tests --disable-win16 \
      --without-x --without-wayland \
      --without-alsa --without-capi --without-coreaudio --without-cups \
      --without-dbus --without-ffmpeg --without-fontconfig --without-freetype \
      --without-gettext --without-gphoto --without-gnutls --without-gssapi \
      --without-gstreamer --without-krb5 --without-netapi --without-opencl \
      --without-opengl --without-oss --without-pcap --without-pcsclite \
      --without-pulse --without-sane --without-sdl --without-udev \
      --without-usb --without-v4l2 --without-vulkan \
 && sed -i "s|^LDFLAGS = \$|LDFLAGS = -Wl,-rpath,'\$\$ORIGIN'|" Makefile \
 && grep -x "LDFLAGS = -Wl,-rpath,'\$\$ORIGIN'" Makefile \
 && make -j"$(nproc)" \
 && make install \
 && readelf -d /opt/wine/lib/wine/x86_64-unix/ws2_32.so | grep -F 'RUNPATH' | grep -F '$ORIGIN'

# The trace (spec section 10, "trace first"): on the CI runner's real
# Linux kernel, through musl. The prefix is created first and traced on
# its own, then the command Phase 3 must run is traced warm, in full and
# as counts. -s 256 keeps arguments such as command lines readable (paths
# are printed in full regardless). "Warm" still includes wineboot: the
# first process of every session runs `wineboot --init` (Wine 11.0
# dlls/ntdll/unix/env.c, build_initial_params), which redoes the wine.inf
# install only when .update-timestamp is stale (programs/wineboot/
# wineboot.c, update_wineprefix).
FROM build AS trace
ENV WINEPREFIX=/tmp/prefix WINEDEBUG=-all PATH=/opt/wine/bin:$PATH
WORKDIR /trace
RUN strace -f -s 256 -o prefix-trace.txt wineboot --init > prefix-stdout.txt 2>&1; \
    echo "exit $?" >> prefix-stdout.txt; \
    strace -f -s 256 -o trace.txt wine cmd /c echo hello > hello-stdout.txt 2>&1; \
    echo "exit $?" >> hello-stdout.txt; \
    strace -f -c -o counts.txt wine cmd /c echo hello > /dev/null 2>&1; \
    apk list --installed | sort > packages.txt; \
    uname -srm > kernel.txt; \
    cd /opt && tar -cf - wine | xz -9 > /trace/wine-11.0-musl-x86_64.tar.xz; \
    cd /trace && sha256sum * > SHA256SUMS

FROM scratch
COPY --from=trace /trace/ /
