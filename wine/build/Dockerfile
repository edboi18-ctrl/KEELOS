# Minimal console-only Wine on musl (P4-T1, done early for P3-T1), and the
# system-call trace Phase 3 is planned from. Run by
# .github/workflows/wine-image.yml:
#     docker build --output type=local,dest=out wine/build
#
# Pinned and verified (SR-29): the base image by digest; the Wine source
# by SHA-256 (its upstream signature was checked when the pin was made,
# see README.md); every installed Alpine package is listed with its exact
# version in packages.txt next to the output.
FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS build

# build-base: gcc, make, musl-dev. mingw-w64-gcc: the PE cross-compiler
# that --enable-archs requires for Wine's Windows-side DLLs. flex and
# bison: Wine's parsers. linux-headers: kernel UAPI headers.
RUN apk add --no-cache build-base mingw-w64-gcc flex bison linux-headers perl

ARG WINE_VERSION=11.0
ARG WINE_SHA256=c07a6857933c1fc60dff5448d79f39c92481c1e9db5aa628db9d0358446e0701
WORKDIR /src
RUN wget -q "https://dl.winehq.org/wine/source/11.0/wine-${WINE_VERSION}.tar.xz" \
 && echo "${WINE_SHA256}  wine-${WINE_VERSION}.tar.xz" | sha256sum -c - \
 && tar -xJf "wine-${WINE_VERSION}.tar.xz"

# Console only, 64-bit only (spec P4-T1). Every option below is listed by
# Wine 11.0's `./configure --help`.
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
 && make -j"$(nproc)" \
 && make install \
 && apk list --installed | sort > /packages-build.txt

# The trace (spec section 10, "trace first"): on the CI runner's real
# Linux kernel, through musl. The prefix is created first and traced on
# its own, then the command Phase 3 must run is traced warm, in full and
# as counts.
FROM build AS trace
RUN apk add --no-cache strace
ENV WINEPREFIX=/tmp/prefix WINEDEBUG=-all PATH=/opt/wine/bin:$PATH
WORKDIR /trace
RUN strace -f -o prefix-trace.txt wineboot --init > prefix-stdout.txt 2>&1; \
    echo "exit $?" >> prefix-stdout.txt; \
    strace -f -o trace.txt wine cmd /c echo hello > hello-stdout.txt 2>&1; \
    echo "exit $?" >> hello-stdout.txt; \
    strace -f -c -o counts.txt wine cmd /c echo hello > /dev/null 2>&1; \
    apk list --installed | sort > packages.txt; \
    cd /opt && tar -cf - wine | xz -9 > /trace/wine-11.0-musl-x86_64.tar.xz; \
    cd /trace && sha256sum * > SHA256SUMS

FROM scratch
COPY --from=trace /trace/ /
