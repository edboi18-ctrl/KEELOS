# Build recipe for the dynamically linked musl fixture (P3-T2). Pinned:
# the base image by digest (SR-29); every installed package with its exact
# version is written to packages.txt; the outputs are hash-pinned by the
# committed hello.sha256 and ld-musl.sha256.
FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS build
RUN apk add --no-cache gcc musl-dev
WORKDIR /src
COPY hello.c .
# Alpine's gcc links position-independent and dynamically by default; the
# interpreter is /lib/ld-musl-x86_64.so.1. --build-id=none and
# -ffile-prefix-map keep the output independent of the build machine.
RUN gcc -std=c11 -O2 -ffile-prefix-map=/src=. -Wl,--build-id=none -o hello hello.c \
 && strip hello \
 && cp /lib/ld-musl-x86_64.so.1 ld-musl-x86_64.so.1 \
 && apk list --installed | sort > packages.txt \
 && sha256sum hello > hello.sha256 \
 && sha256sum ld-musl-x86_64.so.1 > ld-musl.sha256 \
 && apk info -W /lib/ld-musl-x86_64.so.1 > ld-musl.owner

FROM scratch
COPY --from=build /src/hello /src/ld-musl-x86_64.so.1 /src/packages.txt /src/hello.sha256 /src/ld-musl.sha256 /src/ld-musl.owner /
