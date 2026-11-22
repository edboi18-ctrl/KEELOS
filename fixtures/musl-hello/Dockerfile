# Build recipe for the musl "hello world" fixture (Phase 1 acceptance 1).
# Everything is pinned: the base image by digest (SR-29), and the package
# versions are written to packages.txt next to the binary, so a rebuild
# can be compared exactly.
FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS build
RUN apk add --no-cache gcc musl-dev
WORKDIR /src
COPY hello.c .
# -static -no-pie: a fixed-address static executable (ET_EXEC).
# --build-id=none and -ffile-prefix-map keep the output independent of
# the build machine and directory (SR-30).
RUN gcc -std=c11 -O2 -static -no-pie -ffile-prefix-map=/src=. \
        -Wl,--build-id=none -o hello hello.c \
 && strip hello \
 && apk info -v gcc musl musl-dev binutils | sort > packages.txt \
 && sha256sum hello > hello.sha256

FROM scratch
COPY --from=build /src/hello /src/packages.txt /src/hello.sha256 /
