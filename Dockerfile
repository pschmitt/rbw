# syntax=docker/dockerfile:1

# Build stage: compile the two binaries this repo produces (`rbw` and
# `rbw-agent`, both under src/bin/) with plain cargo. The version pinned
# here should track Cargo.toml's `rust-version` (MSRV); bump both together.
FROM rust:1.88-bookworm AS build
WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY src ./src

# --no-default-features: this drops the `clipboard` cargo feature (arboard),
# which otherwise pulls in wayland-data-control system deps at build time.
# A container has no clipboard/display to speak of, so there's nothing for
# that feature to do here anyway - dropping it keeps the build stage free of
# libxkbcommon/wayland-client headers and their transitive build deps.
RUN cargo build --release --no-default-features --bin rbw --bin rbw-agent \
    && install -Dm755 target/release/rbw /out/usr/bin/rbw \
    && install -Dm755 target/release/rbw-agent /out/usr/bin/rbw-agent

# Runtime stage: debian-slim rather than alpine or distroless, because rbw
# needs a real pinentry program on PATH for interactive password/passphrase
# prompts ([package.metadata.deb] depends = "pinentry" in Cargo.toml is the
# same signal upstream's .deb packaging relies on) and pinentry's usual
# implementations are readily available and well-tested on Debian; distroless
# has no package manager to add one, and alpine's pinentry story is
# comparatively thin. `pinentry-curses` gives a working prompt out of the
# box in a plain terminal/`docker run -it`; swap in pinentry-gnome3/
# pinentry-qt etc. at the image-build layer if a GUI prompt is ever wanted
# instead. Callers that only ever use `--stdin`/non-interactive flows don't
# need this, but it's kept so interactive use isn't silently broken.
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates \
       pinentry-curses \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/usr/bin/rbw /usr/bin/rbw
COPY --from=build /out/usr/bin/rbw-agent /usr/bin/rbw-agent

ENTRYPOINT ["/usr/bin/rbw"]
CMD ["--help"]
