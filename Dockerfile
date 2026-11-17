# The relay container image (DESIGN.md "Relay deployment").
#
# The build stage makes a static musl binary for the target architecture,
# with a vendored OpenSSL for the passkey sign-in (webauthn-rs). The runtime
# image is distroless/static: no shell, no package manager and no libc. It
# holds the binary, the CA certificates and the nonroot user (UID 65532).
#
# Build it for one architecture with `docker build --platform linux/amd64 .`
# or `linux/arm64`. Each architecture builds natively under its own platform.
#
# Run: docker run -e SNAILFISH_AUTHORITY=sync.example.net -v data:/data -v secrets:/secrets -p 8080:8080 IMAGE
# The secrets volume holds session.key. Backups do not copy it ([STO-9]).

FROM rust:1.99.1-alpine3.22@sha256:9a744dc47d1ac2a7d17fc3cedfc8b4928b1696dfcba3274ab25bfb40988a9ff0 AS build
# The vendored OpenSSL build needs a C compiler, perl and make.
RUN apk add --no-cache musl-dev perl make linux-headers
# cargo-auditable writes the dependency tree into a section of the binary.
# Vulnerability scanners and the SBOM read it from the stripped binary.
# --locked uses the lock file of the release. crates.io checksums each crate.
RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    cargo install --locked cargo-auditable@0.7.7

WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates crates
# The image build only: one codegen unit and fat LTO give a smaller and
# faster binary. The workspace release profile keeps overflow-checks.
ENV CARGO_PROFILE_RELEASE_LTO=fat \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
    CARGO_PROFILE_RELEASE_STRIP=symbols
# The cache mounts keep the crate downloads and the build output between
# local builds. They do not go into a layer. The target cache is per platform,
# because the build artefacts of two architectures must not mix.
ARG TARGETPLATFORM
RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=cargo-target-${TARGETPLATFORM},target=/src/target,sharing=locked \
    cargo auditable build --locked --release -p snailfish-relay \
 && install -D -m 0755 target/release/snailfish-relay /out/snailfish-relay \
 # A static binary has no dynamic loader entry.
 && ! readelf -l /out/snailfish-relay | grep -q INTERP \
 # The dependency tree of cargo-auditable is present.
 && readelf -S /out/snailfish-relay | grep -q '\.dep-v0' \
 && mkdir -p /out/data /out/secrets && chmod 0700 /out/secrets

FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931
# --link makes each layer independent of the base layers, so a base image
# update does not change these layers. root owns the binary, so the relay
# process cannot replace it. Numeric IDs let Kubernetes runAsNonRoot verify
# the user.
COPY --link --from=build /out/snailfish-relay /usr/local/bin/snailfish-relay
COPY --link --from=build --chown=65532:65532 /out/data /data
COPY --link --from=build --chown=65532:65532 /out/secrets /secrets
USER 65532:65532
ENV SNAILFISH_DATA=/data SNAILFISH_SECRETS=/secrets SNAILFISH_LISTEN=0.0.0.0:8080
EXPOSE 8080
VOLUME ["/data", "/secrets"]
# distroless has no curl. The relay binary checks its own health route.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/snailfish-relay", "health", "--url", "http://127.0.0.1:8080/v1/health"]
ENTRYPOINT ["/usr/local/bin/snailfish-relay"]
CMD ["serve"]
