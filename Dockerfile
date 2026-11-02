# The relay container image (DESIGN.md "Relay deployment").
#
# The build stage makes a static musl binary for the target architecture,
# with a vendored OpenSSL for the passkey sign-in (webauthn-rs). The runtime image is distroless/static: no shell and no libc. Build it
# for one architecture with `docker build --platform linux/amd64 .` or
# `linux/arm64`. Each architecture builds natively under its own platform.
#
# Run: docker run -e SNAILFISH_AUTHORITY=sync.example.net -v data:/data -v secrets:/secrets -p 8080:8080 IMAGE
# The secrets volume holds session.key. Backups do not copy it ([STO-9]).

FROM rust:1.99.1-alpine3.22 AS build
# The vendored OpenSSL build needs a C compiler, perl and make.
RUN apk add --no-cache musl-dev perl make linux-headers
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates crates
RUN cargo build --locked --release -p snailfish-relay \
 && cp target/release/snailfish-relay /snailfish-relay \
 # A static binary has no dynamic loader entry.
 && ! readelf -l /snailfish-relay | grep -q INTERP \
 && mkdir -p /data /secrets && chmod 0700 /secrets

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /snailfish-relay /usr/local/bin/snailfish-relay
COPY --from=build --chown=nonroot:nonroot /data /data
COPY --from=build --chown=nonroot:nonroot /secrets /secrets
USER nonroot:nonroot
ENV SNAILFISH_DATA=/data SNAILFISH_SECRETS=/secrets SNAILFISH_LISTEN=0.0.0.0:8080
EXPOSE 8080
VOLUME ["/data", "/secrets"]
# distroless has no curl. The relay binary checks its own health route.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/snailfish-relay", "health", "--url", "http://127.0.0.1:8080/v1/health"]
ENTRYPOINT ["/usr/local/bin/snailfish-relay"]
CMD ["serve"]
