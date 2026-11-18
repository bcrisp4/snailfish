# Changelog

This file lists the changes in each release of Snailfish. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a minor version can change the protocol or a format.

A tag `v<version>` makes a GitHub release with the notes of its section. The Python package uses its own `py-v<version>` tags (see [docs/release.md](docs/release.md)).

## [Unreleased]

### Added

- The relay image on `ghcr.io/bcrisp4/snailfish-relay` for each push to `main`, each release and each release candidate. Each image has a cosign signature, a build provenance attestation and an SBOM.

### Changed

- The relay image runs as the numeric user `65532:65532` on distroless Debian 13, with a smaller LTO build of the binary.

## [0.1.0] - 2026-11-08

The first release. The protocol and the formats can change before 1.0.

### Added

- The protocol in `PROTOCOL.md`, with shared test vectors for Rust, Go, Python and Swift.
- The relay: encrypted append and fetch, one SQLite file for each app of each user, backup and restore, and a container image.
- Log integrity: client checks of the space log, fork detection, rollback repair and the restore hold.
- Device authority: grants, the recovery key, and enrollment through a QR code and a code match.
- Passkey sign-in, invite links, tenant isolation, the user page, quotas and user webhooks.
- The SwiftUI sample app for macOS and iOS, with the Keychain key store.
- Device removal with key rotation, recovery key replacement, full recovery onto a new device, and protocol levels.
- Log compaction with snapshots.
- Space export and import, fork repair, a metrics endpoint, Prometheus alert rules and self-host docs.
- The `snailfish` Python package, version 0.1.0 on PyPI.
