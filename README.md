# Snailfish

Snailfish is a self-hosted sync system for local-first apps. It keeps one person's devices in sync, and the server cannot read the data. The project is at milestone M1: the protocol crate and the verification toolchain.

## Problem

Local-first apps keep data on each device, so the copies on a laptop and a phone drift apart. Existing sync options either tie you to one vendor or can read your data.

## Approach

- Each device encrypts and signs its changes before upload. The relay stores only ciphertext and never holds a key.
- A small Rust relay runs on a cheap VPS or a home server. It keeps one SQLite file for each app of each user, and `snailfish-relay backup` copies all of them.
- Apps integrate through the Rust sync engine, with Swift and Python bindings.

## Name

Snailfish live deeper than any other fish on record, more than 8,000 m down in ocean trenches. App data sinks ("syncs") to the relay, and it stays in the dark there, because the relay cannot read it.

## Status

See [DESIGN.md](DESIGN.md) for the design and [PROTOCOL.md](PROTOCOL.md) for the exact bytes.

## Develop

1. Install [mise](https://mise.jdx.dev) and [rustup](https://rustup.rs).
2. Run `mise install` in the repo root. It installs every dev tool at its pinned version.
3. Run `make check` before each commit.
4. Read [AGENTS.md](AGENTS.md) for the full verification workflow.

## Licence

MIT OR Apache-2.0, at your option. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
