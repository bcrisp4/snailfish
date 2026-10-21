# Snailfish

Snailfish is a self-hosted sync system for local-first apps. It keeps one person's devices in sync, and the server cannot read the data. The project is at the design stage, and no code exists yet.

## Problem

Local-first apps keep data on each device, so the copies on a laptop and a phone drift apart. Existing sync options either tie you to one vendor or can read your data.

## Approach

- Each device encrypts and signs its changes before upload. The relay stores only ciphertext and never holds a key.
- A small Rust relay runs on a cheap VPS or a home server, with one SQLite file for each user.
- Apps integrate through the Rust sync engine, with Swift and Python bindings.

## Name

Snailfish live deeper than any other fish on record, more than 8,000 m down in ocean trenches. App data sinks ("syncs") to the relay, and it stays in the dark there, because the relay cannot read it.

## Status

See [DESIGN.md](DESIGN.md) for the current draft design.
