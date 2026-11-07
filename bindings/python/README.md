# snailfish

The Python binding of the Snailfish sync engine. Snailfish syncs end-to-end encrypted app data between the devices of one user through a relay that cannot read it.

Each wheel holds the engine as a native library and its UniFFI module. You need no Rust toolchain.

## Install

```bash
pip install snailfish
```

The wheels are for Python 3.13 or later on macOS arm64, Linux x86_64 and Linux aarch64 (glibc 2.28 or later).

## Documentation

- The protocol: [PROTOCOL.md](https://github.com/bcrisp4/snailfish/blob/main/PROTOCOL.md)
- The design: [DESIGN.md](https://github.com/bcrisp4/snailfish/blob/main/DESIGN.md)
- A complete app that uses this package: [demo](https://github.com/bcrisp4/snailfish/tree/main/demo)

## Licence

MIT or Apache-2.0, at your option.
