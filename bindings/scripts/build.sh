#!/usr/bin/env bash
# Build the UniFFI bindings. Run it through `make bindings-python` or
# `make bindings-swift`, from the repo root.
#
# python: the generated module and the host cdylib in bindings/python/build/.
# swift:  the generated Swift sources and Snailfish.xcframework (iOS device,
#         iOS simulator, macOS) in bindings/swift/build/.
set -euo pipefail

cd "$(dirname "$0")/../.."
CARGO="mise exec -- cargo"
BINDGEN=target/debug/uniffi-bindgen

$CARGO build -p snailfish-uniffi-bindgen
host_lib() {
  $CARGO build -p snailfish-bindings --lib
  case "$(uname -s)" in
    Darwin) echo target/debug/libsnailfish.dylib ;;
    *) echo target/debug/libsnailfish.so ;;
  esac
}

case "${1:-}" in
  python)
    lib=$(host_lib)
    out=bindings/python/build
    rm -rf "$out" && mkdir -p "$out"
    $BINDGEN generate --library "$lib" --language python --out-dir "$out"
    cp "$lib" "$out/"
    ;;
  swift)
    # xcodebuild needs the full Xcode, not the command line tools.
    export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
    lib=$(host_lib)
    out=bindings/swift/build
    gen="$out/generated"
    rm -rf "$out" && mkdir -p "$gen/headers" bindings/swift/Sources/Snailfish
    $BINDGEN generate --library "$lib" --language swift --out-dir "$gen"
    # SwiftPM finds the module map only at the top of the Headers directory
    # of each XCFramework slice.
    mv "$gen/snailfishFFI.h" "$gen/headers/"
    cp "$gen/snailfishFFI.modulemap" "$gen/headers/module.modulemap"
    cp "$gen/snailfish.swift" bindings/swift/Sources/Snailfish/Snailfish.swift
    targets=(aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin)
    args=()
    for t in "${targets[@]}"; do
      $CARGO build -p snailfish-bindings --lib --release --target "$t"
      args+=(-library "target/$t/release/libsnailfish.a" -headers "$gen/headers")
    done
    xcodebuild -create-xcframework "${args[@]}" -output "$out/Snailfish.xcframework"
    # SwiftPM test resources must sit inside the package.
    rm -rf bindings/swift/Tests/SnailfishTests/vectors
    cp -R vectors bindings/swift/Tests/SnailfishTests/vectors
    ;;
  *)
    echo "usage: $0 python|swift" >&2
    exit 2
    ;;
esac
