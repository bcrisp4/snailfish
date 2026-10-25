#!/usr/bin/env bash
# Build the UniFFI bindings. Run it through `make bindings-python` or
# `make bindings-swift`, from the repo root.
#
# python: the generated module and the host cdylib in bindings/python/build/.
# swift:  the generated Swift sources and Snailfish.xcframework (iOS device,
#         iOS simulator, macOS) in bindings/swift/build/.
#
# Each step writes to a staging directory. The script moves the results into
# the package only after every step succeeds, so a failed build leaves the
# last good package in place.
set -euo pipefail

cd "$(dirname "$0")/../.."
CARGO="mise exec -- cargo"
# cargo can put its output outside ./target (CARGO_TARGET_DIR or
# build.target-dir), so ask cargo where it is.
TARGET_DIR=$($CARGO metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
BINDGEN="$TARGET_DIR/debug/uniffi-bindgen"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

$CARGO build -p snailfish-uniffi-bindgen
host_lib() {
  $CARGO build -p snailfish-bindings --lib
  case "$(uname -s)" in
    Darwin) echo "$TARGET_DIR/debug/libsnailfish.dylib" ;;
    *) echo "$TARGET_DIR/debug/libsnailfish.so" ;;
  esac
}

case "${1:-}" in
  python)
    lib=$(host_lib)
    $BINDGEN generate --library "$lib" --language python --out-dir "$STAGE"
    cp "$lib" "$STAGE/"
    rm -rf bindings/python/build
    mv "$STAGE" bindings/python/build
    trap - EXIT
    ;;
  swift)
    # xcodebuild needs the full Xcode, not the command line tools.
    export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
    lib=$(host_lib)
    gen="$STAGE/generated"
    mkdir -p "$gen/headers"
    $BINDGEN generate --library "$lib" --language swift --out-dir "$gen"
    # SwiftPM finds the module map only at the top of the Headers directory
    # of each XCFramework slice.
    mv "$gen/snailfishFFI.h" "$gen/headers/"
    cp "$gen/snailfishFFI.modulemap" "$gen/headers/module.modulemap"
    args=()
    for t in aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin; do
      $CARGO build -p snailfish-bindings --lib --release --target "$t"
      args+=(-library "$TARGET_DIR/$t/release/libsnailfish.a" -headers "$gen/headers")
    done
    xcodebuild -create-xcframework "${args[@]}" -output "$STAGE/Snailfish.xcframework"
    # Every step succeeded. Replace the package outputs together. SwiftPM
    # test resources must sit inside the package.
    pkg=bindings/swift
    mkdir -p "$pkg/build" "$pkg/Sources/Snailfish"
    rm -rf "$pkg/build/Snailfish.xcframework" "$pkg/Tests/SnailfishTests/vectors"
    mv "$STAGE/Snailfish.xcframework" "$pkg/build/"
    cp "$gen/snailfish.swift" "$pkg/Sources/Snailfish/Snailfish.swift"
    cp -R vectors "$pkg/Tests/SnailfishTests/vectors"
    ;;
  *)
    echo "usage: $0 python|swift" >&2
    exit 2
    ;;
esac
