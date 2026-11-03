#!/usr/bin/env bash
# Build and test the app on an iOS simulator and on macOS, with no signing,
# then check that a Release build has no UI test seam.
# Run it through `make test-app`, inside with-relay.sh and with-approver.sh.
# Usage: test.sh IOS_DESTINATION DERIVED_DATA_DIR
set -euo pipefail

dest_ios=$1
dd=$2
# Command line settings win over the xcconfig files, so the gate builds with
# no team and no entitlements, also if Config/Local.xcconfig exists.
unsigned=(CODE_SIGN_STYLE=Manual CODE_SIGN_IDENTITY=- DEVELOPMENT_TEAM= CODE_SIGN_ENTITLEMENTS=)
cd apps/apple
for dest in "$dest_ios" "platform=macOS,arch=arm64"; do
  xcodebuild test -project Tasks.xcodeproj -scheme Tasks -destination "$dest" \
    -derivedDataPath "$dd" "${unsigned[@]}"
done

# Tasks/UITestSeam.swift replaces the passkey and the camera, so only Debug
# builds may contain it. Its environment variable names are in the binary.
# The Debug build must show them, or the check finds nothing.
# The Rust library of bindings/swift has arm64 only, and a Release build
# builds every architecture by default.
xcodebuild build -project Tasks.xcodeproj -scheme Tasks -configuration Release \
  -destination "platform=macOS,arch=arm64" -derivedDataPath "$dd" "${unsigned[@]}" ARCHS=arm64
grep -rqa SNAILFISH_UITEST_APPROVER "$dd/Build/Products/Debug/Tasks.app" \
  || { echo "FAIL: the Debug build has no UI test seam, so the Release check finds nothing"; exit 1; }
if grep -rqa SNAILFISH_UITEST "$dd/Build/Products/Release/Tasks.app"; then
  echo "FAIL: the Release build contains the UI test seam"
  exit 1
fi
echo "ok: the Release build has no UI test seam"
