#!/usr/bin/env bash
# Build and test the app on an iOS simulator and on macOS, with no signing.
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
