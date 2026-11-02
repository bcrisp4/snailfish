#!/usr/bin/env bash
# Print the UDID of an iPhone simulator on the newest iOS runtime. The runner
# image chooses the simulator models, and Package.swift needs iOS 17 or later.
set -euo pipefail

id=$(xcrun simctl list devices available -j | jq -r '
  .devices | to_entries
  | map(select(.key | test("SimRuntime\\.iOS-(1[7-9]|[2-9][0-9])-")))
  | sort_by(.key | capture("iOS-(?<maj>[0-9]+)-(?<min>[0-9]+)") | [(.maj|tonumber), (.min|tonumber)])
  | last | .value | map(select(.name | startswith("iPhone"))) | .[0].udid // empty')
test -n "$id" && test "$id" != null
echo "$id"
