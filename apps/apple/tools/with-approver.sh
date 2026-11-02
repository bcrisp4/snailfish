#!/usr/bin/env bash
# Run a command with the sign-in approver of apps/apple/tools/approver.py.
# Run it inside bindings/scripts/with-relay.sh, from the repo root. It sets
# TEST_RUNNER_SNAILFISH_RELAY_URL and TEST_RUNNER_SNAILFISH_APPROVER, which
# xcodebuild passes to the tests without the TEST_RUNNER_ prefix.
set -euo pipefail

: "${SNAILFISH_RELAY_URL:?run inside bindings/scripts/with-relay.sh}"
: "${SNAILFISH_INVITE:?run inside bindings/scripts/with-relay.sh}"
tmp=$(mktemp -d)
log="$tmp/approver.log"
(cd demo && exec mise exec -- uv run --locked python ../apps/apple/tools/approver.py \
  "$SNAILFISH_RELAY_URL" "$SNAILFISH_INVITE" sam "$tmp/port") 2> "$log" &
pid=$!
stop() { kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; rm -rf "$tmp"; }
trap stop EXIT
for _ in $(seq 200); do
  [ -s "$tmp/port" ] && break
  kill -0 "$pid" 2>/dev/null || break
  sleep 0.05
done
[ -s "$tmp/port" ] || { echo "FAIL: the approver did not start"; cat "$log"; exit 1; }
export TEST_RUNNER_SNAILFISH_RELAY_URL="$SNAILFISH_RELAY_URL"
export TEST_RUNNER_SNAILFISH_APPROVER="http://127.0.0.1:$(cat "$tmp/port")"
rc=0
"$@" || rc=$?
[ "$rc" -eq 0 ] || { echo "approver log:"; cat "$log"; }
exit "$rc"
