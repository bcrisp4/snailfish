#!/usr/bin/env bash
# Run a command with a snailfish-relay process on a free local port.
# It sets SNAILFISH_RELAY_URL and SNAILFISH_INVITE (the invite link of the
# user "sam") for the command, and stops the relay at the end. The authority
# is localhost, because the WebAuthn relying party needs a domain name. Run
# it from the repo root.
set -euo pipefail

relay="${SNAILFISH_RELAY_BIN:-target/debug/snailfish-relay}"
data=$(mktemp -d)
log="$data/relay.log"
port=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
args=(--data "$data/relay" --authority "localhost:$port" --origin "http://localhost:$port")
invite=$("$relay" "${args[@]}" user add sam)
"$relay" serve "${args[@]}" --listen "127.0.0.1:$port" 2> "$log" &
pid=$!
stop() { kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; rm -rf "$data"; }
trap stop EXIT
for _ in $(seq 100); do
  if curl -fsS "http://127.0.0.1:$port/v1/health" > /dev/null 2>&1; then break; fi
  sleep 0.05
done
curl -fsS "http://127.0.0.1:$port/v1/health" > /dev/null || { echo "FAIL: the relay did not start"; cat "$log"; exit 1; }
rc=0
SNAILFISH_RELAY_URL="http://localhost:$port" SNAILFISH_INVITE="$invite" "$@" || rc=$?
exit "$rc"
