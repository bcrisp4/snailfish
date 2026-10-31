#!/bin/bash
# The guest side of the power-loss test. systemd starts it at each boot.
#
# The data disk holds the relay, devices A and B, and a boot counter. At each
# boot the script starts the relay, syncs both devices until they agree, and
# prints the state. Then it edits and syncs in a loop until the host kills
# the VM. The markers go to the virtio-serial port sf.markers, and a copy goes
# to the console for the log. The host reads only the port, because kernel
# and systemd output on the console can split a line:
#
#   SF-BOOT n            the boot number
#   SF-STATE json        the state after the check syncs
#   SF-FAIL text         a check failed
#   SF-EDIT id           an edit returned: the app database holds it
#   SF-PUSH / SF-PUSHED  a sync of the device that made the last edit
#   SF-PULL / SF-PULLED  a sync of the other device
set -u
root=/mnt/sf
state=$root/state
export PYTHONPATH=$root/payload/python:$root/payload/demo:$root/payload/site
relay=$root/payload/snailfish-relay
port=/dev/virtio-ports/sf.markers
for _ in $(seq 100); do [ -e "$port" ] && break; sleep 0.1; done
[ -e "$port" ] || { echo "SF-FAIL no marker port"; sleep 3600; exit 1; }
# One write of one complete line, so the port never holds a part of a line.
mark() { printf '%s\n' "$*" > "$port"; echo "$*"; }
fail() { mark "SF-FAIL $*"; sleep 3600; exit 1; }
demo() { python3 -m snailfish_demo.cli --dir "$state/$1" "${@:2}"; }

boot=$(( $(cat "$state/boot" 2>/dev/null || echo 0) + 1 ))
echo "$boot" > "$state/boot.tmp" && sync "$state/boot.tmp" && mv "$state/boot.tmp" "$state/boot" && sync "$state"
mark "SF-BOOT $boot"

"$relay" --data "$state/relay" serve --listen 127.0.0.1:8080 --authority 127.0.0.1:8080 &
for _ in $(seq 100); do "$relay" health --url http://127.0.0.1:8080/v1/health 2>/dev/null && break; sleep 0.1; done
"$relay" health --url http://127.0.0.1:8080/v1/health || fail "the relay did not start"

if [ ! -e "$state/setup-done" ]; then
  # The host kills only after SF-WORK, so the setup completes once.
  tenant=$("$relay" --data "$state/relay" user add sam) || fail "user add"
  python3 -m snailfish_demo.cli setup --relay http://127.0.0.1:8080 --tenant "$tenant" "$state/a" "$state/b" > /dev/null || fail "setup"
  sync
  touch "$state/setup-done" && sync "$state"
fi

# The check: sync until both devices are ok and agree, then print the state.
out=$(python3 "$root/payload/check.py" "$state/a" "$state/b") || { mark "$out"; fail "check"; }
mark "$out"

mark "SF-WORK"
i=0
while true; do
  i=$((i + 1))
  if [ $((i % 2)) -eq 1 ]; then editor=a; other=b; else editor=b; other=a; fi
  id="e$boot-$i"
  demo "$editor" edit "$id" title "v$i" > /dev/null || fail "edit $id"
  mark "SF-EDIT $id"
  mark "SF-PUSH"
  demo "$editor" sync > /dev/null || fail "sync $editor"
  mark "SF-PUSHED"
  mark "SF-PULL"
  demo "$other" sync > /dev/null || fail "sync $other"
  mark "SF-PULLED"
done
