"""The guest check of the power-loss test.

Sync devices A and B until both report `ok` and hold the same tasks, then
print `SF-STATE` with the task IDs and the counts that the host checks.
Exit 1 if the devices do not agree after 6 rounds.
"""

from __future__ import annotations

import json
import subprocess
import sys


def demo(device: str, *args: str) -> subprocess.CompletedProcess[str]:
    """Run the demo CLI for one device."""
    return subprocess.run(
        [sys.executable, "-m", "snailfish_demo.cli", "--dir", device, *args],
        capture_output=True,
        text=True,
        check=False,
    )


def main() -> int:
    """Sync until the devices agree, then print the state."""
    a, b = sys.argv[1], sys.argv[2]
    last: dict[str, object] = {}
    for _ in range(6):
        codes = [demo(d, "sync").returncode for d in (a, b, a)]
        da = json.loads(demo(a, "dump").stdout)
        db = json.loads(demo(b, "dump").stdout)
        last = {"a": da, "b": db, "codes": codes}
        if codes == [0, 0, 0] and da["tasks"] == db["tasks"] and da["outbox"] == db["outbox"] == []:
            out = {
                "tasks": sorted(da["tasks"]),
                "handled": [len(da["handled"]), len(db["handled"])],
                "unique": [len(set(da["handled"])), len(set(db["handled"]))],
                "engine_outbox": [da["engine_outbox"], db["engine_outbox"]],
                "status": [da["status"], db["status"]],
            }
            print("SF-STATE " + json.dumps(out, sort_keys=True), flush=True)
            return 0
    print("SF-FAIL the devices do not agree: " + json.dumps(last)[:2000], flush=True)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
