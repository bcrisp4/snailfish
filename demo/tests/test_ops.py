"""M9 operations: the metrics listener and the Prometheus rules file
(DESIGN.md "Monitoring and alerting" signals 3 and 5).

The relay runs with `--metrics-listen`. The test scrapes it at a full
quota, writes the samples into a `promtool test rules` case, and checks
that the quota alert of `ops/prometheus/snailfish.rules.yml` fires on the
real samples, and no other alert.
"""

from __future__ import annotations

import http.client
import shutil
import subprocess
from typing import TYPE_CHECKING

import pytest
from conftest import ROOT, Relay, demo, dump, free_port, setup, sync_ok

if TYPE_CHECKING:
    from pathlib import Path

RULES = ROOT / "ops" / "prometheus" / "snailfish.rules.yml"
ALERTS = (
    "SnailfishSpaceAboveQuota",
    "SnailfishSpaceAboveReserve",
    "SnailfishSpaceManyStubs",
    "SnailfishStorageError",
    "SnailfishMigrationFailed",
)

QUOTA_SUMMARY = "A space uses more than 95% of its quota."
QUOTA_DESCRIPTION = (
    "1 spaces on relay use more than 95% of their quota. At the quota, the relay refuses "
    "appends. Find the user in snailfish_tenant_stored_bytes. Raise the quota with "
    "`snailfish-relay quota <user>`, or ask the user to delete data."
)


def scrape(port: int, path: str = "/metrics") -> tuple[int, str]:
    """GET a path of a listener on 127.0.0.1."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", path)
    resp = conn.getresponse()
    body = resp.read().decode()
    conn.close()
    return resp.status, body


def samples(text: str) -> list[tuple[str, str]]:
    """The series and values of a Prometheus text page."""
    out: list[tuple[str, str]] = []
    for line in text.splitlines():
        if line and not line.startswith("#"):
            series, value = line.rsplit(" ", 1)
            out.append((series, value))
    return out


def promtool_case(scraped: list[tuple[str, str]], fired: str) -> str:
    """A promtool test file: each scraped sample as a constant series for
    20 minutes, the alert `fired` firing, and each other alert quiet."""
    lines = [
        f"rule_files:\n  - {RULES}\n",
        "evaluation_interval: 1m\n",
        "tests:\n  - interval: 1m\n    input_series:\n",
    ]
    for series, value in scraped:
        labelled = series if "{" in series else series + "{}"
        name, labels = labelled.split("{", 1)
        labels = labels.rstrip("}")
        full = f'{name}{{instance="relay", {labels}}}' if labels else f'{name}{{instance="relay"}}'
        quoted = full.replace("'", "''")
        lines.append(f"      - series: '{quoted}'\n        values: '{value}x20'\n")
    lines.append("    alert_rule_test:\n")
    for a in ALERTS:
        lines.append(f"      - eval_time: 10m\n        alertname: {a}\n")
        if a == fired:
            lines.append(
                "        exp_alerts:\n          - exp_labels:\n"
                "              severity: warning\n              instance: relay\n"
                "            exp_annotations:\n"
                f"              summary: {QUOTA_SUMMARY}\n"
                f'              description: "{QUOTA_DESCRIPTION}"\n'
            )
        else:
            lines.append("        exp_alerts: []\n")
    return "".join(lines)


def test_full_quota_fires_the_quota_alert(tmp_path: Path) -> None:
    """Signals 3 and 5: at a full quota, the metrics listener reports the
    space above 95% of its quota, and the rules file fires
    `SnailfishSpaceAboveQuota` on those samples. The public port does not
    serve the metrics."""
    promtool = shutil.which("promtool")
    if promtool is None:
        pytest.fail("promtool is missing: run mise install and the tests through mise exec")
    mport = free_port()
    relay = Relay(tmp_path / "relay", serve_args=["--metrics-listen", f"127.0.0.1:{mport}"])
    try:
        a, b = tmp_path / "a", tmp_path / "b"
        setup(relay, a, b)
        assert demo(a, "edit", "t1", "title", "first").returncode == 0
        sync_ok(a)
        status, page = scrape(mport)
        assert status == 200
        assert 'snailfish_spaces_above_quota{ratio="0.95"} 0' in page
        assert relay.admin("quota", "sam", "--space-bytes", "1").returncode == 0
        assert demo(a, "edit", "t2", "title", "second").returncode == 0
        r = demo(a, "sync")
        assert "QUOTA" in r.stdout.upper(), r.stdout
        assert dump(a)["engine_outbox"] == 1
        status, page = scrape(mport)
        assert status == 200
        assert 'snailfish_spaces_above_quota{ratio="0.95"} 1' in page
        assert relay.port != mport
        assert scrape(relay.port)[0] == 404
        case = tmp_path / "quota.test.yml"
        case.write_text(promtool_case(samples(page), "SnailfishSpaceAboveQuota"))
        r2 = subprocess.run(
            [promtool, "test", "rules", str(case)],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        assert r2.returncode == 0, r2.stdout + r2.stderr
    finally:
        relay.stop()
