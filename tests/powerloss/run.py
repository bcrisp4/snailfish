#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = []
# ///
"""The M2 power-loss test (DESIGN.md M2, M2 decision 3).

The test boots a Debian 13 cloud image under QEMU. The guest runs the relay
and the Python demo client from a second disk (`guest.sh`). The host kills
QEMU with SIGKILL during a push or a pull, boots again, and reads the state
that the guest prints after it syncs both devices.

The guest writes its markers to a virtio-serial port, which QEMU writes to a
file on the host. The serial console also carries kernel and systemd output,
which can split a marker line, so the host reads only the port file.

The disks use `cache=none`, so the guest's flushes reach the host file
before QEMU acknowledges them, and a SIGKILL drops only unflushed data. This
covers Linux fsync in the guest. It does not cover Apple F_FULLFSYNC.

Checks after each boot:
1. Each edit that returned before the kill (`SF-EDIT`) is on both devices.
   The app database commits each edit durably before the CLI returns.
2. No device handled a change twice.
3. Both outboxes are empty, and both devices report `ok`.

Usage: run.py [--arch arm64|amd64] [--kills N] [--work DIR]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import random
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
BUILD = "20261021-2638"
BASE = f"https://cloud.debian.org/images/cloud/trixie/{BUILD}"
IMAGES = {
    "arm64": (
        f"debian-13-genericcloud-arm64-{BUILD}.qcow2",
        "e66eea33be9e1345e6c8737e65096e5b31031f4bd4f3f7d59a6f8b53f995a9c4"
        "1996e97c5b4ab89f1587663efed11dfbd10c4d35b7bcc85b2545e58a12cd0e83",
    ),
    "amd64": (
        f"debian-13-genericcloud-amd64-{BUILD}.qcow2",
        "16e0965312c56feb331049d45d2b1b5778f3f942a33d4300eedbb97527707f2b"
        "ea87c0006f3e4cc7a25fadbff739c4e235a51fb9bcd1b66fd554f7f8e80ba45c",
    ),
}
CACHE = Path(os.environ.get("SNAILFISH_QEMU_CACHE", Path.home() / ".cache" / "snailfish-qemu"))
BOOT_TIMEOUT = 300


def log(msg: str) -> None:
    """Print a progress line."""
    print(f"[powerloss] {msg}", flush=True)


def base_image(arch: str) -> Path:
    """Return the cloud image, downloaded once and checked by SHA-512."""
    name, want = IMAGES[arch]
    CACHE.mkdir(parents=True, exist_ok=True)
    path = CACHE / name
    if not path.exists():
        log(f"download {name}")
        tmp = path.with_suffix(".part")
        subprocess.run(["curl", "-fsSL", "-o", str(tmp), f"{BASE}/{name}"], check=True)
        tmp.rename(path)
    h = hashlib.sha512()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    if h.hexdigest() != want:
        path.unlink()
        sys.exit(f"FAIL: {name} has the wrong SHA-512")
    return path


def data_image(arch: str, work: Path) -> Path:
    """Build the data disk with the payload, in a Linux container."""
    log(f"build the payload for linux/{arch}")
    out = work / "data.img"
    subprocess.run(
        [
            "docker", "build", "--platform", f"linux/{arch}",
            "-f", str(HERE / "Dockerfile.payload"), "--target", "image",
            "-t", f"snailfish-powerloss:{arch}", str(ROOT),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    cid = subprocess.run(
        ["docker", "create", "--platform", f"linux/{arch}", f"snailfish-powerloss:{arch}"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    try:
        subprocess.run(["docker", "cp", f"{cid}:/data.img", str(out)], check=True)
    finally:
        subprocess.run(["docker", "rm", cid], check=True, stdout=subprocess.DEVNULL)
    return out


def seed_image(work: Path) -> Path:
    """Build the cloud-init seed: mount the data disk and run the guest
    script as a systemd service at each boot."""
    seed = work / "seed"
    seed.mkdir()
    (seed / "meta-data").write_text("instance-id: snailfish-powerloss\nlocal-hostname: sf\n")
    # The VM has no network. Without this, boot waits 120 s for one.
    (seed / "network-config").write_text("network:\n  version: 2\n  ethernets: {}\n")
    (seed / "user-data").write_text(
        """#cloud-config
mounts:
  - [ "LABEL=sfdata", "/mnt/sf", "ext4", "defaults,nofail", "0", "2" ]
write_files:
  - path: /etc/systemd/system/snailfish.service
    content: |
      [Unit]
      After=mnt-sf.mount
      Requires=mnt-sf.mount
      [Service]
      ExecStart=/mnt/sf/payload/guest.sh
      StandardOutput=journal+console
      StandardError=journal+console
      [Install]
      WantedBy=multi-user.target
bootcmd:
  - [ systemctl, mask, --now, systemd-networkd-wait-online.service ]
runcmd:
  - [ systemctl, daemon-reload ]
  - [ systemctl, enable, --now, snailfish.service ]
"""
    )
    iso = work / "seed.iso"
    if shutil.which("hdiutil"):
        subprocess.run(
            ["hdiutil", "makehybrid", "-quiet", "-o", str(iso), str(seed),
             "-iso", "-joliet", "-default-volume-name", "cidata"],
            check=True,
        )
    else:
        tool = shutil.which("genisoimage") or shutil.which("mkisofs")
        if tool is None:
            sys.exit("FAIL: no genisoimage, mkisofs or hdiutil")
        subprocess.run(
            [tool, "-quiet", "-output", str(iso), "-volid", "cidata", "-joliet", "-rock", str(seed)],
            check=True,
        )
    return iso


def qemu_cmd(arch: str, work: Path, disk: Path, data: Path, seed: Path) -> list[str]:
    """Return the QEMU command. Both writable disks use cache=none."""
    drives = [
        "-drive", f"file={disk},if=virtio,format=qcow2,cache=none,aio=threads",
        "-drive", f"file={data},if=virtio,format=raw,cache=none,aio=threads",
        "-drive", f"file={seed},if=virtio,format=raw,readonly=on",
    ]
    common = ["-m", "1024", "-smp", "2", "-nographic", "-no-reboot", "-nic", "none", *drives]
    native = platform.machine() in (("arm64", "aarch64") if arch == "arm64" else ("x86_64", "amd64"))
    if arch == "arm64":
        fw = Path(os.environ.get("SNAILFISH_QEMU_EFI", "/opt/homebrew/share/qemu/edk2-aarch64-code.fd"))
        if not fw.exists():
            fw = Path("/usr/share/qemu-efi-aarch64/QEMU_EFI.fd")
        vars_ = work / "efivars.fd"
        if not vars_.exists():
            with vars_.open("wb") as f:
                f.truncate(64 << 20)
        accel = ("hvf" if sys.platform == "darwin" else "kvm") if native else "tcg"
        return [
            "qemu-system-aarch64", "-machine", "virt", "-accel", accel,
            "-cpu", "host" if native else "max",
            "-drive", f"if=pflash,format=raw,readonly=on,file={fw}",
            "-drive", f"if=pflash,format=raw,file={vars_}",
            *common,
        ]
    accel = ("hvf" if sys.platform == "darwin" else "kvm") if native else "tcg"
    return [
        "qemu-system-x86_64", "-machine", "q35", "-accel", accel,
        "-cpu", "host" if native else "max", *common,
    ]


class Boot:
    """One boot of the VM. The console goes to a log file. The markers come
    from a virtio-serial port that QEMU writes to a file of its own."""

    def __init__(self, cmd: list[str], logfile: Path, markers: Path) -> None:
        """Start QEMU with the marker port on `markers`."""
        self.logf = logfile.open("ab")
        markers.unlink(missing_ok=True)
        self.markers_path = markers
        port = [
            "-chardev", f"file,id=sfm,path={markers}",
            "-device", "virtio-serial-pci",
            "-device", "virtserialport,chardev=sfm,name=sf.markers",
        ]
        self.proc = subprocess.Popen(
            cmd + port, stdin=subprocess.DEVNULL, stdout=self.logf, stderr=self.logf
        )
        self.buf = b""
        self.pos = 0
        self.lines: list[str] = []

    def _read(self) -> list[str]:
        """Return the complete marker lines written since the last read."""
        try:
            with self.markers_path.open("rb") as f:
                f.seek(self.pos)
                data = f.read()
        except FileNotFoundError:
            return []
        self.pos += len(data)
        self.buf += data
        *done, self.buf = self.buf.split(b"\n")
        return [x.decode(errors="replace").strip() for x in done if x.strip()]

    def wait_for(self, pred: str | tuple[str, ...], timeout: float) -> str:
        """Read marker lines until one starts with `pred`. Fail on SF-FAIL."""
        prefixes = (pred,) if isinstance(pred, str) else pred
        deadline = time.monotonic() + timeout
        pending: list[str] = []
        while time.monotonic() < deadline:
            if not pending:
                pending = self._read()
                if not pending:
                    if self.proc.poll() is not None:
                        sys.exit(f"FAIL: QEMU exited with {self.proc.returncode}; see {self.logf.name}")
                    time.sleep(0.05)
                    continue
            line = pending.pop(0)
            self.lines.append(line)
            if line.startswith("SF-FAIL"):
                self.kill()
                sys.exit(f"FAIL: guest: {line}")
            if line.startswith(prefixes):
                # Lines after the match stay unread for the next call.
                self.buf = b"".join(x.encode() + b"\n" for x in pending) + self.buf
                return line
        self.kill()
        sys.exit(f"FAIL: timeout waiting for {prefixes}; see {self.logf.name}")

    def kill(self) -> list[str]:
        """SIGKILL QEMU: a power loss for the guest.

        Returns:
            The marker lines that the guest wrote before the kill and that the
            host did not read yet.
        """
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGKILL)
        self.proc.wait()
        rest = self._read()
        # A line without its newline is a write that the kill cut. Its edit
        # did not return to the caller before the kill, so it is not counted.
        if not self.logf.closed:
            self.logf.close()
        return rest

    def poweroff(self) -> None:
        """Stop the VM at the end of the test."""
        self.kill()


def check_state(line: str, edits: list[str]) -> dict[str, object]:
    """Check one SF-STATE line against the edits that returned."""
    try:
        s = json.loads(line.removeprefix("SF-STATE "))
    except json.JSONDecodeError as e:
        sys.exit(f"FAIL: the guest state line is not JSON ({e}): {line[:200]}")
    tasks = set(s["tasks"])
    missing = [e for e in edits if e not in tasks]
    if missing:
        sys.exit(f"FAIL: lost changes: {missing[:10]}")
    if s["handled"] != s["unique"]:
        sys.exit(f"FAIL: a change was applied twice: {s}")
    if s["handled"][0] != len(tasks) or s["handled"][1] != len(tasks):
        sys.exit(f"FAIL: handled counts differ from the tasks: {s}")
    if s["engine_outbox"] != [0, 0]:
        sys.exit(f"FAIL: engine outbox not empty: {s}")
    if any(st != "Status.OK()" for st in s["status"]):
        sys.exit(f"FAIL: status: {s['status']}")
    return s


def main() -> int:
    """Run the test."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--arch", default="arm64" if platform.machine() in ("arm64", "aarch64") else "amd64")
    ap.add_argument("--kills", type=int, default=20)
    ap.add_argument("--work", type=Path)
    ap.add_argument("--seed", type=int, default=int(time.time()))
    args = ap.parse_args()
    rng = random.Random(args.seed)
    log(f"arch {args.arch}, {args.kills} kills, seed {args.seed}")
    work = args.work or Path(tempfile.mkdtemp(prefix="snailfish-powerloss-"))
    work.mkdir(parents=True, exist_ok=True)
    base = base_image(args.arch)
    disk = work / "root.qcow2"
    subprocess.run(
        ["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", str(base), str(disk), "8G"],
        check=True,
    )
    data = data_image(args.arch, work)
    seed = seed_image(work)
    cmd = qemu_cmd(args.arch, work, disk, data, seed)
    log("qemu: " + " ".join(cmd))
    consolelog = work / "console.log"

    edits: list[str] = []
    kinds = {"push": 0, "pull": 0}
    states = 0
    for k in range(args.kills + 1):
        t0 = time.monotonic()
        boot = Boot(cmd, consolelog, work / f"markers-{k}.log")
        b = boot.wait_for("SF-BOOT", BOOT_TIMEOUT)
        t1 = time.monotonic()
        line = boot.wait_for("SF-STATE", BOOT_TIMEOUT)
        s = check_state(line, edits)
        states += 1
        log(
            f"{b}: {len(s['tasks'])} tasks on both devices, all {len(edits)} returned edits "
            f"present, none applied twice (boot {t1 - t0:.0f} s, check {time.monotonic() - t1:.0f} s)"
        )
        if k == args.kills:
            boot.poweroff()
            break
        boot.wait_for("SF-WORK", 60)
        kind = rng.choice(("push", "pull"))
        # Kill during the Nth push or pull of this boot, after a short delay
        # inside it, so the kill lands in a different step each time.
        n = rng.randint(1, 4)
        seen = 0
        while True:
            line = boot.wait_for(("SF-EDIT", "SF-PUSH", "SF-PULL"), 120)
            if line.startswith("SF-EDIT"):
                edits.append(line.split()[1])
                continue
            if line == f"SF-{kind.upper()}":
                seen += 1
                if seen == n:
                    time.sleep(rng.uniform(0.0, 1.5))
                    rest = boot.kill()
                    edits += [x.split()[1] for x in rest if x.startswith("SF-EDIT ")]
                    kinds[kind] += 1
                    log(f"SIGKILL during {kind} {n}, {len(edits)} edits so far")
                    break
    log(f"PASS: {args.kills} kills ({kinds['push']} during push, {kinds['pull']} during pull), "
        f"{states} checks, {len(edits)} edits, none lost, none applied twice")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
