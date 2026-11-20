"""Generate the example reports from a scripted, offline lab.

This uses the test FakeProber so it needs no real cameras and no network. It
models a small, deliberately-vulnerable home lab (the kind of equipment you
would own) so the example reports show the tool's output. Run from the repo
root:  python samples/demo_lab.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT))

from fake_prober import FakeProber  # noqa: E402

from cctv_audit.audit import audit_host  # noqa: E402
from cctv_audit.report import to_json, to_markdown, to_text  # noqa: E402
from cctv_audit.targets import build_scope  # noqa: E402

LAB = {
    # Old Hikvision cam: telnet open, vulnerable firmware, default password.
    "192.168.1.64": {
        "ports": {23, 80, 554, 8000},
        "http": {(80, "/"): (401, {"server": "App-webs/1.0 (Hikvision V5.4.0)",
                                   "www-authenticate": 'Digest realm="Hikvision"'}, "")},
        "auth": {(80, "/System/deviceInfo"): {("admin", "12345"): 200}},
    },
    # Dahua NVR: control port exposed, firmware unknown.
    "192.168.1.108": {
        "ports": {80, 554, 37777},
        "http": {(80, "/"): (401, {"server": "Boa/0.94.14rc21 webs (Dahua)",
                                   "www-authenticate": 'Basic realm="Login"'}, "")},
        "auth": {(80, "/System/deviceInfo"): {}},
    },
    # Cheap XMEye DVR: the classic botnet-bait port combo.
    "192.168.1.120": {
        "ports": {34567, 554},
        "http": {},
    },
    # A well-configured camera: HTTPS only, no issues.
    "192.168.1.70": {
        "ports": {443, 554},
        "http": {(443, "/"): (401, {"server": "nginx",
                                    "www-authenticate": 'Digest realm="camera"'}, "")},
        "auth": {},
    },
}


def main() -> None:
    hosts = sorted(LAB)
    scope = build_scope(hosts, authorized_by="Razim Kudaybergenov (home lab)",
                        cred_targets=["192.168.1.64"])
    prober = FakeProber(LAB)
    results = [audit_host(h, scope, prober) for h in scope.hosts]

    ex = ROOT / "examples"
    ex.mkdir(exist_ok=True)
    (ex / "report.txt").write_text(to_text(results, scope.authorized_by, color=False))
    (ex / "report.json").write_text(to_json(results, scope.authorized_by) + "\n")
    (ex / "report.md").write_text(to_markdown(results, scope.authorized_by))
    print("wrote examples/report.{txt,json,md}")
    print()
    print(to_text(results, scope.authorized_by, color=False))


if __name__ == "__main__":
    main()
