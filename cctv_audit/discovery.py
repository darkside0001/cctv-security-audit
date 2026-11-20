"""Find camera/NVR-looking hosts inside an authorized scope.

A sweep only touches the small set of camera/NVR ports in services.py and only
runs inside the bounded, non-public ranges that targets.py allows. A host is
"candidate" if any of those ports is open.
"""

from __future__ import annotations

from .probe import Prober
from .services import DISCOVERY_PORTS


def discover(hosts: list[str], prober: Prober) -> list[str]:
    """Return the subset of hosts with at least one camera/NVR port open."""
    found: list[str] = []
    for host in hosts:
        for port in DISCOVERY_PORTS:
            if prober.tcp_open(host, port):
                found.append(host)
                break
    return found
