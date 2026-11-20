"""Low-level network probes.

Every socket this tool opens goes through here, so the rest of the code is
pure data handling and the whole thing is trivial to unit-test with a fake
prober. Probes are read-only: a TCP connect, an optional short banner read,
and plain unauthenticated HTTP GETs. Nothing here writes to or changes a
target device.
"""

from __future__ import annotations

import base64
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: str = ""

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


class Prober:
    """Performs the actual network I/O. Swap it out in tests."""

    def __init__(self, timeout: float = 2.0, user_agent: str = "cctv-audit"):
        self.timeout = timeout
        self.user_agent = user_agent

    def tcp_open(self, host: str, port: int) -> bool:
        """Return True if a TCP connection to host:port completes."""
        try:
            with socket.create_connection((host, port), timeout=self.timeout):
                return True
        except OSError:
            return False

    def banner(self, host: str, port: int, probe: bytes = b"") -> str:
        """Open the port, optionally send a probe, read a short banner."""
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as s:
                s.settimeout(self.timeout)
                if probe:
                    s.sendall(probe)
                data = s.recv(512)
            return data.decode("latin-1", "replace").strip()
        except OSError:
            return ""

    def http_get(
        self,
        host: str,
        port: int,
        path: str = "/",
        tls: bool = False,
        auth: tuple[str, str] | None = None,
    ) -> HttpResponse | None:
        """Unauthenticated (or basic-auth) GET. Returns None if unreachable."""
        scheme = "https" if tls else "http"
        url = f"{scheme}://{host}:{port}{path}"
        req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
        if auth is not None:
            token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
            req.add_header("Authorization", f"Basic {token}")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # cameras ship self-signed certs
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as r:
                raw = r.read(4096)
                headers = {k.lower(): v for k, v in r.headers.items()}
                return HttpResponse(r.status, headers, raw.decode("latin-1", "replace"))
        except urllib.error.HTTPError as e:
            headers = {k.lower(): v for k, v in (e.headers or {}).items()}
            return HttpResponse(e.code, headers)
        except (urllib.error.URLError, OSError, ValueError):
            return None
