"""A scripted Prober stand-in so tests never touch the network."""

from __future__ import annotations

from cctv_audit.probe import HttpResponse


class FakeProber:
    """Models one or more fake devices.

    devices maps host -> {
        "ports": set[int],
        "http": {(port, path): HttpResponse or (status, headers, body)},
        "auth": {(port, path): {(user, pwd): status}},   # for cred checks
    }
    Any port/path not described defaults to closed / unreachable.
    """

    def __init__(self, devices: dict):
        self.devices = devices
        self.tcp_calls: list[tuple[str, int]] = []
        self.auth_attempts: list[tuple[str, int, str, str]] = []

    def _dev(self, host: str) -> dict | None:
        return self.devices.get(host)

    def tcp_open(self, host: str, port: int) -> bool:
        self.tcp_calls.append((host, port))
        dev = self._dev(host)
        return bool(dev and port in dev.get("ports", set()))

    def banner(self, host: str, port: int, probe: bytes = b"") -> str:
        dev = self._dev(host)
        if not dev:
            return ""
        return dev.get("banners", {}).get(port, "")

    def http_get(self, host, port, path="/", tls=False, auth=None):
        dev = self._dev(host)
        if not dev:
            return None
        if auth is not None:
            self.auth_attempts.append((host, port, auth[0], auth[1]))
            table = dev.get("auth", {}).get((port, path))
            if table is None:
                return None
            status = table.get((auth[0], auth[1]), 401)
            return HttpResponse(status, {}, "" if status != 200 else "<deviceInfo/>")
        entry = dev.get("http", {}).get((port, path))
        if entry is None:
            # An auth-gated path answers 401 to an anonymous request.
            if (port, path) in dev.get("auth", {}):
                return HttpResponse(401, {})
            return None
        if isinstance(entry, HttpResponse):
            return entry
        status, headers, body = entry
        return HttpResponse(status, {k.lower(): v for k, v in headers.items()}, body)
