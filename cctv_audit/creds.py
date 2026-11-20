"""Default-credential configuration check (authorized targets only).

The single purpose here is hardening verification: confirming that a camera
you own or are contracted to assess is **no longer** accepting the
factory-default login. It tries a short list of each vendor's publicly
documented factory defaults against a device's own authentication endpoint and
reports whether any still work, so you can change them.

Guardrails, by design:
  * runs only against hosts the operator listed with --check-default-creds;
  * uses a small, vendor-documented default list - it is not a password
    cracker and loads no external wordlists;
  * makes one attempt per credential, stops at the first that is accepted,
    and records exactly what was tried;
  * is skipped entirely unless authorization was recorded for the run.

Finding a default still works means "change this password now", not access to
exploit. Do not point this at devices you are not authorized to assess.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .probe import Prober

# Publicly documented factory defaults, by vendor. Short on purpose.
DEFAULT_CREDS: dict[str, list[tuple[str, str]]] = {
    "Hikvision": [("admin", "12345"), ("admin", "admin12345")],
    "Dahua": [("admin", "admin"), ("888888", "888888"), ("666666", "666666")],
    "Axis": [("root", "pass"), ("root", "root")],
    "Foscam": [("admin", "")],
    "Reolink": [("admin", "")],
    "D-Link": [("admin", ""), ("admin", "admin")],
    "Uniview": [("admin", "123456")],
    "Generic": [("admin", "admin"), ("admin", ""), ("admin", "1234"),
                ("root", "root"), ("guest", "guest")],
}

# Unauthenticated-looking endpoints that still require valid creds; a 200 here
# with a default credential means the default is live.
_AUTH_PATHS = ("/System/deviceInfo", "/ISAPI/System/deviceInfo", "/axis-cgi/param.cgi", "/")


@dataclass
class CredResult:
    host: str
    web_port: int
    tls: bool
    attempts: int = 0
    accepted: tuple[str, str] | None = None  # (user, password) that worked
    tried: list[str] = field(default_factory=list)

    @property
    def default_in_use(self) -> bool:
        return self.accepted is not None


def _candidate_creds(vendor: str) -> list[tuple[str, str]]:
    creds: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for source in (DEFAULT_CREDS.get(vendor, []), DEFAULT_CREDS["Generic"]):
        for c in source:
            if c not in seen:
                seen.add(c)
                creds.append(c)
    return creds


def check_default_credentials(
    host: str,
    web_port: int,
    tls: bool,
    vendor: str,
    prober: Prober,
) -> CredResult:
    """Try documented defaults against one host. Caller must have verified
    authorization and per-host opt-in before calling this."""
    result = CredResult(host=host, web_port=web_port, tls=tls)
    for user, pwd in _candidate_creds(vendor):
        result.attempts += 1
        result.tried.append(f"{user}:{pwd or '<blank>'}")
        for path in _AUTH_PATHS:
            # Baseline: does this path even require auth? If it answers 200
            # with no credentials, it is not an auth check - skip it.
            anon = prober.http_get(host, web_port, path, tls=tls)
            if anon is None:
                continue
            if anon.status == 200:
                break  # endpoint is not credential-gated; try the next path
            if anon.status in (401, 403):
                authed = prober.http_get(host, web_port, path, tls=tls, auth=(user, pwd))
                if authed is not None and authed.status == 200:
                    result.accepted = (user, pwd)
                    return result
        if result.accepted:
            return result
    return result
