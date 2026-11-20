"""Camera / NVR service ports and what their exposure means."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ServiceDef:
    port: int
    name: str
    # Risk if this port is reachable on an untrusted network. "info" means
    # expected/normal, it is only a finding when combined with other issues.
    exposure: str  # info | low | medium | high
    note: str


# Deliberately a small, fixed set of ports relevant to IP cameras and NVRs.
# This is not a general port scanner.
SERVICES: dict[int, ServiceDef] = {
    23: ServiceDef(23, "telnet", "high",
                   "Cleartext remote shell. Should never be open on a camera."),
    554: ServiceDef(554, "rtsp", "info",
                    "Video stream. Normal, but must require authentication."),
    80: ServiceDef(80, "http", "medium",
                   "Web admin over cleartext. Credentials cross the network in the clear."),
    443: ServiceDef(443, "https", "info",
                    "Web admin over TLS. Expected."),
    8000: ServiceDef(8000, "hikvision-sdk", "medium",
                     "Hikvision SDK/ISAPI service port. Should not face untrusted networks."),
    8080: ServiceDef(8080, "http-alt", "medium",
                     "Alternate web admin. Often an unauthenticated secondary interface."),
    8443: ServiceDef(8443, "https-alt", "low", "Alternate TLS web admin."),
    37777: ServiceDef(37777, "dahua-dvrip", "medium",
                      "Dahua DVRIP control port. Should not face untrusted networks."),
    34567: ServiceDef(34567, "dvrip-xmeye", "high",
                      "Generic DVRIP/XMEye port, tied to many botnet-recruited DVRs."),
    5000: ServiceDef(5000, "onvif-alt", "low", "Alternate ONVIF service port."),
}

# Ports probed during discovery to decide "this looks like a camera/NVR".
DISCOVERY_PORTS: tuple[int, ...] = (80, 554, 8000, 37777, 34567, 8080, 443)

# Ports assessed in detail once a host is identified as in scope.
ASSESS_PORTS: tuple[int, ...] = tuple(SERVICES)

# HTTP ports to try fingerprinting / credential checks against, with TLS flag.
WEB_PORTS: tuple[tuple[int, bool], ...] = (
    (80, False),
    (8080, False),
    (8000, False),
    (443, True),
    (8443, True),
)
