"""Identify a device's vendor, model and firmware from read-only HTTP data.

All signals come from unauthenticated responses a camera hands to any client:
the ``Server`` header, the WWW-Authenticate realm, the login page title and,
where a device exposes it, the ONVIF/ISAPI device-information endpoint. No
credentials are used here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .probe import Prober
from .services import WEB_PORTS


@dataclass
class Fingerprint:
    vendor: str = ""
    model: str = ""
    firmware: str = ""
    web_port: int | None = None
    web_tls: bool = False
    server_header: str = ""
    realm: str = ""

    @property
    def identified(self) -> bool:
        return bool(self.vendor or self.model or self.firmware)


_VENDOR_HINTS = (
    ("hikvision", "Hikvision"),
    ("dvrdvs", "Hikvision"),          # Hikvision's embedded server string
    ("app-webs", "Hikvision"),
    ("dahua", "Dahua"),
    ("webs", "Dahua"),
    ("axis", "Axis"),
    ("reolink", "Reolink"),
    ("dlink", "D-Link"),
    ("d-link", "D-Link"),
    ("foscam", "Foscam"),
    ("uniview", "Uniview"),
    ("hipcam", "Generic/HiSilicon"),
)

_FW_RE = re.compile(r"(?:V|v|version[ :]?)(\d+\.\d+(?:\.\d+){0,2})")


def _vendor_from(*texts: str) -> str:
    blob = " ".join(t.lower() for t in texts if t)
    for needle, vendor in _VENDOR_HINTS:
        if needle in blob:
            return vendor
    return ""


def _parse_isapi_device_info(body: str) -> tuple[str, str, str]:
    """Pull model/firmware from Hikvision ISAPI or ONVIF-style XML/JSON."""

    def tag(name: str) -> str:
        m = re.search(rf"<{name}>([^<]+)</{name}>", body, re.I)
        return m.group(1).strip() if m else ""

    model = tag("model") or tag("Model") or tag("deviceType")
    firmware = tag("firmwareVersion") or tag("FirmwareVersion") or tag("firmware")
    vendor = tag("manufacturer") or tag("Manufacturer")
    return vendor, model, firmware


def fingerprint_host(host: str, prober: Prober) -> Fingerprint:
    fp = Fingerprint()
    for port, tls in WEB_PORTS:
        resp = prober.http_get(host, port, "/", tls=tls)
        if resp is None:
            continue
        fp.web_port, fp.web_tls = port, tls
        fp.server_header = resp.header("server")
        fp.realm = resp.header("www-authenticate")
        vendor = _vendor_from(fp.server_header, fp.realm, resp.body)
        if vendor:
            fp.vendor = vendor
        m = _FW_RE.search(fp.server_header) or _FW_RE.search(resp.body)
        if m:
            fp.firmware = m.group(1)

        # Try the unauthenticated device-info endpoints some cameras leak.
        for path in ("/System/deviceInfo", "/onvif/device_service", "/cgi-bin/magicBox.cgi?action=getSystemInfo"):
            info = prober.http_get(host, port, path, tls=tls)
            if info and info.status == 200 and info.body:
                v, model, fw = _parse_isapi_device_info(info.body)
                fp.vendor = fp.vendor or _vendor_from(v) or v
                fp.model = fp.model or model
                fp.firmware = fp.firmware or fw
        if fp.identified:
            break
    return fp
