"""A small, static knowledge base of well-known IP-camera CVEs.

This is reference data only - published advisories with their fixed-version
information - used to tell an operator "this firmware predates the fix for
CVE-xxxx, update it". It contains no exploit code and performs no exploitation;
matching is a version comparison against vendor-published fix versions.

Keep this list short and curated. It is a prompt to go read the real
advisory, not an exhaustive vulnerability feed.
"""

from __future__ import annotations

from dataclasses import dataclass, field


def parse_version(v: str) -> tuple[int, ...]:
    """Loose dotted-version parse: 'V5.4.1 build220101' -> (5, 4, 1)."""
    nums: list[int] = []
    cur = ""
    for ch in v:
        if ch.isdigit():
            cur += ch
        elif ch == "." and cur:
            nums.append(int(cur))
            cur = ""
        elif cur:
            nums.append(int(cur))
            cur = ""
            break
    if cur:
        nums.append(int(cur))
    return tuple(nums) or (0,)


def _lt(a: str, b: str) -> bool:
    """True if version a is strictly below version b."""
    return parse_version(a) < parse_version(b)


@dataclass(frozen=True)
class CVE:
    cve_id: str
    vendor: str
    title: str
    severity: str  # critical | high | medium
    # Firmware below this (loose) version is affected. Empty = version-agnostic
    # (reported as advisory, not as a definite hit).
    fixed_in: str = ""
    reference: str = ""
    note: str = ""


# Curated, publicly documented advisories for common consumer/SMB gear.
KNOWN_CVES: list[CVE] = [
    CVE(
        "CVE-2017-7921", "Hikvision",
        "Improper authentication: backdoor allowing config/credential disclosure",
        "critical", fixed_in="5.4.5",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2017-7921",
        note="Elevated access to device config without valid credentials on old firmware.",
    ),
    CVE(
        "CVE-2021-36260", "Hikvision",
        "Unauthenticated command injection in the web server",
        "critical", fixed_in="5.5.800",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2021-36260",
        note="Widely exploited. Update firmware and restrict the web interface immediately.",
    ),
    CVE(
        "CVE-2021-33044", "Dahua",
        "Authentication bypass via crafted login (ONVIF/NetKeyboard)",
        "critical", fixed_in="",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2021-33044",
        note="Check the Dahua PSIRT advisory for the fixed build for your exact model.",
    ),
    CVE(
        "CVE-2021-33045", "Dahua",
        "Authentication bypass via crafted login packet",
        "critical", fixed_in="",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2021-33045",
        note="Companion advisory to CVE-2021-33044. Apply the vendor's fixed build.",
    ),
]

# Version-agnostic advisories keyed on an exposed service rather than firmware.
# Reported as context, never as a confirmed vulnerability.
SERVICE_ADVISORIES = {
    34567: "DVRIP/XMEye (port 34567) DVRs are a frequent Mirai/botnet target. "
           "If you do not use the XMEye cloud, disable it and block the port.",
    23: "Telnet on cameras has historically shipped with hard-coded credentials "
        "(e.g. the Mirai default-password list). Disable it.",
}


@dataclass
class CveMatch:
    cve: CVE
    confident: bool  # True = firmware comparison confirms affected range
    reason: str


def match_cves(vendor: str, firmware: str) -> list[CveMatch]:
    """Return advisories relevant to this vendor/firmware."""
    out: list[CveMatch] = []
    vlow = vendor.lower()
    for cve in KNOWN_CVES:
        if cve.vendor.lower() not in vlow and vlow not in cve.vendor.lower():
            continue
        if cve.fixed_in and firmware:
            if _lt(firmware, cve.fixed_in):
                out.append(CveMatch(cve, True,
                    f"firmware {firmware} is below the fixed version {cve.fixed_in}"))
            # firmware at/above fix -> not reported
        else:
            out.append(CveMatch(cve, False,
                "applies to this vendor; confirm your exact model/build against the advisory"))
    return out
