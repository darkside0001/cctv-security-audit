"""Turn read-only observations about a host into findings with remediation."""

from __future__ import annotations

from dataclasses import dataclass, field

from .cve import SERVICE_ADVISORIES, match_cves
from .creds import CredResult, check_default_credentials
from .fingerprint import Fingerprint, fingerprint_host
from .probe import Prober
from .services import ASSESS_PORTS, DISCOVERY_PORTS, SERVICES
from .targets import Scope

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    rule: str
    title: str
    severity: str
    detail: str
    remediation: str
    reference: str = ""


@dataclass
class HostResult:
    host: str
    open_ports: list[int] = field(default_factory=list)
    is_camera: bool = False
    fingerprint: Fingerprint = field(default_factory=Fingerprint)
    cred_result: CredResult | None = None
    findings: list[Finding] = field(default_factory=list)

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    @property
    def max_severity(self) -> str:
        if not self.findings:
            return "info"
        return min((f.severity for f in self.findings), key=lambda s: SEVERITY_ORDER[s])


def looks_like_camera(open_ports: list[int]) -> bool:
    camera_ports = {554, 8000, 37777, 34567}
    if camera_ports & set(open_ports):
        return True
    # A bare web server alone is not enough; needs a video/control port too.
    return False


def _assess_ports(host: str, prober: Prober) -> list[int]:
    return [p for p in ASSESS_PORTS if prober.tcp_open(host, p)]


def audit_host(host: str, scope: Scope, prober: Prober) -> HostResult:
    result = HostResult(host=host)
    result.open_ports = _assess_ports(host, prober)
    result.is_camera = looks_like_camera(result.open_ports)

    # --- exposed-service findings ---
    for port in result.open_ports:
        svc = SERVICES.get(port)
        if svc is None or svc.exposure == "info":
            continue
        sev = {"high": "high", "medium": "medium", "low": "low"}[svc.exposure]
        result.add(Finding(
            rule="SVC-EXPOSED",
            title=f"{svc.name} reachable on port {port}",
            severity=sev,
            detail=svc.note,
            remediation=(
                "Disable the service if unused, or restrict it to a management "
                "VLAN / VPN with a firewall rule. Cameras should never expose "
                "admin or control ports to an untrusted network."),
        ))
        adv = SERVICE_ADVISORIES.get(port)
        if adv:
            result.add(Finding(
                rule="SVC-ADVISORY", title=f"Port {port} advisory",
                severity="medium", detail=adv,
                remediation="Disable the service/cloud feature and block the port at the firewall."))

    if not result.is_camera and not result.open_ports:
        return result  # nothing reachable

    # --- fingerprint + CVE matching ---
    result.fingerprint = fingerprint_host(host, prober)
    fp = result.fingerprint
    if fp.server_header and "http" in " ".join(
            SERVICES[p].name for p in result.open_ports if p in SERVICES) + "http":
        # Cleartext admin already covered by SVC-EXPOSED; nothing extra here.
        pass

    if fp.vendor or fp.firmware:
        for m in match_cves(fp.vendor, fp.firmware):
            sev = m.cve.severity if m.confident else "medium"
            prefix = "" if m.confident else "Possibly affected: "
            result.add(Finding(
                rule=m.cve.cve_id,
                title=f"{prefix}{m.cve.title}",
                severity=sev,
                detail=f"{m.cve.note} ({m.reason}).",
                remediation=(
                    "Update to the vendor's fixed firmware and, until then, "
                    "remove the device's exposure to untrusted networks."),
                reference=m.cve.reference,
            ))

    if fp.firmware == "" and result.is_camera:
        result.add(Finding(
            rule="FW-UNKNOWN", title="Firmware version could not be determined",
            severity="info",
            detail="The device did not expose its firmware version to an "
                   "unauthenticated request.",
            remediation="Check the firmware version in the admin UI and compare "
                        "it against the vendor's security advisories."))

    # --- default-credential check (opt-in, authorized only) ---
    if scope.may_check_credentials(host) and fp.web_port is not None:
        cr = check_default_credentials(host, fp.web_port, fp.web_tls, fp.vendor, prober)
        result.cred_result = cr
        if cr.default_in_use:
            user, pwd = cr.accepted
            result.add(Finding(
                rule="CRED-DEFAULT",
                title="Factory-default credentials still accepted",
                severity="critical",
                detail=f"The device accepted the documented default login "
                       f"'{user}:{pwd or '<blank>'}'. Anyone who can reach it can log in.",
                remediation="Set a unique strong password now, disable unused "
                            "accounts, and enable lockout on repeated failures."))
        else:
            result.add(Finding(
                rule="CRED-OK", title="Default credentials not accepted",
                severity="info",
                detail=f"Tried {cr.attempts} documented default(s); none were accepted.",
                remediation="No action. Keep credentials unique per device."))

    return result


def summarize(results: list[HostResult]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for r in results:
        for f in r.findings:
            counts[f.severity] += 1
    return counts
