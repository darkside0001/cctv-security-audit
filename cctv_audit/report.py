"""Render audit results as text, JSON or Markdown."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .audit import HostResult, SEVERITY_ORDER, summarize

_SEV_LABEL = {
    "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
    "low": "LOW", "info": "INFO",
}
_COLORS = {
    "critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m",
    "low": "\033[36m", "info": "\033[2m",
}
_RESET = "\033[0m"


def _sorted_findings(r: HostResult):
    return sorted(r.findings, key=lambda f: SEVERITY_ORDER[f.severity])


def to_text(results: list[HostResult], authorized_by: str, color: bool = True) -> str:
    def c(sev: str, s: str) -> str:
        return f"{_COLORS[sev]}{s}{_RESET}" if color else s

    out: list[str] = []
    out.append("CCTV / NVR security audit")
    out.append(f"Authorized by: {authorized_by}")
    out.append(f"Generated:     {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')}")
    counts = summarize(results)
    audited = [r for r in results if r.open_ports]
    out.append(
        f"Hosts in scope: {len(results)}  |  responding: {len(audited)}  |  "
        f"cameras/NVRs: {sum(1 for r in results if r.is_camera)}")
    out.append(
        "Findings: " + "  ".join(
            f"{_SEV_LABEL[s]} {counts[s]}" for s in ("critical", "high", "medium", "low")))
    out.append("")

    for r in sorted(results, key=lambda x: SEVERITY_ORDER[x.max_severity]):
        if not r.open_ports:
            continue
        ident = r.fingerprint
        label = " ".join(x for x in (ident.vendor, ident.model) if x) or ("camera/NVR" if r.is_camera else "host")
        fw = f" fw {ident.firmware}" if ident.firmware else ""
        ports = ", ".join(str(p) for p in r.open_ports) or "none"
        out.append(f"{r.host}  [{label}{fw}]")
        out.append(f"    open ports: {ports}")
        for f in _sorted_findings(r):
            if f.severity == "info":
                continue
            out.append(f"    {c(f.severity, '[' + _SEV_LABEL[f.severity] + ']')} {f.rule}  {f.title}")
            out.append(f"        {f.detail}")
            out.append(f"        fix: {f.remediation}")
            if f.reference:
                out.append(f"        ref: {f.reference}")
        out.append("")

    if not audited:
        out.append("No hosts responded on camera/NVR ports.")
    return "\n".join(out).rstrip() + "\n"


def to_json(results: list[HostResult], authorized_by: str) -> str:
    payload = {
        "tool": "cctv-security-audit",
        "generated": datetime.now(timezone.utc).isoformat(),
        "authorized_by": authorized_by,
        "summary": summarize(results),
        "hosts": [
            {
                "host": r.host,
                "is_camera": r.is_camera,
                "open_ports": r.open_ports,
                "vendor": r.fingerprint.vendor,
                "model": r.fingerprint.model,
                "firmware": r.fingerprint.firmware,
                "findings": [
                    {
                        "rule": f.rule, "title": f.title, "severity": f.severity,
                        "detail": f.detail, "remediation": f.remediation,
                        "reference": f.reference,
                    }
                    for f in _sorted_findings(r)
                ],
            }
            for r in results if r.open_ports
        ],
    }
    return json.dumps(payload, indent=2)


def to_markdown(results: list[HostResult], authorized_by: str) -> str:
    counts = summarize(results)
    lines = ["# CCTV / NVR security audit", ""]
    lines.append(f"- **Authorized by:** {authorized_by}")
    lines.append(f"- **Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')}")
    lines.append(f"- **Hosts in scope:** {len(results)}")
    lines.append(
        f"- **Findings:** {counts['critical']} critical, {counts['high']} high, "
        f"{counts['medium']} medium, {counts['low']} low")
    lines.append("")
    for r in sorted(results, key=lambda x: SEVERITY_ORDER[x.max_severity]):
        if not r.open_ports:
            continue
        ident = r.fingerprint
        label = " ".join(x for x in (ident.vendor, ident.model) if x) or "host"
        fw = f", firmware {ident.firmware}" if ident.firmware else ""
        lines.append(f"## {r.host} — {label}{fw}")
        lines.append("")
        lines.append(f"Open ports: {', '.join(str(p) for p in r.open_ports) or 'none'}")
        lines.append("")
        real = [f for f in _sorted_findings(r) if f.severity != "info"]
        if not real:
            lines.append("_No issues found._")
            lines.append("")
            continue
        lines.append("| Severity | Rule | Finding | Remediation |")
        lines.append("|----------|------|---------|-------------|")
        for f in real:
            ref = f" [ref]({f.reference})" if f.reference else ""
            lines.append(
                f"| {_SEV_LABEL[f.severity]} | {f.rule} | {f.title}{ref} | {f.remediation} |")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
