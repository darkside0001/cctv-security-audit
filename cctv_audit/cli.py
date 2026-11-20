"""Command line interface: cctv-audit."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .audit import audit_host
from .discovery import discover
from .probe import Prober
from .report import to_json, to_markdown, to_text
from .targets import ScopeError, build_scope

BANNER = (
    "cctv-security-audit is for equipment you OWN or are explicitly AUTHORIZED\n"
    "to assess. Scanning or testing cameras you do not control may be illegal.\n"
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cctv-audit",
        description="Defensive security audit for IP cameras and NVRs you own "
                    "or are authorized to assess.",
        epilog=BANNER,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("targets", nargs="*",
                   help="camera addresses or a private CIDR, e.g. 192.168.1.64 or 192.168.1.0/24")
    p.add_argument("--authorized-by", metavar="WHO", default="",
                   help="your name or engagement reference, confirming you have "
                        "permission to assess these devices (required)")
    p.add_argument("--check-default-creds", action="append", default=[], metavar="HOST",
                   help="also verify this host no longer accepts factory-default "
                        "logins (repeatable; authorized targets only)")
    p.add_argument("--discover", action="store_true",
                   help="first sweep the scope for camera/NVR ports and audit "
                        "only the hosts that respond")
    p.add_argument("-f", "--format", choices=["text", "json", "markdown"], default="text")
    p.add_argument("-o", "--output", help="write the report to a file")
    p.add_argument("--timeout", type=float, default=2.0, help="per-probe timeout (seconds)")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def run(args: argparse.Namespace, prober: Prober | None = None) -> tuple[int, str]:
    """Core logic, separated from argv handling for testing."""
    prober = prober or Prober(timeout=args.timeout)
    try:
        scope = build_scope(
            args.targets,
            authorized_by=args.authorized_by,
            cred_targets=args.check_default_creds,
        )
    except ScopeError as e:
        return 2, f"error: {e}"

    hosts = discover(list(scope.hosts), prober) if args.discover else list(scope.hosts)
    # Credential-check targets are always audited even if discovery skips them.
    for h in scope.cred_check_hosts:
        if h not in hosts:
            hosts.append(h)
    results = [audit_host(h, scope, prober) for h in hosts]

    if args.format == "json":
        report = to_json(results, scope.authorized_by)
    elif args.format == "markdown":
        report = to_markdown(results, scope.authorized_by)
    else:
        report = to_text(results, scope.authorized_by, color=not args.no_color)

    # Exit code reflects worst finding: 0 clean, 1 issues found.
    worst = min((f.severity for r in results for f in r.findings),
                default="info", key=lambda s: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[s])
    code = 1 if worst in ("critical", "high", "medium", "low") else 0
    return code, report


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.targets:
        print(BANNER, file=sys.stderr)
        print("error: no targets given. See --help.", file=sys.stderr)
        return 2
    code, report = run(args)
    if args.output:
        with open(args.output, "w") as fh:
            fh.write(report if report.endswith("\n") else report + "\n")
        print(f"report written to {args.output}", file=sys.stderr)
    else:
        print(report)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
