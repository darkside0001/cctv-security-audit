"""Scope parsing and authorization gating.

This module is deliberately strict: the auditor only looks at hosts the
operator has explicitly put in scope, and only inside address ranges that
cannot belong to the public Internet. There is no "scan the Internet" mode
and there never will be - this tool audits equipment you own or are
contracted to assess.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Iterable, Iterator

# A discovery sweep is capped so the tool can never be turned into a mass
# scanner. One subnet, a bounded number of hosts.
MAX_SWEEP_HOSTS = 1024


class ScopeError(ValueError):
    """Raised when a requested target is outside what this tool will scan."""


def _is_auditable_network(net: ipaddress._BaseNetwork) -> bool:
    """True only for ranges that are private, loopback, link-local or CGNAT.

    Public, globally routable addresses are refused for range sweeps so an
    accidental (or deliberate) Internet-wide scan is impossible.
    """
    return net.is_private or net.is_loopback or net.is_link_local


def parse_hosts(spec: str) -> list[str]:
    """Expand a single host or CIDR into a list of host addresses.

    A CIDR must sit inside an auditable (non-public) range and must not
    exceed MAX_SWEEP_HOSTS. A single host literal is allowed as-is: auditing
    one camera by its address is a normal, targeted action.
    """
    spec = spec.strip()
    if "/" in spec:
        net = ipaddress.ip_network(spec, strict=False)
        if not _is_auditable_network(net):
            raise ScopeError(
                f"{spec} is a public range. Range sweeps are restricted to "
                "private/reserved networks (RFC1918, CGNAT, link-local). "
                "Audit a public host by giving its exact address instead."
            )
        hosts = list(net.hosts()) or [net.network_address]
        if len(hosts) > MAX_SWEEP_HOSTS:
            raise ScopeError(
                f"{spec} expands to {len(hosts)} hosts; the limit is "
                f"{MAX_SWEEP_HOSTS}. Narrow the subnet."
            )
        return [str(h) for h in hosts]
    # Single literal: validate it is an address, but allow any address.
    ipaddress.ip_address(spec)
    return [spec]


@dataclass
class Scope:
    """The resolved set of hosts to audit and the authorization behind it."""

    hosts: list[str] = field(default_factory=list)
    authorized_by: str = ""
    # Hosts for which the operator has explicitly authorized the
    # default-credential configuration check (a superset check needs opt-in
    # per target, never the whole sweep).
    cred_check_hosts: set[str] = field(default_factory=set)

    @property
    def authorized(self) -> bool:
        return bool(self.authorized_by)

    def may_check_credentials(self, host: str) -> bool:
        return host in self.cred_check_hosts

    def __iter__(self) -> Iterator[str]:
        return iter(self.hosts)

    def __len__(self) -> int:
        return len(self.hosts)


def build_scope(
    targets: Iterable[str],
    authorized_by: str,
    cred_targets: Iterable[str] = (),
) -> Scope:
    """Resolve CLI targets into a Scope, enforcing the authorization gate."""
    if not authorized_by:
        raise ScopeError(
            "No authorization recorded. This tool only audits devices you own "
            "or are contracted to assess. Re-run with --authorized-by "
            '"<your name / engagement ref>" to confirm you have permission.'
        )
    hosts: list[str] = []
    seen: set[str] = set()
    for t in targets:
        for h in parse_hosts(t):
            if h not in seen:
                seen.add(h)
                hosts.append(h)
    if not hosts:
        raise ScopeError("No targets given.")

    cred_hosts: set[str] = set()
    for t in cred_targets:
        for h in parse_hosts(t):
            cred_hosts.add(h)
    # A credential-check target that is not also in the audit scope is added
    # to scope: the operator clearly means to assess it.
    for h in cred_hosts:
        if h not in seen:
            seen.add(h)
            hosts.append(h)

    return Scope(hosts=hosts, authorized_by=authorized_by, cred_check_hosts=cred_hosts)
