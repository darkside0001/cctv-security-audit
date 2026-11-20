import pytest

from cctv_audit.targets import ScopeError, build_scope, parse_hosts, MAX_SWEEP_HOSTS


def test_single_private_host():
    assert parse_hosts("192.168.1.64") == ["192.168.1.64"]


def test_private_cidr_expands():
    hosts = parse_hosts("192.168.1.0/30")
    assert hosts == ["192.168.1.1", "192.168.1.2"]


def test_public_cidr_refused():
    with pytest.raises(ScopeError):
        parse_hosts("8.8.8.0/24")


def test_public_single_host_allowed():
    # A single explicit address is a targeted action and is allowed.
    assert parse_hosts("203.0.113.10") == ["203.0.113.10"]


def test_cgnat_range_allowed():
    assert parse_hosts("100.64.0.1") == ["100.64.0.1"]


def test_oversized_sweep_refused():
    with pytest.raises(ScopeError):
        parse_hosts("10.0.0.0/8")


def test_sweep_cap_boundary():
    # /22 = 1022 usable hosts, under the cap.
    assert len(parse_hosts("10.0.0.0/22")) <= MAX_SWEEP_HOSTS


def test_authorization_required():
    with pytest.raises(ScopeError):
        build_scope(["192.168.1.1"], authorized_by="")


def test_scope_dedups_and_records_auth():
    scope = build_scope(["192.168.1.1", "192.168.1.1"], authorized_by="Razim")
    assert scope.hosts == ["192.168.1.1"]
    assert scope.authorized is True
    assert scope.authorized_by == "Razim"


def test_cred_targets_added_to_scope_and_flagged():
    scope = build_scope(["192.168.1.1"], authorized_by="Razim",
                        cred_targets=["192.168.1.9"])
    assert "192.168.1.9" in scope.hosts
    assert scope.may_check_credentials("192.168.1.9")
    assert not scope.may_check_credentials("192.168.1.1")
