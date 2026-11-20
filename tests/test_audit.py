from cctv_audit.audit import audit_host, looks_like_camera, summarize
from cctv_audit.probe import HttpResponse
from cctv_audit.targets import build_scope
from fake_prober import FakeProber


def test_looks_like_camera():
    assert looks_like_camera([554])
    assert looks_like_camera([80, 8000])
    assert not looks_like_camera([80])  # web alone is not enough
    assert not looks_like_camera([])


def _hikvision_device(ports, firmware="5.4.0", default_cred=None):
    server = f"App-webs/1.0 (Hikvision V{firmware})"
    http = {
        (80, "/"): (401, {"server": server,
                          "www-authenticate": 'Digest realm="Hikvision"'}, ""),
    }
    auth = {}
    if default_cred is not None:
        auth = {(80, "/System/deviceInfo"): {default_cred: 200}}
    else:
        auth = {(80, "/System/deviceInfo"): {}}
    return {
        "ports": set(ports),
        "http": http,
        "auth": auth,
    }


def test_exposed_telnet_is_high():
    devices = {"192.168.1.64": _hikvision_device([23, 80, 554])}
    scope = build_scope(["192.168.1.64"], authorized_by="Razim")
    prober = FakeProber(devices)
    r = audit_host("192.168.1.64", scope, prober)
    assert r.is_camera
    rules = {f.rule for f in r.findings}
    assert "SVC-EXPOSED" in rules
    telnet = [f for f in r.findings if f.rule == "SVC-EXPOSED" and "telnet" in f.title]
    assert telnet and telnet[0].severity == "high"


def test_firmware_cve_matched():
    devices = {"192.168.1.64": _hikvision_device([80, 554], firmware="5.4.0")}
    scope = build_scope(["192.168.1.64"], authorized_by="Razim")
    r = audit_host("192.168.1.64", scope, FakeProber(devices))
    ids = {f.rule for f in r.findings}
    assert "CVE-2021-36260" in ids
    cve = [f for f in r.findings if f.rule == "CVE-2021-36260"][0]
    assert cve.severity == "critical"
    assert cve.reference


def test_default_creds_flagged_only_when_opted_in():
    devices = {"192.168.1.64": _hikvision_device([80, 554], default_cred=("admin", "12345"))}
    # Without opt-in: no credential check happens.
    scope = build_scope(["192.168.1.64"], authorized_by="Razim")
    r = audit_host("192.168.1.64", scope, FakeProber(devices))
    assert all(f.rule != "CRED-DEFAULT" for f in r.findings)
    assert r.cred_result is None

    # With opt-in: default credential detected, critical.
    scope2 = build_scope(["192.168.1.64"], authorized_by="Razim",
                         cred_targets=["192.168.1.64"])
    r2 = audit_host("192.168.1.64", scope2, FakeProber(devices))
    cred = [f for f in r2.findings if f.rule == "CRED-DEFAULT"]
    assert cred and cred[0].severity == "critical"


def test_unreachable_host_no_findings():
    scope = build_scope(["192.168.1.200"], authorized_by="Razim")
    r = audit_host("192.168.1.200", scope, FakeProber({}))
    assert r.open_ports == []
    assert r.findings == []


def test_summarize_counts():
    devices = {"192.168.1.64": _hikvision_device([23, 80, 554])}
    scope = build_scope(["192.168.1.64"], authorized_by="Razim")
    r = audit_host("192.168.1.64", scope, FakeProber(devices))
    counts = summarize([r])
    assert counts["high"] >= 1
