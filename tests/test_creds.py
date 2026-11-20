from cctv_audit.creds import check_default_credentials
from fake_prober import FakeProber


def test_default_credentials_detected():
    # Anonymous request returns 401 (needs auth), admin:12345 returns 200.
    devices = {
        "192.168.1.64": {
            "ports": {80},
            "auth": {(80, "/System/deviceInfo"): {("admin", "12345"): 200}},
        }
    }
    prober = FakeProber(devices)
    r = check_default_credentials("192.168.1.64", 80, False, "Hikvision", prober)
    assert r.default_in_use
    assert r.accepted == ("admin", "12345")


def test_no_default_accepted():
    devices = {
        "192.168.1.64": {
            "ports": {80},
            "auth": {(80, "/System/deviceInfo"): {}},  # nothing accepted -> 401
        }
    }
    prober = FakeProber(devices)
    r = check_default_credentials("192.168.1.64", 80, False, "Hikvision", prober)
    assert not r.default_in_use
    assert r.attempts > 0
    assert r.tried  # recorded what it tried


def test_stops_at_first_accepted():
    devices = {
        "192.168.1.64": {
            "ports": {80},
            "auth": {(80, "/System/deviceInfo"): {("admin", "admin"): 200,
                                                  ("888888", "888888"): 200}},
        }
    }
    prober = FakeProber(devices)
    r = check_default_credentials("192.168.1.64", 80, False, "Dahua", prober)
    assert r.default_in_use
    # Dahua list starts with admin:admin, so it stops there.
    assert r.accepted == ("admin", "admin")
