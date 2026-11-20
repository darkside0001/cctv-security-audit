from cctv_audit.cve import match_cves, parse_version


def test_parse_version_with_build_string():
    assert parse_version("V5.4.1 build220101") == (5, 4, 1)
    assert parse_version("5.5.800") == (5, 5, 800)
    assert parse_version("garbage") == (0,)


def test_hikvision_old_firmware_confident_hit():
    matches = match_cves("Hikvision", "5.4.0")
    ids = {m.cve.cve_id for m in matches}
    assert "CVE-2017-7921" in ids
    assert "CVE-2021-36260" in ids
    assert all(m.confident for m in matches if m.cve.fixed_in)


def test_hikvision_patched_firmware_no_versioned_hit():
    matches = match_cves("Hikvision", "5.5.900")
    ids = {m.cve.cve_id for m in matches}
    assert "CVE-2021-36260" not in ids  # above fixed version


def test_dahua_version_agnostic_reported_as_unconfident():
    matches = match_cves("Dahua", "")
    assert matches
    assert all(not m.confident for m in matches)


def test_other_vendor_no_matches():
    assert match_cves("Axis", "1.0") == []
