import json

from cctv_audit.cli import build_parser, run
from fake_prober import FakeProber


def _args(argv):
    return build_parser().parse_args(argv)


def _hik():
    return {
        "192.168.1.64": {
            "ports": {23, 80, 554},
            "http": {(80, "/"): (401, {"server": "App-webs/1.0 (Hikvision V5.4.0)",
                                       "www-authenticate": 'Digest realm="Hikvision"'}, "")},
            "auth": {(80, "/System/deviceInfo"): {}},
        }
    }


def test_requires_authorization():
    code, report = run(_args(["192.168.1.64"]), FakeProber(_hik()))
    assert code == 2
    assert "authorization" in report.lower()


def test_public_cidr_rejected():
    code, report = run(_args(["8.8.8.0/24", "--authorized-by", "Razim"]), FakeProber({}))
    assert code == 2
    assert "public" in report.lower()


def test_text_report_flags_issues():
    code, report = run(
        _args(["192.168.1.64", "--authorized-by", "Razim", "--no-color"]),
        FakeProber(_hik()))
    assert code == 1
    assert "telnet" in report
    assert "CVE-2021-36260" in report
    assert "Razim" in report


def test_json_report_shape():
    code, report = run(
        _args(["192.168.1.64", "--authorized-by", "Razim", "-f", "json"]),
        FakeProber(_hik()))
    data = json.loads(report)
    assert data["tool"] == "cctv-security-audit"
    assert data["authorized_by"] == "Razim"
    assert data["hosts"][0]["vendor"] == "Hikvision"
    assert data["summary"]["high"] >= 1


def test_markdown_report():
    code, report = run(
        _args(["192.168.1.64", "--authorized-by", "Razim", "-f", "markdown"]),
        FakeProber(_hik()))
    assert report.startswith("# CCTV")
    assert "| Severity |" in report


def test_clean_host_exit_zero():
    devices = {"192.168.1.70": {"ports": {443}, "http": {}, "auth": {}}}
    code, report = run(
        _args(["192.168.1.70", "--authorized-by", "Razim", "--no-color"]),
        FakeProber(devices))
    assert code == 0
