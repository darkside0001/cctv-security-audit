# cctv-security-audit

![tests](https://github.com/darkside0001/cctv-security-audit/actions/workflows/tests.yml/badge.svg)

A defensive auditor for IP cameras and NVRs **you own or are contracted to
assess**. It looks at the equipment the way a careful installer would during a
hardening pass: which services are exposed, what the firmware is and whether it
is behind a known advisory, and — only when you explicitly ask — whether a
device still accepts its factory-default password.

Everything it does is read-only. It opens TCP ports, reads banners and
unauthenticated HTTP responses, and compares what it finds against a small,
curated list of published advisories and vendor defaults. It does **not**
exploit anything, change any device setting, or scan the Internet.

Pure Python standard library, no dependencies.

> ⚠️ **Authorization is required.** This tool is for cameras and recorders you
> own or have written permission to test. Scanning or logging into devices you
> do not control may be illegal. The tool will not run without an
> `--authorized-by` statement, and the default-credential check is off unless
> you name each target.

```
$ cctv-audit 192.168.1.0/24 --discover --authorized-by "Razim (home lab)"
CCTV / NVR security audit
Authorized by: Razim (home lab)
Hosts in scope: 254  |  responding: 3  |  cameras/NVRs: 3
Findings: CRITICAL 2  HIGH 2  MEDIUM 8  LOW 0

192.168.1.64  [Hikvision fw 5.4.0]
    open ports: 23, 554, 80, 8000
    [CRITICAL] CVE-2021-36260  Unauthenticated command injection in the web server
        Widely exploited. Update firmware and restrict the web interface immediately.
        fix: Update to the vendor's fixed firmware and, until then, remove the
             device's exposure to untrusted networks.
    [HIGH] SVC-EXPOSED  telnet reachable on port 23
        Cleartext remote shell. Should never be open on a camera.
    ...
```

Full output for the bundled demo lab: [text](examples/report.txt),
[JSON](examples/report.json), [Markdown](examples/report.md).

## What it checks

| Check | Rule(s) | What it means |
|-------|---------|---------------|
| Exposed services | `SVC-EXPOSED` | Telnet, cleartext HTTP admin, vendor control ports (Hikvision 8000, Dahua 37777, DVRIP/XMEye 34567) reachable on the network. |
| Known-bad ports | `SVC-ADVISORY` | Ports tied to well-documented botnet recruitment (telnet, XMEye/DVRIP). |
| Firmware vs advisories | `CVE-xxxx` | Vendor/firmware read from unauthenticated responses, matched against a curated advisory list (e.g. Hikvision CVE-2021-36260, CVE-2017-7921; Dahua CVE-2021-33044/33045). A firmware comparison marks a confident hit; otherwise it is flagged as "possibly affected" for you to confirm. |
| Default credentials | `CRED-DEFAULT` | **Opt-in per host.** Confirms the device no longer accepts its documented factory login, so you can change it if it does. |

Every finding comes with a severity and a concrete remediation step. The exit
code is `1` when any issue is found, `0` when the responding hosts are clean —
handy for a cron job on your own network.

## Scope and safety by design

- **Authorization gate.** No audit runs without `--authorized-by`.
- **No Internet scanning.** A CIDR sweep is only allowed inside private /
  reserved ranges (RFC1918, CGNAT, link-local) and is capped at 1024 hosts. To
  audit a public host you must give its exact address, one at a time.
- **Default-credential check is explicit and minimal.** It runs only against
  hosts you pass with `--check-default-creds`, tries a short list of
  vendor-documented defaults (no external wordlists), makes one attempt per
  credential, stops at the first that works, and records exactly what it tried.
  Its only purpose is to tell you "this still accepts the factory password —
  change it".
- **Read-only.** The tool never writes to or reconfigures a device.

## Install

```
git clone https://github.com/darkside0001/cctv-security-audit
cd cctv-security-audit
pip install -e .
```

## Usage

```
# Audit specific cameras you own
cctv-audit 192.168.1.64 192.168.1.108 --authorized-by "Jane Doe, SOW-2026-14"

# Sweep your camera VLAN, auditing only hosts that answer on camera ports
cctv-audit 10.20.0.0/24 --discover --authorized-by "home lab"

# Also verify two cameras no longer use their default password
cctv-audit 192.168.1.0/24 --discover \
    --check-default-creds 192.168.1.64 \
    --check-default-creds 192.168.1.65 \
    --authorized-by "home lab"

# JSON or Markdown output, written to a file
cctv-audit 192.168.1.64 --authorized-by me -f json -o audit.json
cctv-audit 192.168.1.64 --authorized-by me -f markdown -o audit.md
```

Key options:

| Option | Meaning |
|--------|---------|
| `--authorized-by WHO` | Required. Your name or engagement reference. |
| `--discover` | Sweep the scope first, audit only responding hosts. |
| `--check-default-creds HOST` | Opt in a host to the default-credential check (repeatable). |
| `-f {text,json,markdown}` | Output format. |
| `-o FILE` | Write the report to a file. |
| `--timeout SECONDS` | Per-probe timeout (default 2.0). |

## How the advisory list works

`cctv_audit/cve.py` holds a short, curated set of published advisories with
their fixed-version information. It is a prompt to go read the real advisory for
your exact model, not an exhaustive vulnerability feed. When a device exposes
its firmware version, the tool compares it against the fixed version; when it
does not, the advisory is reported as "possibly affected" so you can check the
build yourself. Keeping the list small and honest is the point.

## Development

```
pip install -e .[dev]
PYTHONPATH=tests pytest -q
```

All network I/O goes through a single `Prober` class, so the test suite drives
the whole tool against a scripted fake device and never touches the network.
`python samples/demo_lab.py` regenerates the example reports from that same
offline lab.

## License

MIT — see [LICENSE](LICENSE).
