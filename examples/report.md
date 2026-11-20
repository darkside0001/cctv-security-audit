# CCTV / NVR security audit

- **Authorized by:** Razim Kudaybergenov (home lab)
- **Generated:** 2026-11-20 07:50:59Z
- **Hosts in scope:** 4
- **Findings:** 3 critical, 2 high, 8 medium, 0 low

## 192.168.1.64 — Hikvision, firmware 5.4.0

Open ports: 23, 554, 80, 8000

| Severity | Rule | Finding | Remediation |
|----------|------|---------|-------------|
| CRITICAL | CVE-2017-7921 | Improper authentication: backdoor allowing config/credential disclosure [ref](https://nvd.nist.gov/vuln/detail/CVE-2017-7921) | Update to the vendor's fixed firmware and, until then, remove the device's exposure to untrusted networks. |
| CRITICAL | CVE-2021-36260 | Unauthenticated command injection in the web server [ref](https://nvd.nist.gov/vuln/detail/CVE-2021-36260) | Update to the vendor's fixed firmware and, until then, remove the device's exposure to untrusted networks. |
| CRITICAL | CRED-DEFAULT | Factory-default credentials still accepted | Set a unique strong password now, disable unused accounts, and enable lockout on repeated failures. |
| HIGH | SVC-EXPOSED | telnet reachable on port 23 | Disable the service if unused, or restrict it to a management VLAN / VPN with a firewall rule. Cameras should never expose admin or control ports to an untrusted network. |
| MEDIUM | SVC-ADVISORY | Port 23 advisory | Disable the service/cloud feature and block the port at the firewall. |
| MEDIUM | SVC-EXPOSED | http reachable on port 80 | Disable the service if unused, or restrict it to a management VLAN / VPN with a firewall rule. Cameras should never expose admin or control ports to an untrusted network. |
| MEDIUM | SVC-EXPOSED | hikvision-sdk reachable on port 8000 | Disable the service if unused, or restrict it to a management VLAN / VPN with a firewall rule. Cameras should never expose admin or control ports to an untrusted network. |

## 192.168.1.120 — host

Open ports: 554, 34567

| Severity | Rule | Finding | Remediation |
|----------|------|---------|-------------|
| HIGH | SVC-EXPOSED | dvrip-xmeye reachable on port 34567 | Disable the service if unused, or restrict it to a management VLAN / VPN with a firewall rule. Cameras should never expose admin or control ports to an untrusted network. |
| MEDIUM | SVC-ADVISORY | Port 34567 advisory | Disable the service/cloud feature and block the port at the firewall. |

## 192.168.1.108 — Dahua

Open ports: 554, 80, 37777

| Severity | Rule | Finding | Remediation |
|----------|------|---------|-------------|
| MEDIUM | SVC-EXPOSED | http reachable on port 80 | Disable the service if unused, or restrict it to a management VLAN / VPN with a firewall rule. Cameras should never expose admin or control ports to an untrusted network. |
| MEDIUM | SVC-EXPOSED | dahua-dvrip reachable on port 37777 | Disable the service if unused, or restrict it to a management VLAN / VPN with a firewall rule. Cameras should never expose admin or control ports to an untrusted network. |
| MEDIUM | CVE-2021-33044 | Possibly affected: Authentication bypass via crafted login (ONVIF/NetKeyboard) [ref](https://nvd.nist.gov/vuln/detail/CVE-2021-33044) | Update to the vendor's fixed firmware and, until then, remove the device's exposure to untrusted networks. |
| MEDIUM | CVE-2021-33045 | Possibly affected: Authentication bypass via crafted login packet [ref](https://nvd.nist.gov/vuln/detail/CVE-2021-33045) | Update to the vendor's fixed firmware and, until then, remove the device's exposure to untrusted networks. |

## 192.168.1.70 — host

Open ports: 554, 443

_No issues found._
