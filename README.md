# SOC Home Lab

A growing collection of hands-on SOC detection engineering scenarios, built on a self-hosted Elastic Stack SIEM running across isolated VirtualBox virtual machines (Ubuntu Server, Windows 10, Kali Linux).

Each scenario documents a specific detection use case end-to-end: environment setup, attack simulation, log analysis, and (where applicable) custom Kibana detection rules — written in the style of a real SOC analyst investigation report.

![Status](https://img.shields.io/badge/status-active-success)
![Elastic Stack](https://img.shields.io/badge/Elastic%20Stack-9.4.4-blue)
![Platform](https://img.shields.io/badge/platform-VirtualBox-orange)

---

## Lab Environment

| Component | Details |
|---|---|
| Hypervisor | Oracle VirtualBox |
| SIEM Server | Ubuntu Server, Elasticsearch 9.4.4, Kibana 9.4.4, Fleet Server |
| Endpoint | Windows 10 Pro, Elastic Agent 9.4.4, Sysmon (SwiftOnSecurity config) |
| Web App | DVWA on XAMPP (Apache, MySQL, PHP 7.4), hosted on the monitored Windows endpoint |
| Attacker | Kali Linux 2024.1 |
| Network | VirtualBox NAT Network (isolated internal segment, `10.0.2.0/24`) |

---

## Scenarios

| # | Scenario | Focus | Status |
|---|---|---|---|
| 1 | [Sysmon: Encoded PowerShell & Download Cradle Detection](scenario1-sysmon-encoded-powershell/README.md) | Endpoint telemetry, obfuscated PowerShell, fileless execution artifacts, MITRE ATT&CK mapping | ✅ Complete |
| 2 | [Port Scan Detection & Custom Kibana Detection Rule](scenario2-port-scan-detection/README.md) | Windows Firewall (Event ID 5152), Kibana Security Threshold rule, automated alert generation, noise filtering | ✅ Complete |
| 3 | [Web Application Attacks (DVWA) & PowerShell Script Block Logging](scenario3-dvwa-web-attacks/README.md) | DVWA/XAMPP setup, Apache log collection, SQL Injection, Reflected XSS, Command Injection, Script Block Logging (Event 4104) | ✅ Complete |

More scenarios will be added here as the lab expands. Planned next: Active Directory, DNS, and network firewall integration for a more enterprise-realistic environment.

---

## Author

Built as a hands-on learning project in SOC fundamentals, log pipeline engineering, and endpoint/network/web detection with the Elastic Stack.

📍 Riyadh, Saudi Arabia · [LinkedIn](https://www.linkedin.com/in/wejdan-alhajeri12/) · [wejdanalhajeri99@gmail.com](mailto:wejdanalhajeri99@gmail.com)
