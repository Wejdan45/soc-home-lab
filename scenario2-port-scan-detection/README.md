# Scenario 2 — Port Scan Detection & Custom Kibana Detection Rule

## Overview

This investigation documents the design, deployment, and validation of a custom Elastic Security detection rule that identifies network reconnaissance (port scanning) activity by correlating Windows Firewall packet-drop events. Unlike Scenario 1, where evidence was gathered through manual Kibana Discover queries, this scenario builds a fully automated detection pipeline: a **Threshold Rule** that runs on a schedule and generates real, actionable alerts in Kibana Security — the way a production SOC detection actually operates.

---

## Alert Information

| Field | Value |
|---|---|
| Alert Name | Potential SYN-Based Port Scan Detected |
| Rule Type | Threshold Rule |
| Detection Field | `event.code: "5152"` (Windows Filtering Platform Packet Drop) |
| Group By | `source.ip` |
| Threshold | 5 events |
| Severity | Low |
| Risk Score | 21 |
| Source IP | 10.0.2.6 (Kali attacker) |
| Destination IP | 10.0.2.15 (Windows victim) |

---

## Attack Description

Two separate SYN-based TCP port scans were launched from the Kali Linux attacker machine against the Windows 10 victim endpoint using Nmap, on different dates within the same lab session:

```bash
sudo nmap -sS -T4 10.0.2.15
sudo nmap -sS -p 1-1000 -T4 10.0.2.15
```

Both scans generated large volumes of inbound TCP SYN packets to closed or filtered ports. Windows Defender Firewall silently dropped these packets and — because Windows Filtering Platform auditing had been explicitly enabled beforehand — logged each drop as a Security Event ID 5152.

### Enabling firewall auditing (prerequisite)

By default, Windows does not log packet-drop events. This was enabled manually on the victim host:

```powershell
auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
```

---

## What I Found in the Logs

### Raw evidence — Windows Filtering Platform packet drop (Event ID 5152)

A representative event from the second scan confirms the attack signature directly:

```json
event.code: "5152"
event.action: "windows-firewall-packet-drop"
event.outcome: "failure"
winlog.event_data.Direction: "Inbound"
source.ip: "10.0.2.6"
source.port: 44476
destination.ip: "10.0.2.15"
destination.port: 418
network.transport: "tcp"
message: "The Windows Filtering Platform has blocked a packet...
           Direction: Inbound
           Source Address: 10.0.2.6
           Source Port: 44476
           Destination Address: 10.0.2.15
           Destination Port: 418"
```

Each scan produced thousands of these events — one per probed port — as Kali's SYN packets hit closed/filtered ports on the Windows host and were rejected by the firewall.

### Detection query used to isolate scan traffic

Early in this investigation, the raw `event.code: "5152"` query returned tens of thousands of events, most of which were **normal background traffic between Elasticsearch (10.0.2.4:9200) and the Windows Agent** rather than actual attacker activity — the two hosts routinely exchange TCP connections as part of Fleet's own telemetry shipping, and some of those connections were also being dropped and logged. Filtering to the Kali host specifically eliminated this noise entirely:

```
event.code: "5152" and winlog.channel: "Security" and source.ip: "10.0.2.6"
```

### Evidence — Alert generated (Scan 1)

```
kibana.alert.reason: "event with source 10.0.2.6 created low alert
                       Potential SYN-Based Port Scan Detected."
kibana.alert.threshold_result.count: 3996
kibana.alert.threshold_result.terms.value: "10.0.2.6"
kibana.alert.risk_score: 21
```

### Evidence — Alert generated (Scan 2, independent confirmation)

```
kibana.alert.reason: "event with source 10.0.2.6 created low alert
                       Potential SYN-Based Port Scan Detected."
kibana.alert.threshold_result.count: 3567
kibana.alert.threshold_result.terms.value: "10.0.2.6"
kibana.alert.risk_score: 21
```

Two independent scans, run on different occasions, both triggered the same rule with a consistent alert reason and comparable event volume (3,996 and 3,567 packet-drop events respectively) — strong evidence that the detection is reliable and repeatable, not a one-off coincidence.

---

## True Positive or False Positive

**Classification: True Positive (TP)**

### Why?

Both alerts correctly attributed thousands of inbound, denied TCP connection attempts to a single external source (`10.0.2.6`) within a short time window — the exact signature of a port scan. The source host is a known attacker machine on the lab network, and the destination and port range match the Nmap commands actually executed. There is no legitimate reason for one host to attempt thousands of distinct TCP connections to another host in seconds.

---

## Indicators of Compromise (IOCs)

| IOC Type | Value |
|---|---|
| Source IP | 10.0.2.6 |
| Destination IP | 10.0.2.15 |
| Tool Used | Nmap (`-sS` SYN scan) |
| Protocol | TCP |
| Detection Event | Windows Security Event ID 5152 |
| Example Dropped Port | 418/tcp |

---

## MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| TA0043 – Reconnaissance | T1595 – Active Scanning |
| TA0007 – Discovery | T1046 – Network Service Discovery |

---

## Actions Taken

- Enabled Windows Filtering Platform auditing on the victim host to generate Event ID 5152.
- Added a Custom Windows Event Log integration in Fleet to collect the `Security` channel.
- Built a Kibana Security **Threshold Rule**, grouped by `source.ip`, with a 5-event threshold over a 5-minute scheduled interval.
- Diagnosed and resolved a "zero alerts" issue by identifying that the majority of raw 5152 events were background Elasticsearch-to-Agent traffic, not attacker activity, and added a `source.ip` filter to isolate genuine scan traffic.
- Validated the rule against two independent Nmap scans, confirming consistent, repeatable alert generation.
- Recommended blocking or closely monitoring the scanning host at the network perimeter.

---

## Lessons Learned

- **Threshold values must match the scale of the test environment.** An initial threshold of 50 was too high for a single lab-scale scan to reliably trigger; lowering it to 5 made the rule sensitive enough to catch realistic single-scan traffic without being effectively unusable.
- **Not every event matching a detection field is malicious.** The same Event ID 5152 used to detect the Nmap scan was also being generated constantly by legitimate infrastructure traffic (Elasticsearch ↔ Elastic Agent). A detection rule is only as good as its ability to separate signal from this kind of operational noise — in this case, scoping to the known attacker's `source.ip` was the fix, but in a real environment this same problem requires understanding what "normal" background traffic looks like before tuning any rule.
- **Repeat testing builds confidence in a detection rule.** A single successful alert could be coincidence; two independent scans triggering the same rule with comparable event counts is meaningful evidence the detection logic is sound.
- **Rule execution history is essential for troubleshooting.** The Execution Results log (showing "Succeeded" with 0 alerts created, run after run) was the key diagnostic tool that revealed the rule was running correctly but simply not matching real attacker traffic — without it, it would have been easy to wrongly assume the rule itself was broken.

---

## Conclusion

A custom Kibana Security Threshold Rule was successfully designed, deployed, and validated to detect Nmap-based port scanning activity via Windows Firewall packet-drop telemetry (Event ID 5152). After resolving an initial detection gap caused by background infrastructure noise and an oversized threshold, the rule reliably generated true-positive alerts across two independent test scans, correctly attributing over 3,500 and 3,900 denied connection attempts respectively to the attacking host. The alerts were automatically mapped to MITRE ATT&CK techniques T1595 (Active Scanning) and T1046 (Network Service Discovery), demonstrating a complete, automated detection engineering workflow — from raw telemetry, to rule logic, to an actionable SOC alert.

---

## Previous in this series
⬅️ [Scenario 1 — Sysmon: Encoded PowerShell & Download Cradle Detection](../scenario1-sysmon-encoded-powershell/README.md)

## Next in this series
➡️ [Scenario 3 — Web Application Attacks (DVWA) & PowerShell Script Block Logging](../scenario3-dvwa-web-attacks/README.md)
