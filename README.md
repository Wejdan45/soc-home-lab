# Scenario 3 — Web Application Attacks (DVWA) & PowerShell Script Block Logging

## Overview

This scenario extends the SOC Home Lab in two directions:

1. **Endpoint telemetry upgrade** — enabling PowerShell Script Block Logging (Event ID 4104) to defeat command obfuscation techniques that plain process-creation logging cannot fully reveal.
2. **Web application attack surface** — standing up DVWA (Damn Vulnerable Web Application) on the monitored Windows endpoint via XAMPP, then simulating and detecting three OWASP Top 10 web attacks through Apache access log analysis in Kibana.

Everything below — every download, every command, every configuration change — was performed in the order shown, with the exact commands used.

---

## Part A — PowerShell Script Block Logging (Event ID 4104)

### Why this matters

Simulation 2 in [Scenario 1](../scenario1-sysmon-encoded-powershell/README.md) showed that Base64-encoded PowerShell commands appear as an opaque, unreadable blob in Process Creation (Sysmon Event ID 1) logs. Script Block Logging closes that gap: PowerShell decodes `-EncodedCommand` internally before execution, and Script Block Logging captures that **decoded, plaintext output** — regardless of how the attacker obfuscated the original command.

### Enable it on the Windows endpoint

```powershell
$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $path -Force | Out-Null
Set-ItemProperty -Path $path -Name "EnableScriptBlockLogging" -Value 1
```

Verify:
```powershell
Get-ItemProperty -Path $path -Name "EnableScriptBlockLogging"
```
```
EnableScriptBlockLogging : 1
```

The `Powershell Operational` channel (`Microsoft-Windows-PowerShell/Operational`) was already being collected by the existing Windows integration in Fleet — no additional integration was required.

### Validation test

```powershell
Get-Process | Select-Object -First 3
```

**Kibana Discover query:**
```
event.code: "4104"
```

**Result:** captured cleanly, with the full command in `powershell.file.script_block_text`.

### Defeating obfuscation — re-running the Scenario 1 encoded command attack

```powershell
$cmd = "whoami; Get-Process | Select -First 3"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encodedCommand = [Convert]::ToBase64String($bytes)
powershell.exe -NoProfile -EncodedCommand $encodedCommand
```

**Result — Event 4104 captured the fully decoded command in plaintext:**
```
powershell.file.script_block_text: "whoami; Get-Process | Select -First 3"
```

**Key lesson:** where Process Creation logging (Scenario 1) only exposed the opaque Base64 string, Script Block Logging exposed the attacker's actual intent in plaintext — proving that a single logging source is never sufficient; detection coverage requires layering multiple telemetry sources against the same technique.

---

## Part B — Standing up DVWA on the Windows Endpoint

### Design decision: same host as the monitored endpoint

DVWA was installed directly on the existing Windows 10 victim machine (not a separate VM), for three reasons:
- Mirrors a realistic scenario where a compromised web server is also the monitored endpoint.
- Lets Apache access logs and Sysmon/PowerShell telemetry be correlated on the same host and timeline.
- Avoids the memory pressure of standing up a fourth VM (this lab already hit an Elasticsearch OOM crash once during setup — see Scenario 1 troubleshooting).

### 1. Install XAMPP (Apache + MySQL + PHP)

Downloaded XAMPP for Windows, PHP 7.4.33 branch (chosen for best compatibility with the classic DVWA codebase, which predates PHP 8.x deprecations):

```
https://sourceforge.net/projects/xampp/files/XAMPP%20Windows/7.4.33/
→ xampp-windows-x64-7.4.33-0-VS16-installer.exe
```

Installed with default components selected: **Apache, MySQL, PHP, phpMyAdmin** (FileZilla, Mercury, Tomcat left enabled by default but unused).

![XAMPP installer — Select Components](screenshots/xampp-select-components-installer.png)

![XAMPP Control Panel installed and ready](screenshots/xampp-control-panel-installed.png)
![XAMPP Control Panel — Apache & MySQL running with assigned ports](screenshots/xampp-control-panel-running-detail.png)

When prompted by Windows Defender Firewall, access was allowed for **Private networks**:

![Allowing Apache through Windows Defender Firewall](screenshots/windows-firewall-allow-apache.png)

**Apache** and **MySQL** were started from the XAMPP Control Panel. Verified working via:
```
http://localhost/
```

### 2. Download and place DVWA

```
https://github.com/digininja/DVWA → Code → Download ZIP
```

Extracted `DVWA-master.zip`, confirmed the correct file structure (`config`, `database`, `dvwa`, `login.php`, `setup.php`, etc.):

![DVWA extracted files — part 1](screenshots/dvwa-master-extracted-files-1.png)
![DVWA extracted files — part 2](screenshots/dvwa-master-extracted-files-2.png)

All contents of the inner `DVWA-master\DVWA-master` folder were copied into:
```
C:\xampp\htdocs\dvwa
```

### 3. Configure the database connection

Copied the config template and renamed it:
```
C:\xampp\htdocs\dvwa\config\config.inc.php.dist  →  config.inc.php
```

This DVWA release reads DB credentials from environment variables with fallback defaults:
```php
$_DVWA[ 'db_server' ]   = getenv('DB_SERVER') ?: '127.0.0.1';
$_DVWA[ 'db_database' ] = getenv('DB_DATABASE') ?: 'dvwa';
$_DVWA[ 'db_user' ]     = getenv('DB_USER') ?: 'dvwa';
$_DVWA[ 'db_password' ] = getenv('DB_PASSWORD') ?: 'p@ssw0rd';
$_DVWA[ 'db_port']      = getenv('DB_PORT') ?: '3306';
```

Since XAMPP's default MySQL only has a passwordless `root` account (no dedicated `dvwa` user was created), the fallback defaults were edited to match:
```php
$_DVWA[ 'db_user' ]     = getenv('DB_USER') ?: 'root';
$_DVWA[ 'db_password' ] = getenv('DB_PASSWORD') ?: '';
```

### 4. Run setup and create the database

```
http://localhost/dvwa/setup.php
```

Setup Check confirmed all green: writable folders, `mod_rewrite` enabled, PHP 7.4.33, `mysql`/`pdo_mysql` modules installed, DB credentials matching (`root` / blank / `dvwa` / `127.0.0.1:3306`).

Clicked **Create / Reset Database** → database and tables created successfully.

Logged in at `http://localhost/dvwa/login.php`:
```
Username: admin
Password: password
```

Set **DVWA Security Level** to **Low** (from the default **Impossible**) via the *DVWA Security* page, to allow the vulnerabilities to be exploitable for this exercise.

---

## Part C — Collecting Apache Access Logs in Fleet

To correlate web attacks with the same Elastic Stack pipeline used for endpoint telemetry, Apache's `access.log` was shipped to Elasticsearch via a new Fleet integration.

### Add the integration

`Fleet → Agent policies → windows-victim-policy → Add integration` → searched **"Custom Logs"** and selected the non-deprecated option:

```
Custom Logs (Filestream)
```

(the older plain **"Custom Logs"** entry is deprecated in favor of Filestream, which has better performance and ongoing support)

![Selecting Custom Logs (Filestream) integration](screenshots/fleet-add-custom-logs-filestream-1.png)
![Naming the integration](screenshots/fleet-add-custom-logs-filestream-2.png)

### Configure the log path

Under **Custom Filestream Logs → Paths**:
```
C:\xampp\apache\logs\access.log
```

![Filestream path configuration](screenshots/fleet-apache-filestream-path-config.png)

Integration name set to `apache-access-logs`, added to the `windows-victim-policy`:

![Integration listed in the policy](screenshots/fleet-integrations-list-apache-access-logs.png)

### Verify data is arriving

Generated traffic by opening a DVWA page, then queried Kibana Discover:
```
log.file.path: "C:\\xampp\\apache\\logs\\access.log"
```

![Apache access logs arriving in Kibana Discover](screenshots/kibana-apache-access-logs-arriving.png)

**Troubleshooting note:** Apache stopped responding once mid-session (`ERR_CONNECTION_REFUSED` on `localhost`) — resolved simply by restarting the Apache service from the XAMPP Control Panel. No configuration change was needed; this is a known intermittent behavior when a competing process briefly holds port 80.

---

## Part D — Attack Simulations

All three attacks were run manually through the DVWA UI at Security Level **Low**, against `localhost`.

### Simulation 1 — SQL Injection

**Location:** `http://localhost/dvwa/vulnerabilities/sqli/`

**Payload (User ID field):**
```
1' OR '1'='1
```

**Result:** the query returned every row in the `users` table instead of a single user — confirming the classic tautology-based SQLi bypass:
```sql
SELECT first_name, last_name FROM users WHERE user_id = '1' OR '1'='1'
```
```
admin / admin
Gordon / Brown
Hack / Me
Pablo / Picasso
Bob / Smith
```

![DVWA SQL Injection — full results returned for all users](screenshots/dvwa-sqli-full-results.png)

**Evidence — Apache access.log (Kibana Discover):**
```
GET /dvwa/vulnerabilities/sqli/?id=1%27+OR+%271%27%3D%271&Submit=Submit HTTP/1.1
```
(`%27` = `'`, `%3D` = `=` — full payload preserved in the URL since this is a GET request)

![Kibana Discover — SQL Injection payload captured in Apache access log](screenshots/kibana-sqli-detected-query.png)

**Detection query:**
```
data_stream.dataset: "apache.access" and message: *%27*OR*%27*
```

---

### Simulation 2 — Reflected XSS

**Location:** `http://localhost/dvwa/vulnerabilities/xss_r/`

**Payload (name field):**
```html
<script>alert('XSS Test')</script>
```

![DVWA Reflected XSS — payload entered in the name field](screenshots/dvwa-xss-reflected-payload-input.png)

**Result:** a JavaScript alert box fired in the browser, confirming the input was reflected back into the page and executed as active script rather than rendered as inert text.

![Browser alert box confirming successful XSS execution](screenshots/dvwa-xss-alert-popup-success.png)

**Evidence — Apache access.log (Kibana Discover), two related entries:**

The original request that triggered execution:
```
GET /dvwa/vulnerabilities/xss_r/?name=%3Cscript%3Ealert%28%27XSS+Test%27%29%3C%2Fscript%3E HTTP/1.1
Status: 200
```

A follow-up favicon request one millisecond later, carrying the same payload in its `Referer` header (browser navigation artifact):
```
GET /dvwa/favicon.ico HTTP/1.1
Referer: http://localhost/dvwa/vulnerabilities/xss_r/?name=%3Cscript%3Ealert%28%27XSS+Test%27%29%3C%2Fscript%3E
```

![Kibana Discover — XSS payload captured in Apache access log](screenshots/kibana-xss-detected-query.png)

**Detection query:**
```
data_stream.dataset: "apache.access" and message: *script*
```

---

### Simulation 3 — Command Injection

**Location:** `http://localhost/dvwa/vulnerabilities/exec/`

**Payload (IP address field):**
```
127.0.0.1 & whoami
```

**Result:** the application returned the expected `ping` output **plus** the output of the injected `whoami` command, revealing the local Windows account running the web server process:
```
Pinging 127.0.0.1 with 32 bytes of data:
Reply from 127.0.0.1: bytes=32 time=3ms TTL=128
...
Packets: Sent = 4, Received = 4, Lost = 0 (0% loss)

desktop-t4vlkqs\victim
```

**Evidence — Apache access.log (Kibana Discover):**
```
POST /dvwa/vulnerabilities/exec/ HTTP/1.1
Status: 200
```

**Key lesson — GET vs. POST logging visibility:** unlike the SQLi and XSS payloads (sent via GET, and therefore fully visible in the URL logged by Apache), this attack used a POST request, so the injected payload (`127.0.0.1 & whoami`) is **not visible** in the standard access log — only the fact that a POST request succeeded is recorded. This is an important limitation to document: **plain web server access logs are sufficient to detect GET-based injection attacks, but insufficient to reveal the content of POST-based attacks.** Full visibility into POST bodies would require a web application firewall (e.g., ModSecurity) or network-level packet capture (e.g., Wireshark).

**Detection query (best available without payload visibility):**
```
data_stream.dataset: "apache.access" and url.path: "/dvwa/vulnerabilities/exec/" and http.request.method: "POST"
```

---

## MITRE ATT&CK Mapping

| Technique | ID | Simulation |
|---|---|---|
| Exploit Public-Facing Application | T1190 | SQL Injection, Reflected XSS, Command Injection |
| Command and Scripting Interpreter: PowerShell | T1059.001 | Script Block Logging bypass test |
| Obfuscated Files or Information | T1027 | Base64-encoded PowerShell command |
| Unix/Windows Shell (via web exec) | T1059 | Command Injection (`whoami` execution) |

---

## Key Takeaways

- **Layered logging beats single-source logging.** Script Block Logging (Event 4104) revealed a fully decoded PowerShell command that Process Creation logging (Event 1) could only show as an unreadable Base64 blob — proving that no single telemetry source gives complete visibility into the same technique.
- **GET-based web attacks are fully visible in access logs; POST-based attacks are not.** SQLi and XSS payloads sent via GET were captured in full in Apache's access log. The Command Injection payload, sent via POST, only produced a generic "POST succeeded" log line — the actual injected command was invisible without deeper instrumentation (WAF or packet capture).
- **Same-host web app + endpoint monitoring enables correlation.** Hosting DVWA on the already-monitored Windows endpoint made it possible to observe both the web-layer evidence (Apache logs) and host-layer evidence (Sysmon/PowerShell logs) for the same attack timeline, without needing to stitch data across multiple systems.
- **Infrastructure hiccups are normal and quick to resolve.** Apache silently stopped mid-session (likely a brief port 80 contention) — restarting the service from the XAMPP Control Panel was the entire fix, with no configuration changes required.

---

## Screenshots

| Stage | Screenshot |
|---|---|
| XAMPP installer — selecting components | `screenshots/xampp-select-components-installer.png` |
| XAMPP Control Panel installed | `screenshots/xampp-control-panel-installed.png` |
| XAMPP Control Panel — Apache & MySQL running with ports | `screenshots/xampp-control-panel-running-detail.png` |
| Windows Firewall prompt for Apache | `screenshots/windows-firewall-allow-apache.png` |
| DVWA extracted files (1/2) | `screenshots/dvwa-master-extracted-files-1.png` |
| DVWA extracted files (2/2) | `screenshots/dvwa-master-extracted-files-2.png` |
| Fleet — selecting Custom Logs (Filestream) | `screenshots/fleet-add-custom-logs-filestream-1.png` |
| Fleet — naming the integration | `screenshots/fleet-add-custom-logs-filestream-2.png` |
| Fleet — configuring the Apache log path | `screenshots/fleet-apache-filestream-path-config.png` |
| Fleet — integration listed in the policy | `screenshots/fleet-integrations-list-apache-access-logs.png` |
| Kibana Discover — Apache access logs arriving | `screenshots/kibana-apache-access-logs-arriving.png` |
| DVWA SQL Injection — full results returned for all users | `screenshots/dvwa-sqli-full-results.png` |
| Kibana Discover — SQLi payload captured in Apache access log | `screenshots/kibana-sqli-detected-query.png` |
| DVWA Reflected XSS — payload entered in the name field | `screenshots/dvwa-xss-reflected-payload-input.png` |
| Browser alert box confirming successful XSS execution | `screenshots/dvwa-xss-alert-popup-success.png` |
| Kibana Discover — XSS payload captured in Apache access log | `screenshots/kibana-xss-detected-query.png` |

---

## Next in this series

⬅️ [Scenario 1 — Sysmon: Encoded PowerShell & Download Cradle Detection](../scenario1-sysmon-encoded-powershell/README.md)
