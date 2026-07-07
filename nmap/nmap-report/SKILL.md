---
name: nmap-report
description: Use when analyzing Nmap output files (.nmap/.gnmap/.xml scan results) to identify vulnerabilities and configuration issues and produce an HTML findings report for a pentest/engagement. Triggers on nmap scan analysis, service enumeration review, turning port-scan results into a client report.
---

# Nmap → HTML Findings Report

## Overview

Turn a raw Nmap service scan into a de-noised, severity-ranked HTML findings report with verified reference/PoC links.

**Core principle: DE-NOISE BEFORE YOU COUNT.** Large scans are dominated by artifacts — `tcpwrapped` ports, load-balancer VIPs that answer on hundreds of ports, and service-detection misfires. Counting these as real services inflates and mis-ranks findings. Every count in the report must come from *confirmed* services, and the report must state what was excluded and why.

## When to use

- You have an Nmap results file and need a vulnerability/misconfig report.
- Reviewing service/version (`-sV -sC`) output for exposures.
- Any "analyze this scan and tell me what's exploitable" request.

## Workflow

1. **Parse** → `python3 scripts/parse_nmap.py scan.nmap > hosts.json` (also `--summary` for a quick service tally). Works on Nmap normal output; for XML, tell the user or convert first.
2. **Triage / de-noise** → `python3 scripts/triage.py hosts.json`. Read all three sections: NOISE REPORT (flooder hosts + tcpwrapped %), FALSE-POSITIVE WATCHLIST, and the de-noised FINDINGS INVENTORY.
3. **Investigate** the inventory + version banners + NSE signals. `grep` the raw file for detail (`ssl-cert`, `smb2-security-mode`, `http-cors`, `ftp-anon`, etc.). Confirm what's real before it becomes a finding.
4. **Assign severity** using network-position context (see taxonomy). Down-rate exposures behind auth; up-rate unauth data stores / mgmt planes.
5. **Verify every link** (see rule below) — no unverified reference or PoC ships.
6. **Build the report** from `assets/report_template.html`: fill placeholders, one finding card per issue, keep the artifacts/caveats card last.

## The de-noising rules (this is the point of the skill)

| Artifact | Signature | Do |
|---|---|---|
| **Load-balancer / firewall / honeypot VIP** | one host "open" on 100s of ports, nearly all `tcpwrapped` (F5 BIG-IP, Citrix, etc. leak a banner on 80/443) | Treat as ONE device. Do NOT report its ports as services. List under artifacts card. Cross-check any real banner it leaks. |
| **`tcpwrapped`** | TCP handshake completes, no service banner | NOT a confirmed service. Exclude from counts. High scan-wide % (e.g. >50%) means heavy filtering/proxying — say so. |
| **Service-detection false positive** | app name on a well-known port for something else (e.g. "Apache Spark" on 464/kpasswd, an app on 3389) | Flag as likely misfire; do not action without confirmation. |
| **Sanitized identifiers** | hostnames/domains normalized to `hostname`/`domain.tld` | Note it; org data may still be in certs. |

`triage.py` detects the first three automatically. **Trust the de-noised inventory, not raw `--summary` counts.**

## Finding taxonomy (what to hunt; typical severity)

High-signal categories — confirm each against the raw file:

- **Critical/High, unauth data & control planes:** exposed **etcd** (2379/2380), **Kubernetes** kubelet 10250 / apiserver / scheduler 10259 / controller 10257, unauth **Redis/MongoDB**, exposed **etcd/CoreDNS/k8s** secrets.
- **High, relay & mgmt:** **SMB signing not required** (`smb2-security-mode` → NTLM relay), **iLO/iDRAC/BMC** & **VMware ESXi** (902/8182) mgmt exposure, IPMI.
- **Medium, cleartext & legacy:** **Telnet**, **FTP**, **VNC** (esp. RFB 3.3), **SNMP** (v1/v2c/`public`), **rsh/rlogin**, EOL SSH (OpenSSH ≤7.7 → CVE-2018-15473; old Dropbear/libssh), unauth **printers** (9100/PJL), **NFS** exports, network-exposed **databases** (MSSQL/PostgreSQL/Oracle).
- **Low/Info:** broad **RDP** exposure (with NLA), wildcard **CORS**, expired/long-validity/self-signed **certs**, default web pages, remote-access agents (Splashtop/TeamViewer).

Severity is contextual: an unauthenticated etcd is Critical; an authenticated DB restricted to an app tier may be informational. State the assumption when exploitability is unconfirmed.

## Link verification (non-negotiable)

Every reference and PoC URL MUST be fetched/confirmed live before inclusion (the user requires this).

- Prefer stable canonical sources: **NVD** (`nvd.nist.gov/vuln/detail/CVE-…`), vendor advisories, **CWE** (`cwe.mitre.org`), **Exploit-DB**, official tool repos.
- Verify the CVE actually matches the observed version. **Common trap:** libssh **CVE-2018-10933** auth bypass affects 0.6.0–0.8.3/0.7.5 — it does **NOT** apply to 0.5.x. Match version ranges precisely; don't attach a famous CVE to a version outside its range.
- If a page 404s or doesn't match, drop or replace it. Mark the refs block `verified` only when true.

## Report specifics

- Build from `assets/report_template.html` (self-contained: inline CSS/JS, light/dark toggle, severity badges). Write the finished report to the engagement dir, not the template.
- **`.poc` blocks need `white-space:pre-wrap`** (already in template) or multi-line commands collapse to one line.
- Include the **artifacts/caveats card** every time — flooder hosts, tcpwrapped %, false positives, and what was NOT tested (UDP amp, SNMP community brute, DNS recursion, credentialed vuln scan).
- Give exploitable findings a PoC/validation block; give hygiene findings remediation only.

## Common mistakes (observed in unguided baseline)

- **Counting `tcpwrapped`/LB ports as real services** — reported "Redis 15 hosts / Telnet 23 hosts / Oracle 15 hosts" that were all one /24 of F5 VIPs answering on every port. Run `triage.py` and count from its de-noised inventory.
- **Writing a "treat cautiously" caveat, then ignoring it** in the counts. The caveat must actually change the numbers.
- **Under-ranking the real crown jewels** (etcd, k8s control plane, iLO) while over-ranking noisy cleartext hits.
- **Unverified links / mismatched CVEs.** Fetch every URL; check version ranges.
- **Broken PoC line breaks** from missing `white-space:pre-wrap`.
