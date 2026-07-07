#!/usr/bin/env python3
"""De-noise parsed Nmap data and bucket real services into finding categories.

Usage:
    python3 parse_nmap.py scan.nmap > hosts.json
    python3 triage.py hosts.json

THE CORE JOB: separate real services from scan artifacts BEFORE counting, so
findings aren't inflated by tcpwrapped noise and load-balancer VIPs. Prints:
  1. NOISE report  — hosts that answer on absurdly many ports (LB/firewall/honeypot)
                     and the scan-wide tcpwrapped total.
  2. FALSE-POSITIVE watchlist — service detections that are probably wrong.
  3. FINDINGS inventory — real (non-tcpwrapped) services per category, with hosts.

Counts here are DE-NOISED. The analyst still assigns severity, verifies links,
and writes the report.  Categories/thresholds are heuristics — read, don't trust blindly.
"""
import json, sys
from collections import Counter

if len(sys.argv) < 2:
    sys.exit(__doc__)
hosts = json.load(open(sys.argv[1]))

def ipkey(t):
    try: return tuple(int(x) for x in t.split(':')[0].split('.'))
    except Exception: return (999,)

# ---------- 1. NOISE: hosts answering on implausibly many ports ----------
FLOOD = 100   # a host with >100 open ports is almost never a real multi-service host
flood = sorted([(h['target'], len(h['ports']),
                 sum(1 for p in h['ports'] if p['service'] == 'tcpwrapped'))
                for h in hosts if len(h['ports']) > FLOOD], key=lambda x: -x[1])
tw_total = sum(1 for h in hosts for p in h['ports'] if p['service'] == 'tcpwrapped')
total = sum(len(h['ports']) for h in hosts)
print("=" * 70)
print(f"NOISE REPORT   hosts={len(hosts)}  open-ports={total}  tcpwrapped={tw_total} "
      f"({100*tw_total//max(total,1)}%)")
print("=" * 70)
if flood:
    print(f"\n{len(flood)} host(s) answer on >{FLOOD} ports — treat as load-balancer VIP /")
    print("firewall / honeypot. Their 'open' ports are NOT confirmed services:")
    for t, n, tw in flood:
        print(f"   {t:18}  {n} ports ({tw} tcpwrapped)")
# identify device type of flooders from any real banner they leak
for t, n, tw in flood[:5]:
    h = next(x for x in hosts if x['target'] == t)
    banners = {p['version'] for p in h['ports'] if p['version']}
    if banners:
        print(f"   {t} banners: {', '.join(sorted(banners)[:4])}")

# ---------- 2. FALSE-POSITIVE watchlist ----------
# Nmap version detection misfires on odd ports. Flag only a MISMATCH: an app/service
# detected on a well-known port where it doesn't belong (expected service given, and
# the actual detection isn't it). Correct detections (e.g. ms-wbt on 3389) are NOT flagged.
SUSPECT = {   # port: (expected-service-substrings, why a mismatch is suspect)
    464: (('kpasswd', 'kerberos'), 'kpasswd/Kerberos port — app detections here are usually wrong'),
    88:  (('kerberos',),           'Kerberos port — app-server detections here are usually wrong'),
    3389:(('ms-wbt', 'tcpwrapped'),'RDP port — non-RDP detections here are suspect'),
    2049:(('nfs', 'rpcbind'),      'NFS port — other detections here are suspect'),
}
print("\n" + "=" * 70 + "\nFALSE-POSITIVE WATCHLIST\n" + "=" * 70)
fp = []
for h in hosts:
    for p in h['ports']:
        exp = SUSPECT.get(p['port'])
        if not exp or 'tcpwrapped' in p['service']:
            continue
        if not any(e in p['service'].lower() for e in exp[0]):
            fp.append(f"   {h['target']}:{p['port']} detected '{p['service']} {p['version']}'"
                      f"  <- {exp[1]}")
print("\n".join(fp) if fp else "   (no classic misfire-port mismatches detected)")

# ---------- 3. FINDINGS inventory (de-noised) ----------
def real(p):  # a service we trust enough to count
    return p['service'] != 'tcpwrapped'

CATS = [
    ("etcd datastore (2379/2380)",      lambda p: p['port'] in (2379, 2380)),
    ("Kubernetes (kubelet/api 10250/10259/10257/6443/16443)",
                                        lambda p: p['port'] in (10250, 10257, 10259, 6443, 16443)),
    ("Telnet (cleartext)",              lambda p: p['service'] == 'telnet'),
    ("FTP (cleartext)",                 lambda p: p['service'].startswith('ftp')),
    ("VNC",                             lambda p: 'vnc' in p['service']),
    ("SNMP",                            lambda p: p['service'].startswith('snmp')),
    ("Redis",                           lambda p: 'redis' in p['service'].lower()),
    ("MongoDB",                         lambda p: 'mongo' in p['service'].lower()),
    ("MSSQL",                           lambda p: p['service'] == 'ms-sql-s'),
    ("PostgreSQL",                      lambda p: p['service'] == 'postgresql'),
    ("Oracle TNS",                      lambda p: 'oracle' in p['service'].lower() or p['port'] == 1521),
    ("NFS",                             lambda p: p['service'] == 'nfs'),
    ("RDP (ms-wbt-server)",             lambda p: p['service'] == 'ms-wbt-server'),
    ("LDAP / AD",                       lambda p: 'ldap' in p['service'].lower()),
    ("VMware mgmt (902/8182)",          lambda p: 'vmware' in p['service'].lower()),
    ("HP iLO / BMC",                    lambda p: 'ilo' in p['version'].lower() or 'Lights-Out' in p['version']),
    ("Printers (9100/jetdirect/print)", lambda p: 'jetdirect' in p['service'] or 'print' in p['service'].lower() or 'printer' in p['version'].lower()),
    ("SMB / netbios",                   lambda p: p['service'] in ('microsoft-ds', 'netbios-ssn') or 'microsoft-ds' in p['service']),
]
print("\n" + "=" * 70 + "\nFINDINGS INVENTORY  (tcpwrapped excluded)\n" + "=" * 70)
for label, pred in CATS:
    rows = sorted({f"{h['target']}:{p['port']}" for h in hosts for p in h['ports']
                   if real(p) and pred(p)}, key=ipkey)
    if rows:
        print(f"\n[{len(rows)}] {label}")
        print("   " + ", ".join(rows[:40]) + (" ..." if len(rows) > 40 else ""))

# Outdated/weak version banners worth grepping (version strings only)
print("\n" + "-" * 70 + "\nVERSION BANNERS (scan for EOL/CVE-bearing versions):")
vers = Counter(f"{p['service']} {p['version']}" for h in hosts for p in h['ports']
               if real(p) and p['version'])
for v, n in vers.most_common(30):
    print(f"   {n:4}  {v}")

# NSE script findings that flag misconfig directly
print("\n" + "-" * 70 + "\nNSE MISCONFIG SIGNALS (read these lines in the raw file):")
SIGNALS = ['but not required', 'open-proxy', 'Access-Control-Allow-Origin: *',
           'VNC Authentication', 'anonymous', 'NULL', 'sslv2', 'sslv3',
           'Not valid after', 'ftp-anon']
sig = Counter()
for h in hosts:
    for p in h['ports']:
        for s in p['scripts']:
            for k in SIGNALS:
                if k in s: sig[k] += 1
for k, n in sig.most_common():
    print(f"   {n:4}  {k}")
