#!/usr/bin/env python3
"""Parse Nmap normal output (-oN / .nmap) into structured JSON.

Usage:
    python3 parse_nmap.py client.nmap > hosts.json
    python3 parse_nmap.py client.nmap --summary   # print service counts, no JSON

Output: JSON list of {target, ports:[{port,proto,state,service,version,scripts:[...]}],
                       hostscripts:[...], serviceinfo}
Handles multiple concatenated scans and host/port-level NSE script lines.
"""
import re, json, sys

def parse(path):
    lines = open(path, encoding='utf-8', errors='replace').read().splitlines()
    hosts, cur, curport = [], None, None
    for ln in lines:
        m = re.match(r'Nmap scan report for (.+)', ln)
        if m:
            if cur: hosts.append(cur)
            cur = {'target': m.group(1).strip(), 'ports': [], 'hostscripts': []}
            curport = None
            continue
        if cur is None:
            continue
        pm = re.match(r'(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)\s*(.*)', ln)
        if pm:
            curport = {'port': int(pm.group(1)), 'proto': pm.group(2),
                       'state': pm.group(3), 'service': pm.group(4),
                       'version': pm.group(5).strip(), 'scripts': []}
            cur['ports'].append(curport)
            continue
        sm = re.match(r'\|_?\s?(.*)', ln)          # NSE script output line
        if sm:
            (curport['scripts'] if curport else cur['hostscripts']).append(sm.group(1))
            continue
        if ln.startswith('Service Info:'):
            cur['serviceinfo'] = ln
    if cur: hosts.append(cur)
    return hosts

if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    hosts = parse(sys.argv[1])
    if '--summary' in sys.argv:
        from collections import Counter
        c = Counter(p['service'] for h in hosts for p in h['ports'])
        print(f"hosts={len(hosts)}  ports={sum(len(h['ports']) for h in hosts)}")
        for s, n in c.most_common(50):
            print(f"{n:6}  {s}")
    else:
        json.dump(hosts, sys.stdout)
