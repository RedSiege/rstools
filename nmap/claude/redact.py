#!/usr/bin/env python3
import re
import sys


def redact(input_path, output_path):
    """ Redact Nmap output to remove hostnames from various fields """
    with open(input_path, 'r', errors='replace') as f:
        lines = f.readlines()

    out = []
    skip = False

    for line in lines:
        stripped = line.rstrip('\n')

        # Start of fingerprint block
        if re.search(r'\d+ services? unrecognized despite returning data', stripped):
            skip = True
            continue

        # Within fingerprint block: skip SF: data lines and section separators
        if skip:
            if re.match(r'^SF', stripped) or re.match(r'^={10,}', stripped):
                continue
            else:
                skip = False
                # Fall through to process this line normally

        # Nmap scan report for hostname (IP) — redact resolved hostname
        def _redact_scan_report(m):
            host = m.group(1)
            replacement = 'hostname.domain.tld' if '.' in host else 'hostname'
            return f'Nmap scan report for {replacement} '
        stripped = re.sub(
            r'^Nmap scan report for ([^\s(]+) (?=\()',
            _redact_scan_report,
            stripped
        )

        # NetBIOS / DNS script output fields: "|   KEY: VALUE"
        stripped = re.sub(
            r'(^\|[ ]+NetBIOS_Domain_Name:[ ]+).+',
            r'\1domain',
            stripped
        )
        stripped = re.sub(
            r'(^\|[ ]+NetBIOS_Computer_Name:[ ]+).+',
            r'\1hostname',
            stripped
        )
        stripped = re.sub(
            r'(^\|[ ]+DNS_Domain_Name:[ ]+).+',
            r'\1domain.tld',
            stripped
        )
        stripped = re.sub(
            r'(^\|[ ]+DNS_Computer_Name:[ ]+).+',
            r'\1hostname.domain.tld',
            stripped
        )
        stripped = re.sub(
            r'(^\|[ ]+DNS_Tree_Name:[ ]+).+',
            r'\1domain.tld',
            stripped
        )

        stripped = re.sub(
            r'(^\|[ ]+Target_Name:[ ]+).+',
            r'\1hostname',
            stripped
        )

        # nbstat NetBIOS name
        stripped = re.sub(
            r'(NetBIOS name:[ ]+)[^,]+',
            r'\1hostname',
            stripped
        )

        # ssl-cert commonName
        stripped = re.sub(
            r'(^\|[ ]+ssl-cert: Subject: commonName=)[^/\n]+',
            r'\1hostname.domain.tld',
            stripped
        )

        # Inline LDAP Domain: value (e.g. "Domain: ziply.com,")
        stripped = re.sub(
            r'(Domain:[ ]+)[^,)]+',
            r'\1domain.tld',
            stripped
        )

        # nbns/msrpc script fields: Domain name, Forest name, FQDN
        stripped = re.sub(
            r'(^\|[ ]+Domain name:[ ]+).+',
            r'\1domain.tld',
            stripped
        )
        stripped = re.sub(
            r'(^\|[ ]+Forest name:[ ]+).+',
            r'\1domain.tld',
            stripped
        )
        stripped = re.sub(
            r'(^\|[ ]+FQDN:[ ]+).+',
            r'\1hostname.domain.tld',
            stripped
        )

        # smtp-commands: server FQDN before "Hello"
        def _redact_smtp_fqdn(m):
            prefix, host, rest = m.group(1), m.group(2), m.group(3)
            if '.' in host and not host.startswith('['):
                host = 'hostname.domain.tld'
            return prefix + host + rest
        stripped = re.sub(
            r'(^\|[_ ]smtp-commands:\s+)(\S+)(\s+Hello\s+)',
            _redact_smtp_fqdn,
            stripped
        )

        # Service Info: Host/Hosts — redact any FQDN (dotted, non-IP) value
        def _redact_service_host(m):
            prefix, hosts_str, suffix = m.group(1), m.group(2), m.group(3)
            redacted = []
            for h in hosts_str.split(', '):
                h = h.strip()
                if '.' in h and not re.match(r'[\d.]+$', h):
                    h = 'hostname.domain.tld'
                redacted.append(h)
            return prefix + ', '.join(redacted) + suffix
        stripped = re.sub(
            r'(Service Info: Hosts?:\s+)([^;]+)(;|$)',
            _redact_service_host,
            stripped
        )

        # Subject Alternative Name — redact DNS: FQDNs (dotted, non-IP, non-.local)
        def _redact_san_dns(m):
            value = m.group(1)
            if re.match(r'[\d.:]+$', value) or value.lower() == 'localhost':
                return 'DNS:' + value
            if '.' in value:
                return 'DNS:hostname.domain.tld'
            return 'DNS:' + value
        if 'Subject Alternative Name' in stripped:
            stripped = re.sub(r'DNS:([^,\s]+)', _redact_san_dns, stripped)

        # workgroup in microsoft-ds service line
        stripped = re.sub(
            r'(workgroup:[ ]+)[^)]+',
            r'\1domain',
            stripped
        )

        # VMware vCenter/PSC LDAP hostname
        stripped = re.sub(
            r'(open\s+ldap\s+VMware vCenter or PSC LDAP\s+)\S+',
            r'\1hostname.domain.tld',
            stripped
        )

        out.append(stripped + '\n')

    with open(output_path, 'w') as f:
        f.writelines(out)


if __name__ == '__main__':
    if len(sys.argv) == 3:
        redact(sys.argv[1], sys.argv[2])
    elif len(sys.argv) == 2:
        redact(sys.argv[1], sys.argv[1])
    else:
        print(f"Usage: {sys.argv[0]} <input.nmap> [output.nmap]")
        print("  If output is omitted, file is redacted in-place.")
        sys.exit(1)
