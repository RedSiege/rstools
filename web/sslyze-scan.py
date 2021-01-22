#!/usr/bin/env python3
import sys
import argparse
import datetime

try:
    from sslyze import *
    import sslyze.errors
except:
    print("""
Missing module "sslyze". Install it with the following commands:
  pip install --upgrade setuptools
  pip install --upgrade sslyze
    """)
    sys.exit()

try:
    import xmlstarlet
except:
    print('Missing module xmlstarlet. Please install with:\n  pip install --upgrade xmlstarlet')
    sys.exit()

def NmapXmlToTargets(nxml):
    from subprocess import Popen, PIPE
    process = Popen(['xmlstarlet', 'select', '-T', '-t', '-m', '/nmaprun/host/ports/port/service[@name="https" or @name="ssl" or @tunnel="ssl"]', '-v', '../../../child::address/attribute::addr', '-o', ':', '-v', '../@portid', '-n', nxml], stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    if stderr:
        print('Error: reading file ' + nxml.name)
        print(stderr)
        sys.exit
    targets = []
    output = stdout.decode('ascii').strip()
    if len(output) == 0:
        return []
    for target in output.split('\n'):
        host, port = target.split(':')
        targets.append((host,int(port)))
    return targets


def CheckHosts(targets, export=False):
    cmds = [ # see list here: https://nabla-c0d3.github.io/sslyze/documentation/available-scan-commands.html
        ScanCommand.CERTIFICATE_INFO,
        ScanCommand.SSL_2_0_CIPHER_SUITES,
        ScanCommand.SSL_3_0_CIPHER_SUITES,
        ScanCommand.TLS_1_0_CIPHER_SUITES,
        ScanCommand.TLS_1_1_CIPHER_SUITES,
        ScanCommand.TLS_1_2_CIPHER_SUITES,
        ScanCommand.TLS_1_3_CIPHER_SUITES,
        ScanCommand.TLS_COMPRESSION,
        ScanCommand.TLS_1_3_EARLY_DATA,
        ScanCommand.OPENSSL_CCS_INJECTION,
        ScanCommand.TLS_FALLBACK_SCSV,
        ScanCommand.HEARTBLEED,
        ScanCommand.ROBOT,
    ]

    # queue the scanners
    scanner = Scanner()

    for target in targets:
        host, port = target
        server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(host, port)

        # Do connectivity testing to ensure SSLyze is able to connect
        try:
            server_info = ServerConnectivityTester().perform(server_location)
        except sslyze.errors.ConnectionToServerTimedOut as e:
            # Could not connect to the server; abort
            #print(f"Error connecting to {server_location}: {e.error_message}")
            print(f"Error connecting to {server_location.hostname} {server_location.ip_address}: {e.error_message}")
            continue
        except Exception as e:
            print(f"Error connecting to {target}: \n{e.error_message}")

        server_scan_req = ServerScanRequest(server_info=server_info, scan_commands=cmds)
        scanner.queue_scan(server_scan_req)

    results = []
    for r in scanner.get_results():
        results.append({
            'ip': r.server_info.server_location.ip_address,
            'port': r.server_info.server_location.port,
            'print': (r.server_info.server_location.ip_address + ":" + str(r.server_info.server_location.port)),
            'result': r
        })

    if export:
        for i, r in enumerate(results):
            with open(f"{r['print']}-{i}.json", 'w') as f:
                f.write(json.dumps(asdict(r['result']), cls=sslyze.JsonEncoder))


    # Self-Signed
    print("\nSelf-Signed Certificate:")
    for r in results:
        if r['result'].scan_commands_results['certificate_info'].certificate_deployments[0].path_validation_results[0].openssl_error_string and "self signed certificate" in r['result'].scan_commands_results['certificate_info'].certificate_deployments[0].path_validation_results[0].openssl_error_string:
                print(r['print'])

    # Deprecated Protocols - Report up to TLS 1.1
    # In the future we may need to add ScanCommand.TLS_1_2_CIPHER_SUITES and ScanCommand.TLS_1_3_CIPHER_SUITES
    deprecated_protos = [ScanCommand.SSL_2_0_CIPHER_SUITES, ScanCommand.SSL_3_0_CIPHER_SUITES, ScanCommand.TLS_1_0_CIPHER_SUITES, ScanCommand.TLS_1_1_CIPHER_SUITES]
    print("\nDeprecated Protocols:")
    for r in results:
        protos = []
        for proto in deprecated_protos:
            if len(r['result'].scan_commands_results[proto].accepted_cipher_suites):
                name,major,minor = r['result'].scan_commands_results[proto].tls_version_used.name.split('_')
                protos.append(f'{name}v{major}.{minor}')
        if len(protos):
            print(r['print'] + '\t' + ', '.join(protos))

    # Expired
    print("\nExpired Certificates:")
    for r in results:
        if datetime.datetime.now() > r['result'].scan_commands_results['certificate_info'].certificate_deployments[0].received_certificate_chain[0].not_valid_after:
            print(r['print'])


    # Weak Signature
    print("\nSHA1 Signature: ")
    for r in results:
        if r['result'].scan_commands_results['certificate_info'].certificate_deployments[0].received_certificate_chain[0].signature_hash_algorithm.name in ['sha1', 'md5']:
            print(r['print'])
    

    # Weak RSA Length < 2048
    print("\nInsecure RSA Length:")
    for r in results:
        keysize = r['result'].scan_commands_results['certificate_info'].certificate_deployments[0].received_certificate_chain[0].public_key().key_size
        if keysize < 2048:
            print(f"{r['print']} {keysize} bits")

    # Weak ciphers
    print("\nWeak Ciphers")
    all_protos = [
        #ScanCommand.SSL_2_0_CIPHER_SUITES, # already caught with depracated protocols
        ScanCommand.SSL_3_0_CIPHER_SUITES, # already caught with depracated protocols
        ScanCommand.TLS_1_0_CIPHER_SUITES,
        ScanCommand.TLS_1_1_CIPHER_SUITES,
        ScanCommand.TLS_1_2_CIPHER_SUITES,
        ScanCommand.TLS_1_3_CIPHER_SUITES
    ]
    for r in results:
        ciphers = []
        for proto in all_protos:
            for cipher in r['result'].scan_commands_results[proto].accepted_cipher_suites:
                name = cipher.cipher_suite.openssl_name
                if 'NULL' in name or 'EXP' in name or 'ADH' in name or 'AECDH' in name:
                    ciphers.append(name)
        if len(ciphers):
            print(f"{r['print']}\t{', '.join(ciphers)}")
    

    # Medium ciphers
    print("\nMedium Ciphers")
    for r in results:
        ciphers = []
        for proto in all_protos:
            for cipher in r['result'].scan_commands_results[proto].accepted_cipher_suites:
                name = cipher.cipher_suite.openssl_name
                if 'DES' in name or 'RC4' in name:
                    ciphers.append(name)
        if len(ciphers):
            print(f"{r['print']}\t{', '.join(ciphers)}")

def main():
    parser = argparse.ArgumentParser(description='Get SSL/TTL Issues in a simple format')

    xml_group = parser.add_argument_group(title='Get targets from Nmap XML output')
    xml_group.add_argument('-x', dest='nmapxmls', nargs='+', type=argparse.FileType('r'), help="Nmap's XML files", metavar='nmap.xml')

    target_group = parser.add_argument_group(title='Target a host')
    target_group.add_argument('-t', dest='targets', nargs='+', type=str, help="Target host or host:port. If not port is specified the default will be 443.", metavar='host:port')

    args = parser.parse_args()

    if not args.nmapxmls and not args.targets:
        #print(parser.print_usage())
        parser.print_help()
        print('\nNo input file(s) or target(s) provided')
        sys.exit()


    targets = []

    # get individual items added on the command line
    if args.targets:
        for target in args.targets:
            if ':' in target:
                host, port = target.split(':')
                targets.append((host,int(port)))
            else:
                targets.append((target, 443))

    # get targets from xml
    if args.nmapxmls:
        for nxml in args.nmapxmls:
            targets.extend(NmapXmlToTargets(nxml.name))
            
    if len(targets) == 0:
        print('No targets')

    CheckHosts(targets)

if __name__ == '__main__':
    main()
