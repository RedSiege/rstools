#!/usr/bin/env python3
import sys
import argparse
import datetime

GROUPSIZE = 20

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

def chunker(seq, size):
    return (seq[pos:pos + size] for pos in range(0, len(seq), size))

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

def printer(header, data, verbose):
    if len(data):
        print('\n' + header + ':')
        for s in data:
            print(s)
        print('Count: ' + str(len(data)))
    elif verbose:
        print('\n' + header)
        print('Count: 0')

def CheckHosts(targets, verbose=False):
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

    results = []

    for chunk in chunker(targets, GROUPSIZE):
        # this is an asyncronous scanner, but it has a memory leak so it is being caller serially
        # Yes, Scanner() has options to reduce the number of targets, but the propblem still occurs
        scanner = Scanner()

        # Chunking so the scanner can be nuked and restarted
        for host,port in chunk:

            if verbose:
                print(f'Testing {host}:{port}')

            server_location = ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(host, port)

            # Do connectivity testing to ensure SSLyze is able to connect
            try:
                server_info = ServerConnectivityTester().perform(server_location)
            except sslyze.errors.ConnectionToServerTimedOut as e:
                # Could not connect to the server; abort
                print(f'Error connecting to {server_location.hostname} {server_location.ip_address}: {e.error_message}')
                continue
            except sslyze.errors.ServerRejectedConnection as e:
                # Could not connect to the server; abort
                print(f'Connection rejected to {server_location.hostname} {server_location.ip_address}: {e.error_message}')
                continue
            except sslyze.errors.ServerTlsConfigurationNotSupported as e:
                # Could not connect to the server; abort
                print(f'TLS Configuration not supported {server_location.hostname} {server_location.ip_address}: {e.error_message}')
                continue
            except sslyze.errors.ConnectionToServerFailed as e:
                # Could not connect to the server; abort
                print(f'Connection to server failed {server_location.hostname} {server_location.ip_address}: {e.error_message}')
                continue
            except KeyboardInterrupt:
                sys.exit()
            except:
                e = sys.exc_info()[0]
                print(f'Error connecting to {target}: \n{e}')
                continue

            server_scan_req = ServerScanRequest(server_info=server_info, scan_commands=cmds)
            scanner.queue_scan(server_scan_req)

        for r in scanner.get_results():
            results.append({
                'ip': r.server_info.server_location.ip_address,
                'port': r.server_info.server_location.port,
                'print': (r.server_info.server_location.ip_address + ':' + str(r.server_info.server_location.port)),
                'result': r
            })

            if verbose:
                print('Tested ' + r.server_info.server_location.ip_address + ':' + str(r.server_info.server_location.port))

    #if export:
    #    for i, r in enumerate(results):
    #        with open(f"{r['print']}-{i}.json", 'w') as f:
    #            f.write(json.dumps(asdict(r['result']), cls=sslyze.JsonEncoder))


    # Self-Signed
    a = []
    for r in results:
        if r['result'].scan_commands_results['certificate_info'].certificate_deployments[0].path_validation_results[0].openssl_error_string and 'self signed certificate' in r['result'].scan_commands_results['certificate_info'].certificate_deployments[0].path_validation_results[0].openssl_error_string:
                a.append(r['print'])
    printer('Self-Signed Certificate', a, verbose)

    # Deprecated Protocols - Report up to TLS 1.1
    # In the future we may need to add ScanCommand.TLS_1_2_CIPHER_SUITES and ScanCommand.TLS_1_3_CIPHER_SUITES
    a = []
    deprecated_protos = [ScanCommand.SSL_2_0_CIPHER_SUITES, ScanCommand.SSL_3_0_CIPHER_SUITES, ScanCommand.TLS_1_0_CIPHER_SUITES, ScanCommand.TLS_1_1_CIPHER_SUITES]
    for r in results:
        protos = []
        for proto in deprecated_protos:
            if proto in r['result'].scan_commands_results:
                if len(r['result'].scan_commands_results[proto].accepted_cipher_suites):
                    name,major,minor = r['result'].scan_commands_results[proto].tls_version_used.name.split('_')
                    protos.append(f'{name}v{major}.{minor}')
        if len(protos):
            a.append(r['print'] + '\t' + ', '.join(protos))
    printer('Deprecated Protocols', a, verbose)

    # Expired
    a = []
    for r in results:
        if datetime.datetime.now() > r['result'].scan_commands_results['certificate_info'].certificate_deployments[0].received_certificate_chain[0].not_valid_after:
            a.append(r['print'])
    printer('Expired Certificates', a, verbose)

    # Weak Signature
    a = []
    for r in results:
        if r['result'].scan_commands_results['certificate_info'].certificate_deployments[0].received_certificate_chain[0].signature_hash_algorithm.name in ['sha1', 'md5']:
            a.append(r['print'])
    printer('SHA1 Signature', a, verbose)

    # Weak RSA Length < 2048
    a = []
    for r in results:
        keysize = r['result'].scan_commands_results['certificate_info'].certificate_deployments[0].received_certificate_chain[0].public_key().key_size
        if keysize < 2048:
            a.append(f"{r['print']} {keysize} bits")
    printer('Insecure RSA Length', a, verbose)

    # Weak ciphers
    a = []
    all_protos = [
        #ScanCommand.SSL_2_0_CIPHER_SUITES, # already caught with depracated protocols
        #ScanCommand.SSL_3_0_CIPHER_SUITES, # already caught with depracated protocols
        ScanCommand.TLS_1_0_CIPHER_SUITES,
        ScanCommand.TLS_1_1_CIPHER_SUITES,
        ScanCommand.TLS_1_2_CIPHER_SUITES,
        ScanCommand.TLS_1_3_CIPHER_SUITES
    ]
    for r in results:
        ciphers = []
        for proto in all_protos:
            if proto in r['result'].scan_commands_results:
                for cipher in r['result'].scan_commands_results[proto].accepted_cipher_suites:
                    name = cipher.cipher_suite.openssl_name
                    if 'NULL' in name or 'EXP' in name or 'ADH' in name or 'AECDH' in name:
                        ciphers.append(name)
        if len(ciphers):
            # dedup ciphers
            ciphers = list(set(ciphers))
            a.append(f"{r['print']}\t{', '.join(ciphers)}")
    printer('Weak Ciphers', a, verbose)

    # Medium ciphers
    a = []
    for r in results:
        ciphers = []
        for proto in all_protos:
            if proto in r['result'].scan_commands_results:
                for cipher in r['result'].scan_commands_results[proto].accepted_cipher_suites:
                    name = cipher.cipher_suite.openssl_name
                    if 'DES' in name or 'RC4' in name:
                        ciphers.append(name)
        if len(ciphers):
            # dedup ciphers
            ciphers = list(set(ciphers))
            a.append(f"{r['print']}\t{', '.join(ciphers)}")
    printer('Medium Ciphers', a, verbose)

def main():
    parser = argparse.ArgumentParser(description='Get SSL/TTL Issues in a simple format')

    xml_group = parser.add_argument_group(title='Get targets from Nmap XML output')
    xml_group.add_argument('-x', dest='nmapxmls', nargs='+', type=argparse.FileType('r'), help="Nmap's XML files", metavar='nmap.xml')

    target_group = parser.add_argument_group(title='Target a host')
    target_group.add_argument('-t', dest='targets', nargs='+', type=str, help='Target host or host:port. If not port is specified the default will be 443.', metavar='host:port')

    parser.add_argument('-v', '--verbose', action='store_true', dest='verbose')

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

    CheckHosts(targets, args.verbose)

if __name__ == '__main__':
    main()
