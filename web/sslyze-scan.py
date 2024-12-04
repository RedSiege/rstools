#!/usr/bin/env python3
import sys
import argparse
import datetime

GROUPSIZE = 20

from sslyze import *
import sslyze.errors

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
        #sorts based on IP address
        for s in sorted(data, key=lambda x: [int(i) if i.isdigit() else i for i in x.split(':')[0].split('.')]):
            print(s)
        print('Count: ' + str(len(data)))
    elif verbose:
        print('\n' + header)
        print('Count: 0')

def CheckHosts(targets, verbose=False):
    # omitting the commands will try all
    '''
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
    '''

    all_scan_requests = []

    # Chunking so the scanner can be nuked and restarted
    for host,port in targets:

        if verbose:
            print(f'Testing {host}:{port}')

        server_location = ServerNetworkLocation(host, port)

        
        # add a try catch here maybe?
        req = ServerScanRequest(server_location)

        all_scan_requests.append(req)

    scanner = Scanner()

    scanner.queue_scans(all_scan_requests)
        
    '''
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
    '''

    results = []

    for r in scanner.get_results():

        if r.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
            # can't connect
            print(
                f"\nError: Could not connect to {r.server_location.hostname}:"
                f" {r.connectivity_error_trace}"
            )
            continue
        elif r.scan_result.certificate_info.status == ScanCommandAttemptStatusEnum.ERROR:
            # unknown error
            print(
                f"\nError: unknown error connecting to {r.server_location.hostname}:"
                f" {r.connectivity_error_trace}"
            )
            continue

        results.append({
            'ip': r.server_location.ip_address,
            'port': r.server_location.port,
            'print': (r.server_location.ip_address + ':' + str(r.server_location.port)),
            'result': r
        })

        if verbose:
            print('Tested ' + r.server_location.ip_address + ':' + str(r.server_location.port))

    #if export:
    #    for i, r in enumerate(results):
    #        with open(f"{r['print']}-{i}.json", 'w') as f:
    #            f.write(json.dumps(asdict(r['result']), cls=sslyze.JsonEncoder))


    # Self-Signed
    a = []
    for r in results:
        #if r['result'].scan_result.certificate_info.result.certificate_deployments[0].path_validation_results[0].openssl_error_string and 'self signed certificate' in r['result'].scan_result['certificate_info'].certificate_deployments[0].path_validation_results[0].openssl_error_string:
        if r['result'].scan_result.certificate_info.result.certificate_deployments[0].path_validation_results[0].validation_error:
            a.append(r['print'])
    printer('Untrusted Certificates (Likely Self-Signed, please confirm!)', a, verbose)


    # Deprecated Protocols - Report up to TLS 1.1
    # In the future we may need to add ScanCommand.TLS_1_2_CIPHER_SUITES and ScanCommand.TLS_1_3_CIPHER_SUITES
    a = []
    deprecated_protos = [ScanCommand.SSL_2_0_CIPHER_SUITES, ScanCommand.SSL_3_0_CIPHER_SUITES, ScanCommand.TLS_1_0_CIPHER_SUITES, ScanCommand.TLS_1_1_CIPHER_SUITES]
    for r in results:
        protos = []
        for proto in deprecated_protos:
            if hasattr(r['result'].scan_result, proto.value):
                if hasattr(getattr(r['result'].scan_result, proto.value).result, 'accepted_cipher_suites') and len(getattr(r['result'].scan_result, proto.value).result.accepted_cipher_suites):
                    name,major,minor = getattr(r['result'].scan_result, proto.value).result.tls_version_used.name.split('_')
                    protos.append(f'{name}v{major}.{minor}')
        if len(protos):
            a.append(r['print'] + '\t' + ', '.join(protos))
    printer('Deprecated Protocols', a, verbose)

    # Expired
    a = []
    for r in results:
        if datetime.datetime.now(datetime.UTC) > r['result'].scan_result.certificate_info.result.certificate_deployments[0].received_certificate_chain[0].not_valid_after_utc:
            #stores date_time
            expired_time=r['result'].scan_result.certificate_info.result.certificate_deployments[0].received_certificate_chain[0].not_valid_after_utc
            #adds formatted date time
            a.append(r['print']+'\t'+expired_time.strftime('%b %d, %Y'))
    printer('Expired Certificates', a, verbose)

    # Weak Signature
    a = []
    for r in results:
        hashalgo = r['result'].scan_result.certificate_info.result.certificate_deployments[0].received_certificate_chain[0].signature_hash_algorithm.name
        if hashalgo in ['sha1', 'md5']:
            a.append(f"{r['print']}\t{hashalgo}")
    printer('Weak Signature', a, verbose)

    # Weak RSA Length < 2048
    a = []
    if not hasattr(r['result'].scan_result, 'elliptic_curves'):
        for r in results:
            keysize = r['result'].scan_result.certificate_info.result.certificate_deployments[0].received_certificate_chain[0].public_key().key_size
            if keysize < 2048:
                a.append(f"{r['print']}\t{keysize} bits")
        printer('Insecure RSA Length', a, verbose)

    # Weak ECC Length < 256
    a = []
    if hasattr(r['result'].scan_result, 'elliptic_curves'):
        for r in results:
            keysize = r['result'].scan_result.certificate_info.result.certificate_deployments[0].received_certificate_chain[0].public_key().key_size
            if keysize < 256:
                a.append(f"{r['print']}\t{keysize} bits")
    printer('Insecure ECC Length', a, verbose)

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
            if hasattr(r['result'].scan_result, proto.value):
                for cipher in getattr(r['result'].scan_result, proto.value).result.accepted_cipher_suites:
                    name = cipher.cipher_suite.openssl_name
                    if 'NULL' in name or 'EXP' in name or 'ADH' in name or 'AECDH' in name or getattr(r['result'].scan_result, proto.value).result.accepted_cipher_suites[0].cipher_suite.key_size <= 64:
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
            if hasattr(r['result'].scan_result, proto.value):
                for cipher in getattr(r['result'].scan_result, proto.value).result.accepted_cipher_suites:
                    name = cipher.cipher_suite.openssl_name
                    if 'DES' in name or 'RC4' in name or 64 < getattr(r['result'].scan_result, proto.value).result.accepted_cipher_suites[0].cipher_suite.key_size <= 112:
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
    
