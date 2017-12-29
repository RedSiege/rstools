#!/usr/bin/python

"""
This will will get the CN and any Subject alternate names from the hosts/port combinations provided.
The target can be a CIDR range
The search is done in a random order

Available from: https://github.com/RedSiege/rstools
"""

__author__ = "Tim Medin"
__copyright__ = "Copyright 2018, Red Siege"
__credits__ = ["Tim Medin"]
__license__ = "GPL"
__version__ = "1.0.0"
__maintainer__ = "Tim Medin"
__email__ = "tim@redsiege.com"
__contact__ = "tim@redsiege.com"
__status__ = "Production"

import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from netaddr import *
from socket import *

def getCertNames(ip, port, verbose=False):
	setdefaulttimeout(5)
	try:
		certstring = ssl.get_server_certificate((ip, port))
	except (error, timeout) as err:
		if verbose:
			print "No connection: {0}".format(err)
		return None
	der_cert = ssl.PEM_cert_to_DER_cert(certstring)
	cert = x509.load_der_x509_certificate(der_cert, default_backend())

	names = []

	cn = cert.subject.get_attributes_for_oid(x509.OID_COMMON_NAME)[0].value
	names.append(cn)

	try:
		sans = cert.extensions.get_extension_for_oid(x509.OID_SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
	except:
		sans = None

	if sans and len(sans):
		for san in sans:
			names.append(san)
			#print ip, san

	return names

def main():
	import argparse
	import itertools
	import random
	import sys

	parser = argparse.ArgumentParser(description='Get cert names from remote systems.')
	parser.add_argument('-t', '--target', metavar='TARGET', action='append', type=str, help='target name, address, or CIDR range')
	parser.add_argument('-p', '--port', metavar='PORT', action='append', type=int, help='ports to check (default: 443)')
	parser.add_argument('-r', '--random', action='store_false', help='disable randomization of ports and hosts')
	parser.add_argument('-v', '--verbose', action='store_true', help='verbose')
	args = parser.parse_args()

	if not (args.target and len(args.target)):
		print 'Needs at least 1 target!'
		parser.print_help()
		sys.exit(1)


	# get the IPs if rages
	addresses = []
	for t in args.target:
		addresses += list(IPNetwork(t))

	ports = args.port
	if not (ports and len(ports)):
		ports = [443]

	ipportcombo = [ [str(ip), port] for ip, port in itertools.product(addresses, ports)  ]

	# randomize the ports and IP addresses?
	if args.random:
		random.shuffle(ipportcombo)

	for x in ipportcombo:
		if args.verbose:
			print 'Checking: %s:%i' % (x[0], x[1])
		names = getCertNames(x[0], x[1], args.verbose)
		if names and len(names):
			for name in names:
				print x[0], x[1], name

if __name__ == '__main__':
	main()
