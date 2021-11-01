#!/usr/bin/env python3
import sys
import argparse
import datetime
from datetime import datetime
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import os


try:
	import xmlstarlet
except:
	print('Missing module xmlstarlet. Please install with:\n  pip install --upgrade xmlstarlet')
	sys.exit()

#Silence warnings on bad certificates. Use sslyze-scan.py to check for those
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def NmapXmlToTargets(nxml):
	from subprocess import Popen, PIPE
	process = Popen(['xmlstarlet', 'select', '-T', '-t', '-m', '/nmaprun/host/ports/port/service[@name="http" or @name="https" or @name="ssl" or @tunnel="ssl" or @name="http-proxy" or @name="http-alt" or @name="oracleas-https" or @name="https-alt"]', '-v', '../../../child::address[1]/attribute::addr', '-o', ':', '-v', '../@portid', '-o', ':', '-v', '../child::state/attribute::state', '-n', nxml], stdout=PIPE, stderr=PIPE)
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
		if not 'open' in target:
			continue
		host, port, status = target.split(':')
		targets.append((host,port))
	return targets

def CheckHosts(targets, verbose=False):
	
	results =[]
	
	for host,port in targets:
		
		content_security_policy_protection = False
		x_frame_options = False
		strict_transport_security = False
		x_aspnet_version = False
		x_powered_by = False
		server = False

		if verbose:
			print(f'Testing {host}:{port}')
		
		if ('443' in port):
			url = 'https://' + host + ':' + port
		else:
			url = 'http://' + host + ':' + port

		connection_attempts = 0
		finished = False
		no_connection = False
		while not finished:
			try:
				r = requests.head(url, verify=False)
			except requests.ConnectionError:
				print("Connection Failed - network error or server refused connection to " + url)
				results.append({'host' : host, 'port': port, 'url' : url, 'success': False, 'reason': 'Connection Error'})
				finished = True
				no_connection = True
			except requests.Timeout:
				if connection_attempts >= 3:
					print("Connection Failed - Multiple timeouts connecting to "+ url)
					results.append({'host' : host, 'port': port, 'url' : url, 'success': False, 'reason': 'Timeouts'})
					finished = True
					no_connection = True
				else:
					Print("Timeout - Waiting to retry")
					connection_attempts = connection_attempts + 1
					sleep(5)

			except requests.TooManyRedirects:
				print("Error - Too many redirects when connecting to " + url + ". This shouldn't be possible with the 'HEAD' request used here. Please report this error.")
				results.append({'host' : host, 'port': port, 'url' : url, 'success': False, 'reason': 'Too Many Redirects'})
				finished = True
				no_connection = True
			except requests.HTTPError:
				#We really don't care if we got an error.
				#If there was an HTTP code, then we got headers
				#so we functionally treat this as a successful
				#request and move on.
				finished = True
				no_connection = True

			#successful request
			finished = True
				
		if no_connection:
			continue

		#end while not finished:
		#Checking for X-Frame-Options
		if 'X-Frame-Options' in r.headers:
			x_frame_options = True
		else:
			x_frame_options = False

		#Checking for Content-Security-Policy
		if 'Content-Security-Policy' in r.headers:
			content_security_policy_protection = True
		else:
			content_security_policy_protection = False

		#Checking for Strict-Transport-Security
		if 'https' in url:
			if 'Strict-Transport-Security' in r.headers:
				strict_transport_security = True
			else:
				strict_transport_security = False

		else:	
			#This is vacuously true. If it's vanilla http, HSTS doesn't matter
			strict_transport_security = True

		#checking for X-AspNet-Version:
		if 'X-AspNet-Version' in r.headers:
			x_aspnet_version = True
		else:
			x_aspnet_version = False

		#Checking for X-Powered-By:
		if 'X-Powered-By' in r.headers:
			x_powered_by = True
		else:
			x_powered_by = False
#Checking for Server
		if 'Server' in r.headers:
			server = True
		else:
			server = False
		
		results.append({'host' : host, 'port': port, 'url' : url, 'success': True, 'reason': 'OK', 'reason' : r.reason, 'status_code' : str(r.status_code), 'headers' : r.headers, 'content-security-policy' : content_security_policy_protection, 'x-frame-options' : x_frame_options, 'strict-transport-security' : strict_transport_security, 'x-aspnet-version' : x_aspnet_version, 'x-powered-by' : x_powered_by, 'server' : server})

		if verbose:
			print(str(r.status_code) + " " + r.reason)
			for key in list(r.headers.keys()):
				print(key + ": " + r.headers[key])
			print("\n\n")

			print("Content-Security-Policy: " + str(content_security_policy_protection))
			print("\n")
			print("X-Frame-Options: " + str(x_frame_options))
			print("\n")
			print("Strict-Transport-Security: " + str(strict_transport_security))
			print("\n")
			print("X-AspNet-Version: " + str(x_aspnet_version))
			print("\n")
			print("X-Powered-By: " + str(x_powered_by))
			print("\n")
			print("Server: " + str(server))
			print("\n")


	return results
		
def ProcessResults(results, run_time):

	full_results = open(run_time + "/full_headers.txt", "w")
	hsts_results = open(run_time + "/hsts.txt", "w")
	csp_results = open(run_time + "/content_security_policy.txt", "w")
	x_frame_results = open(run_time + "/x_frame.txt", "w")
	header_info_exposure_results = open(run_time + "/info_exposure.txt", "w")


	#Write file headers
	full_results.write("### Full headers from header-scan.py run at " + run_time + "\n")
	hsts_results.write("### HSTS results from header-scan.py run at " + run_time + "\n")
	hsts_results.write("### Servers listed here are missing HSTS headers and should be included in findings.\n")

	csp_results.write("### Content-Security-Policy results from header-scan.py run at " + run_time + "\n")
	csp_results.write("### Servers listed here are missing Content-Security-Policy headers and\n")
	csp_results.write("###should be included in findings.\n")

	x_frame_results.write("### X-Frame-Options results from header-scan.py run at " + run_time + "\n")
	x_frame_results.write("### Servers listed here are missing X-Frame-Options headers and\n")
	x_frame_results.write("### should be included in findings.\n")

	header_info_exposure_results.write("### Header info exposure results from header-scan.py run at " + run_time + "\n")
	header_info_exposure_results.write("### Servers listed here have one or more headers which may disclose sensitive data.\n")
	header_info_exposure_results.write("### You should review the results before adding these servers to your findings.\n")

	for result in results:
		if(result['success'] == False):
			continue
		full_results.write(result['url'] + "\n")
		full_results.write(result['status_code'] + " " + result['reason'] + "\n")
		for header in list(result['headers'].keys()):
			full_results.write(header + ": " + result['headers'][header] + "\n")
		full_results.write("\n\n")

		if not result['content-security-policy']:
			csp_results.write(result['host'] + ":" + result['port'] + " -  " + result['url'] + "\n")
			
		if not result['strict-transport-security']:
			hsts_results.write(result['host'] + ":" + result['port'] + " -  " + result['url'] + "\n")
			
		if not result['x-frame-options']:
			x_frame_results.write(result['host'] + ":" + result['port'] + " -  " + result['url'] + "\n")
			
		if result['server'] or result['x-aspnet-version'] or result['x-powered-by']:
			header_info_exposure_results.write(result['host'] + ":" + result['port'] + " -  " + result['url'] + "\n")
			if result['server']:
				header_info_exposure_results.write("^^^ Server: " + result['headers']['Server'] + "\n")
			if result['x-aspnet-version']:
				header_info_exposure_results.write("^^^ X-AspNet-Version: " + result['headers']['X-AspNet-Version'] + "\n")
			if result['x-powered-by']:
				header_info_exposure_results.write("^^^ X-Powered-By: " + result['headers']['X-Powered-By'] + "\n")
			header_info_exposure_results.write("\n")
			
		
	


def main():
	parser = argparse.ArgumentParser(description="Get HTTP header issues in a simple format. Header-scan checks for HSTS, CSP and X-Frame-Options headers, as well as well-known information disclosure in headers. Ports checked from nmap.xml files are 80, 443, 8080, 8000, 7443, and 8443.")

	xml_group = parser.add_argument_group(title='Get targets from Nmap XML output')
	xml_group.add_argument('-x', dest='nmapxmls', nargs='+', type=argparse.FileType('r'), help="Nmap's XML Files", metavar='nmap.xml')
 
	list_group = parser.add_argument_group(title='Get targets from file (one host per line)')
	list_group.add_argument('-f', dest='infile', nargs='+', type=argparse.FileType('r'), help="List of subdomains (host or host:port) to scan. If no port is specified the default will be 443.", metavar='targets.txt')

	target_group = parser.add_argument_group(title="Target a host")
	target_group.add_argument('-t', dest='targets', nargs='+', type=str, help='Target host or host:port. If no port is specified the default will be 443.', metavar='host:port')

	parser.add_argument('-v', '--verbose', action='store_true', dest='verbose')

	args = parser.parse_args()

	if not args.nmapxmls and not args.targets and not args.infile:
		parser.print_help()
		print('\nNo input file(s) or target(s) provided')
		sys.exit()
	
	targets= []

	# get individual items added on the command line
	if args.targets:
		for target in args.targets:
			if ':' in target:
				host, port = target.split(':')
				targets.append((host,port))
			else:
				targets.append((target, '443'))

	# get targets from xml
	if args.nmapxmls:
		for nxml in args.nmapxmls:
			targets.extend(NmapXmlToTargets(nxml.name))

	if args.infile:
		for target.strip in args.infile:
			if ':' in target:
				host, port = target.split(':')
				targets.append((host,port))
			else:
				targets.append((target, '443'))
            
	if len(targets) == 0:
		print('No targets')

	
	
	run_time = datetime.now().strftime('%m%d%y%H%M%S')
	if not os.path.exists('./' + run_time):
		try:
			os.makedirs('./' + run_time)
		except:
			print("Could not create output directory " + path + ". Exiting")
			exit(0)
		print(f'>>> Output files will be written to ./{run_time}/')
	else:
		print("Output directory " + path + "already exists. Exiting")
		exit(0)
	
	results = CheckHosts(targets, args.verbose)

	ProcessResults(results, run_time)

if __name__ == '__main__':
	main()
		
