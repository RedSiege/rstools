#!/usr/bin/python

"""
Extract "LI" user info from burp output

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

from lxml import etree
import base64
import json
import re
import jsonpath
import sys

if len(sys.argv) != 2:
	print 'You must specify a burp XML file'
	sys.exit(1)

tree = etree.parse(sys.argv[1])

print '%s\t%s\t%s\t%s' % ('firstName', 'lastName', 'occupation', 'profile link')

for o in tree.xpath('item/url[text()="https://www.linkedin.com/voyager/api/mux"]/../response'):
	resp = base64.b64decode(o.text)
	# get json
	jsonstr = resp.splitlines()[-1]
	# check it it contains user info
	if re.search(r'"firstName"', jsonstr):
		j = json.loads(jsonstr)
		search = jsonpath.jsonpath(j, "$..[?(@.firstName)]")
		if search:
			for u in search:
				print '%s\t%s\t%s\thttps://www.linkedin.com/in/%s' % (u['firstName'], u['lastName'], u['occupation'], u['publicIdentifier'])
