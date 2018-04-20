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

# Standard Libarries
import base64
import json
import re
import sys
import argparse
import csv

# Third Party Libaries
from lxml import etree
import jsonpath


def main():
    # Create CSV file if option is present
    if csv:
        output_data = open("{}_output.csv".format(sys.argv[0].split('.')[0]), 'w')
        csvwriter = csv.writer(output_data)

    # URL to search for in Burp XML output
    request_url = 'https://www.linkedin.com/voyager/api/search/cluster'

    # Ensure a file is passed in
    if not input_file:
        print('You must specify a Burp XML file')
        sys.exit(1)

    tree = etree.parse(sys.argv[1])

    # Output header
    print("{0:20}{1:20}{2:40}{3:50}".format('firstName', 'lastName',
                                            'occupation', 'profile link'))

    # Parse Burp XML file for the specific URL and then extract data
    xpath_filter_string = "item/url[contains(text(), '{}')]/../response".format(request_url)
    for o in tree.xpath(xpath_filter_string):
        resp = base64.b64decode(o.text)
        # get json
        jsonstr = resp.splitlines()[-1].decode('utf-8')
        # check it it contains user info
        if re.search(r'"firstName"', jsonstr):
            j = json.loads(jsonstr)
            search = jsonpath.jsonpath(j, "$..[?(@.firstName)]")
            count = 0
            if search:
                for u in search:
                    print("{0:20}{1:20}{2:40}{3:50}".format(
                        u['firstName'],
                        u['lastName'],
                        u['occupation'],
                        'lhttps://www.linkedin.com/in/' + u['publicIdentifier']))
                    if csv:
                        if count == 0:
                            header = u.keys()
                            csvwriter.writerow(header)
                            count += 1
                        csvwriter.writerow(u.values())


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Parse LinkedIn search results from Burp XML Export')
    parser.add_argument('-c', dest='csv_option', action='store_true',
                        default=False,
                        help='Output as CSV instead of STDOUT with ALL fields')
    parser.add_argument('input_file')
    args = parser.parse_args()

    csv_option = args.csv_option
    input_file = args.input_file

    main()
