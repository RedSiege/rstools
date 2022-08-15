#!/usr/bin/python3
# encoding=utf8
# 
# Parse the password last set date and enabled status from BloodHound output.
# Original source: https://raw.githubusercontent.com/addenial/scripts/master/bloodhound-users-json-parser.py

import sys
import datetime
import simplejson

if len(sys.argv) == 1:
    print ("Usage: " + sys.argv[0] + " bloodhound_users.json")
    sys.exit()

bhuserfile = sys.argv[1]
with open(bhuserfile) as data_file:
    data = simplejson.load(data_file)

print ("name,enabled,pwlastset")
for i in data['users']:
    oname = i['Properties']['name'] 
    oenabled = i['Properties']['enabled']
    odisplay = i['Properties']['displayname']
    odescription = i['Properties']['description']
    opwage = i['Properties']['pwdlastset']
    pwage = datetime.date.fromtimestamp(opwage) 
    print("%s,%s," %(oname,oenabled),pwage.strftime("%m/%d/%y"))
