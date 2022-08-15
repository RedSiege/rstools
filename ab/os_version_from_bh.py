#!/usr/bin/python3
# encoding=utf8
# 
# parse OS version, object enabled status, hostname, and password last set date for computer objects

import sys
import datetime
import simplejson

if len(sys.argv) == 1:
    print ("Usage: " + sys.argv[0] + " bloodhound_computers.json")
    sys.exit()

bhuserfile = sys.argv[1]
with open(bhuserfile) as data_file:
    data = simplejson.load(data_file)


print ("name,enabled,operatingsystem,pwlastset")
for i in data['computers']:
    oname = i['Properties']['name'] 
    oenabled = i['Properties']['enabled']
    os = i['Properties']['operatingsystem']
    opwage = i['Properties']['pwdlastset']
    pwage = datetime.date.fromtimestamp(opwage) 
    print("%s,%s,%s," %(oname,oenabled,os),pwage.strftime("%m/%d/%y"))
