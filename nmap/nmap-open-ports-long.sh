#!/bin/sh
#title           :nmap-open-ports-long.sh
#description     :Extract tab delimited table (ip, name, port, service, version) from Nmap XML output
#author          :Tim Medin @TimMedin tim@redsiege.com
#date            :20171229
#version         :1.0
#usage           :nmap-open-ports-long.sh nmap-results.xml
#repository      :https://github.com/RedSiege/rstools
#notes           :Install xmlstarlet. Based on https://gist.github.com/bdpuk/4587372

if [ -z "$1" ]; then
  echo "You must supply an Nmap xml file"
  exit
fi

xmlstarlet sel -T -t -m "//state[@state='open']" -m ../../.. -v 'address[not(@addrtype="mac")]/@addr' -o "	" -m hostnames/hostname -i @name -v @name -b -b -b -o "	" -m .. -v @portid -o '/' -v @protocol -o "	" -m service -v @name -i "@tunnel='ssl'" -o 's' -b -o "	" -v @product -o ' ' -v @version -v @extrainfo -b -n $1
