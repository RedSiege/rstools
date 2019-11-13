#!/bin/sh

#title           :nmap-open-ports-count.sh
#description     :Extract open port count from Nmap XML output
#author          :Tim Medin @TimMedin tim@redsiege.com
#date            :20171229
#version         :1.0
#usage           :nmap-open-ports-count.sh nmap-results.xml
#repository      :https://github.com/RedSiege/rstools
#notes           :Install xmlstarlet. Based on https://gist.github.com/erikvip/7a8972a4571ccb6639a2

if [ -z "$1" ]; then
  echo "You must supply an Nmap xml file"
  exit
fi

xmlstarlet sel -t -m '//port/state[@state="open"]/parent::port' -v 'ancestor::host/address[not(@addrtype="mac")]/@addr' -o : -v './@portid' -n "$1" | cut -d: -f2 | sort | uniq -c | sort -nr -k 1

