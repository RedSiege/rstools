#!/bin/sh

#title           :nmap-open-ports-simple-by-hostname.sh
#description     :Extract Hostname:Port from Nmap XML output
#author          :Brandon Scholet @brandonscholet brandon@redsiege.com
#date            :20230725
#version         :1.0
#usage           :nmap-open-ports-simple-by-hostname.sh nmap-results.xml
#repository      :https://github.com/RedSiege/rstools
#notes           :Install xmlstarlet. Based on https://gist.github.com/erikvip/7a8972a4571ccb6639a2

if [ -z "$1" ]; then
  echo "You must supply an Nmap xml file"
  exit
fi

xmlstarlet sel -t -m '//port/state[@state="open"]/parent::port' -v 'ancestor::host/hostnames/hostname[@type="user"]/@name' -o : -v './@portid' -n "$1"

