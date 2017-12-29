#!/bin/sh
# based on https://gist.github.com/erikvip/7a8972a4571ccb6639a2

if [ -z "$1" ]; then
  echo "You must supply an Nmap xml file"
  exit
fi

xmlstarlet sel -t -m '//port/state[@state="open"]/parent::port' -v 'ancestor::host/address[not(@addrtype="mac")]/@addr' -o : -v './@portid' -n $1

