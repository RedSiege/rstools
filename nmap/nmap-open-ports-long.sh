#!/bin/sh
# based on https://gist.github.com/bdpuk/4587372

if [ -z "$1" ]; then
  echo "You must supply an Nmap xml file"
  exit
fi

xmlstarlet sel -T -t -m "//state[@state='open']" -m ../../.. -v 'address[not(@addrtype="mac")]/@addr' -o "	" -m hostnames/hostname -i @name -v @name -b -b -b -o "	" -m .. -v @portid -o '/' -v @protocol -o "	" -m service -v @name -i "@tunnel='ssl'" -o 's' -b -o "	" -v @product -o ' ' -v @version -v @extrainfo -b -n $1
