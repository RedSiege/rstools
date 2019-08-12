#!/bin/bash
FILEBASE=$(date +%F_%H-%M-%S)
MASSCANRATE=15000
NMAPOPTIONS='-sV -T4 -sC'

# run the script with the list of target IPs or Networks

if [ $# -eq 0 ] || [[ "$*" == *-h* ]] || [[ "$*" == *--help* ]]; then
    echo "Usage: $0 ip_or_network..."
    exit 0
fi

# check if linux, then check iptables
if [[ "$OSTYPE" == "linux-gnu" ]]; then
    # must be root for masscan on linux
    if [[ $EUID -ne 0 ]]; then
       echo "This script must be run as root" 1>&2
       exit 1
    fi

    # drop 61000, assumes iptables is in use AND ENABLED!
    iptables -S | grep 'INPUT.*61000.*DROP' >/dev/null
    if [ $? -eq 1 ]; then
        echo "Adding firewall rule to drop traffic on port 61000"
        iptables -A INPUT -p tcp --dport 61000 -j DROP
    fi
fi

masscan --ports 0-65535 --rate $MASSCANRATE --src-port=61000 --output-format binary --output-filename $FILEBASE.masscan $*

# get the ports
masscan --readscan $FILEBASE.masscan | awk -F'[ /]' '{print $4}' | sort -unk 1 > $FILEBASE-ports.txt

# save the live hosts hosts
masscan --readscan $FILEBASE.masscan | awk '{print $6}' | sort -u > $FILEBASE-hosts.txt

echo
echo "Found `wc -l $FILEBASE-hosts.txt | awk '{print $1}'` live hosts"
echo "Found `wc -l $FILEBASE-ports.txt | awk '{print $1}'` listening ports"
echo

PORTS=`awk -v ORS=, '{ print $1 }' $FILEBASE-ports.txt | sed 's/,$//'`

COMMAND="nmap $NMAPOPTIONS -oA $FILEBASE -iL $FILEBASE-hosts.txt -p $PORTS"
echo "Running: $COMMAND"
$COMMAND
