#!/bin/bash
#FILEBASE=$(date +%F_%H-%M-%S)
FILEBASE=scan-$(date +%F_%H-%M-%S)
MASSCANRATE=15000
NMAPOPTIONS='-sV -T4 -sC'

# run the script with the list of target IPs or Networks

if [ $# -ne 1 ] || [[ "$*" == *-h* ]] || [[ "$*" == *--help* ]]; then
    echo "Usage: $0 targetfile.txt"
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

masscan --ports 0-65535 --rate $MASSCANRATE --src-port=61000 --output-format binary --output-filename $FILEBASE.masscan -iL $1

# convert to grepable
masscan --open --readscan $FILEBASE.masscan -oG $FILEBASE.grep
echo

# get the ports
grep /open/ $FILEBASE.grep | cut -d ' ' -f 4 | cut -d / -f 1 | sort -nk 1 | uniq > $FILEBASE-ports.txt
echo "`wc -l < $FILEBASE-ports.txt` open ports"

# save the live hosts hosts
grep /open/ $FILEBASE.grep | cut -d ' ' -f 2 | sort -uV > $FILEBASE-hosts.txt
echo "`wc -l < $FILEBASE-hosts.txt` live hosts"

# host-port
grep /open/ $FILEBASE.grep | cut -d/ -f 1 | cut -d ' ' -f 2,4 | sed -e 's/ /:/g' | sort -uV > $FILEBASE-host-port.txt
echo "`wc -l < $FILEBASE-host-port.txt` listening services"

# condense the ports to a range
#PORTS=`awk -v ORS=, '{ print $1 }' $FILEBASE-ports.txt | sed 's/,$//'`
PORTS=`awk -v ORS=, '
    NR==1{
        o=$1
        f=$1+1
        next }
    f!=$1{
        if (o==f-1) {
            print o
        } else {
            print o "-" f-1
        }
        o=$1
        f=$1+1
        next }
    {
        f=f+1
        }
    END{
        if (o==f-1) {
            print o
        } else {
            print o "-" f-1
        }}
' $FILEBASE-ports.txt | sed 's/,$//'`

COMMAND="nmap $NMAPOPTIONS -oA $FILEBASE -iL $FILEBASE-hosts.txt -p $PORTS"
echo "Running: $COMMAND"
$COMMAND
