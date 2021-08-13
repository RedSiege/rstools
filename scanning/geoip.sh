#!/bin/bash

if [ $# -ne 2 ] || [[ "$*" == -h ]] || [[ "$*" == --help ]]; then
    echo "Usage: $0 HOSTFILE OUTFILE"
    echo "This script get get list of the locations of systems in the HOSTFILE"
    echo "Output is tab delimited: host | source | coutry, state/prov"
    exit 0
fi

HOSTFILE=$1
OUTFILE=$2

if [[ -f `dirname "$0"`/ipgeolocation.key ]];then
    export APIKEY=`cat $(dirname "$0")/ipgeolocation.key | sed -r s/\s+//g`
    if [[ -z "$APIKEY" ]]; then
        echo 'invalid ipgeolocation.key' | tee $OUTFILE
    else
        rm $$OUTFILE 2>/dev/null
        while read IP; do echo -e $IP\\tipgeolocation.io\\t`curl -s "https://api.ipgeolocation.io/ipgeo?apiKey=$APIKEY&ip=$IP" | jq -jr '.country_code2 + ", " + .state_prov + "\n"'` | tee -a $OUTFILE; done < $HOSTFILE
    fi
else
    echo 'missing ipgeolocation.key' | tee $OUTFILE
fi

