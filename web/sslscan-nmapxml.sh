#!/bin/bash

SSLSCANPATH=sslscan

if [ $# -ne 1 ] || [[ "$*" == *-h* ]] || [[ "$*" == *--help* ]]; then
    echo "Usage: $0 nmap.xml"
    exit 1
fi

if [[ ! $1 == *xml ]]; then
        echo "Not an .xml file"
        exit 1
fi

if [[ ! -f $1 ]]; then
        echo "File $1 does not exist"
        exit 1
fi

TARGETS=`xmlstarlet sel -T -t -m '/nmaprun/host/ports/port/service[@name="https" or @name="ssl" or @tunnel="ssl"]' -v "../../../child::address/attribute::addr" -o : -v "../@portid" -n "$1"`

for TARGET in $TARGETS
do
        FILENAME=`echo $TARGET | sed -e 's/:/_/g'`.xml
        FILENAMES="$FILENAMES $FILENAME"

        if [ -f $FILENAME ]; then
                echo "File $FILENAME already exists, skipping..."
        else
                echo "Running: $SSLSCANPATH --xml=$FILENAME $TARGET"
                $SSLSCANPATH --xml=$FILENAME $TARGET >/dev/null
        fi

        # self-signed check
        grep '<self-signed>true</self-signed>' $FILENAME >/dev/null && SELFSIGNED="$SELFSIGNED^$TARGET"
        # expired
        grep '<expired>true</expired>' $FILENAME >/dev/null && EXPIRED="$EXPIRED^$TARGET"
        # sha1 sig
        grep -ie '<signature-algorithm>.*sha1.*</signature-algorithm>' $FILENAME >/dev/null && SHA1SIG="$SHA1SIG^$TARGET"
        # Weak RSA Length
        WEAKRSA_TEMP=`xmlstarlet sel -T -t -m "///certificate/pk[@bits<2048]" -v @bits $FILENAME`
        [[ ! -z $WEAKRSA_TEMP ]] && WEAKRSA="$WEAKRSA^$TARGET $WEAKRSA_TEMP bits RSA"
        # Depracated protocols
        DEPPROTOS=`xmlstarlet sel -T -t -m "//ssltest/cipher[contains(@sslversion, 'SSL') or @sslversion='TLSv1.0' or @sslversion='TLSv1.1']" -v '@sslversion' -n $FILENAME | sort -uV`
        FIRST=true
        for DEPPROTO_TEMP in $DEPPROTOS
        do
                if [ "$FIRST" = true ]; then
                        DEPPROTO="$DEPPROTO^$TARGET $DEPPROTO_TEMP"
                        FIRST=false
                else
                        DEPPROTO="$DEPPROTO, $DEPPROTO_TEMP"
                fi
        done
        # Weak Ciphers
        WEAKCIPHERS=`xmlstarlet sel -T -t -m "//ssltest/cipher[contains(@cipher,'NULL') or contains(@cipher,'EXP') or contains(@cipher,'ADH') or contains(@cipher,'AECDH') and not(contains(@sslversion,'SSL'))]" -v @sslversion -o ":" -v @cipher -n -b $FILENAME | cut -d: -f 2 | sort -u`
        FIRST=true
        for WEAKCIPHER_TEMP in $WEAKCIPHERS
        do
                if [ "$FIRST" = true ]; then
                        WEAKCIPHER="$WEAKCIPHER^$TARGET $WEAKCIPHER_TEMP"
                        FIRST=false
                else
                        WEAKCIPHER="$WEAKCIPHER, $WEAKCIPHER_TEMP"
                fi
        done

        # Medium Strength Ciphers
        MEDIUMCIPHERS=`xmlstarlet sel -T -t -m "//ssltest/cipher[contains(@cipher,'DES') or contains(@cipher,'RC4') or contains(@cipher,'ADH') or contains(@cipher,'AECDH') and not(contains(@sslversion,'SSL'))]" -v @sslversion -o ":" -v @cipher -n -b $FILENAME | cut -d: -f 2 | sort -u`
        FIRST=true
        for MEDIUMCIPHER_TEMP in $MEDIUMCIPHERS
        do
                if [ "$FIRST" = true ]; then
                        MEDIUMCIPHER="$MEDIUMCIPHER^$TARGET $MEDIUMCIPHER_TEMP"
                        FIRST=false
                else
                        MEDIUMCIPHER="$MEDIUMCIPHER, $MEDIUMCIPHER_TEMP"
                fi
        done

done

echo
echo "Self-signed"
[ ! -z "$SELFSIGNED" ] && echo "${SELFSIGNED:1}" | tr '^' '\n' | sort -uV || echo None
echo
echo "Expired"
[ ! -z "$EXPIRED" ] && echo "${EXPIRED:1}" | tr '^' '\n' | sort -uV || echo None
echo
echo "Weak RSA"
[ ! -z "$WEAKRSA" ] && echo "${WEAKRSA:1}" | tr '^' '\n' | sort -uV || echo None
echo
echo "Deprected Protocols"
[ ! -z "$DEPPROTO" ] && echo "${DEPPROTO:1}" | tr '^' '\n' | sort -uV || echo None
echo
echo "Weak Ciphers"
[ ! -z "$WEAKCIPHER" ] && echo "${WEAKCIPHER:1}" | tr '^' '\n' | sort -uV || echo None
echo
echo "Medium Ciphers"
[ ! -z "$MEDIUMCIPHER" ] && echo "${MEDIUMCIPHER:1}" | tr '^' '\n' | sort -uV || echo None
echo


exit 1


xmlstarlet sel -T -t -m //ssltest -o 'Target: ' -v @host -o ':' -v @port -n \
        -i "///certificate/self-signed[text()='true']" -o 'Self-signed Certificate' -n -b \
        -i "///certificate/expired[text()='true']" -o 'Expired Certificate' -n -b \
        -i "///certificate/signature-algorithm[contains(text(), 'sha1')]" -o 'Bad Certificate Signature Algorithm: SHA1' -n -b \
        -m "///certificate/pk[@bits<2048]" -o 'Weak RSA ' -v @bits -o ' bits' -n \
        $1
xmlstarlet sel -T -t \
        -i "//ssltest/cipher[contains(sslversion, 'SSL') or @sslversion='TLSv1.0' or @sslversion='TLSv1.1']" -o 'Deprecated Protocols:' -n -b \
        -m "//ssltest/cipher[contains(sslversion, 'SSL') or @sslversion='TLSv1.0' or @sslversion='TLSv1.1']" -v '@sslversion' -n -b \
        $1 \
        | sort -u
xmlstarlet sel -T -t \
        -i "//ssltest/cipher[contains(@cipher,'NULL') or contains(@cipher,'EXP') or contains(@cipher,'ADH') or contains(@cipher,'AECDH') and (contains(@sslversion,'TLSv1.0') or contains(@sslversion,'TLSv1.1') or contains(@sslversion,'TLSv1.2'))]" -o 'Red Ciphers' -n -b \
        $1
xmlstarlet sel -T -t \
        -m "//ssltest/cipher[contains(@cipher,'NULL') or contains(@cipher,'EXP') or contains(@cipher,'ADH') or contains(@cipher,'AECDH') and (contains(@sslversion,'TLSv1.0') or contains(@sslversion,'TLSv1.1') or contains(@sslversion,'TLSv1.2'))]" -v @sslversion -o ":" -v @cipher -n -b \
        $1 \
        | cut -d: -f 2

xmlstarlet sel -T -t \
        -i "//ssltest/cipher[contains(@cipher,'RC4') or contains(@cipher,'RC4')]" -o 'Yellow Ciphers' -n -b \
        $1
xmlstarlet sel -T -t \
        -m "//ssltest/cipher[(contains(@cipher,'RC4') or contains(@cipher,'RC4')) and (contains(@sslversion,'TLSv1.0') or contains(@sslversion,'TLSv1.1') or contains(@sslversion,'TLSv1.2'))]" -v @sslversion -o ":" -v @cipher -n -b \
        $1 \
        | cut -d: -f 2 | sort -u
