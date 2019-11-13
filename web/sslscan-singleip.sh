#!/bin/bash

xmlstarlet sel -T -t -m //ssltest -o 'Target: ' -v @host -o ':' -v @port -n \
        -i "///certificate/self-signed[text()='true']" -o 'Self-signbed Certificate' -n -b \
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
