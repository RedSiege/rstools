xmlstarlet sel -T -t -m //ssltest -o 'Target: ' -v @host -o ':' -v @port -n \
-i "///certificate/self-signed[text()='true']" -o 'Self-signbed Certificate' -n -b \
-i "///certificate/expired[text()='true']" -o 'Expired Certificate' -n -b \
-i "///certificate/signature-algorithm[contains(text(), 'sha1')]" -o 'Bad Certificate Signature Algorithm: SHA1' -n -b \
-m "///certificate/pk[@bits<2048]" -o 'Weak RSA ' -v @bits -o ' bits' -n -b \
-i "//heartbleed[contains(sslversion, 'SSL') or @sslversion='TLSv1.0' or @sslversion='TLSv1.1' or @sslversion='TLSv1.2']" -o 'Depracated Protocols:' -n -b \
-m "//heartbleed[contains(sslversion, 'SSL') or @sslversion='TLSv1.0' or @sslversion='TLSv1.1' or @sslversion='TLSv1.2']" -v @sslversion -n -b \
-i "//ssltest/cipher[contains(@cipher,'NULL') or contains(@cipher,'EXP') or contains(@cipher,'ADH') or contains(@cipher,'AECDH')]" -o 'Red Ciphers:' -n -b \
-m "//ssltest/cipher[contains(@cipher,'NULL') or contains(@cipher,'EXP') or contains(@cipher,'ADH') or contains(@cipher,'AECDH')]" -v @cipher -n -b \
-i "//ssltest/cipher[contains(@cipher,'RC4') or contains(@cipher,'RC4')]" -o 'Yellow Ciphers' -n -b \
-m "//ssltest/cipher[contains(@cipher,'RC4') or contains(@cipher,'RC4')]" -v @cipher -n -b \
blah.xml