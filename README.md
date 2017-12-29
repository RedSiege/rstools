# RSTools

## Nmap

### nmap-open-ports-simple.sh
Get a simple list of IP:Port from Nmap XML. Requires `xmlstarlet`.

```
nmap-open-ports-simple.sh nmap-results.xml
192.168.1.1:80
192.168.1.1:443
192.168.1.100:22
192.168.1.200:445
```

### nmap-open-ports-long.sh
Get table delimited table of IP, DNS name, Port, Protocol, Detected Service from Nmap XML. Requires `xmlstarlet`.

```
nmap-open-ports-long.sh nmap-results.xml
```
|               |                    |         |          |                         |
| ------------- | ------------------ | ------- | -------- | ----------------------- |
| 192.168.1.1   | alpha.redsiege.com | 22/tcp  | ssh      | OpenSSH 7.4protocol 2.0 |
| 192.168.1.1   | alpha.redsiege.com | 443/tcp | ssl/http | nginx 1.12.2            |
| 192.168.1.100 | bravo.redsiege.com | 22/tcp  | ssh      | OpenSSH 7.4protocol 2.0 |
    
## Web

### GetNamesFromServerCert.py

Gets the Common Name and Subject Alternate Names from a certificate.

Takes targets (-t) in IP, FQDN, or CIDR format and combines them with ports (-p) and extracts the CN and the Subject Altrnate Names from the certificate. By default, the script will randomize the host and ports but it can be disabled with -r. The -v option can be used to show the verbose actions.

### GetNamesFromServerCert.ps1

Gets the Common Name and Subject Alternate Names from a certificate.

Similar to GetNamesFromServerCert.py but for PowerShell. Parameters are `-Targets` and `-Ports`.
