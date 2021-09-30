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

## Azure

### adss-spray.py

Tool for performing Azure AD user enumeration and password spraying via the Azure AD Seamless SSO endpoint.

```
usage: adsso-spray.py [-h] [-d DOMAIN] [-l USER_LIST] [-u URL] [-w WAIT] [-p PASSWORD] [-v] [-vv]
                      [-o OUTPUT_FILE]

Enumerate users or password spray against Azure AD Seamless SSO

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose
  -vv, --more-verbose
  -o OUTPUT_FILE, --output OUTPUT_FILE
                        Output file for results (csv). Default is spray_results.csv

Attack Target:
  -d DOMAIN             Target domain - required
  -l USER_LIST          File with list of target usernames (without domain)
  -u URL, --url URL     Target URL if using something like fireprox; otherwise will directly call
                        the Azure AD SeamlessSSO endpoint
  -w WAIT, --wait WAIT  Number of seconds to sleep between individual user attempts

Password Group:
  -p PASSWORD, --password PASSWORD
                        password to spray. Defaults to "notarealpassword,Iswear".
```
