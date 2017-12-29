function Get-SSLNames {
<#
    .SYNOPSIS
        Get names from web server's certificate
    .DESCRIPTION
        Access the targeted SSL/TLS server and extract names from the certificate
    .NOTES
        Author: Tim Medin, Red Siege, tim@redsiege.com
    .LINK
        https://github.com/RedSiege/rstools 
    .LINK
        https://redsiege.com
    .EXAMPLE
        Get-SSLNames 192.168.8.2
    .EXAMPLE
        "192.168.8.2" | Get-SSLNames
#>

[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [string[]]$Targets,

        [Parameter(Position = 1)]
        [ValidateRange(1,65535)]
        [int[]]$Ports = 443,

        [Parameter(Position = 2)]
        [int]$Timeout = 3000
    )

    # convert targets to IP Addresses
    $IPs = @()
    foreach ($Target in $Targets) {
        # Is it an IP Address?
        try {
            $IP = [ipaddress]$Target
            $IPS += $IP
        } catch {
            # not an IP
            [System.Net.Dns]::GetHostAddresses($Target) | % {
                $IPS += $_
            }
        }
    }

    $results = foreach ($IP in $IPs) {
        foreach ($Port in $Ports) {
            Get-SSLNamesObject -Target $IP -Port $Port -Timeout $Timeout -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AllNames | % {
                $ht = [ordered]@{
                    Name = $_
                    IPAddress = $IP;
                    Port = $Port;
                }
                New-Object -TypeName PSObject -Property $ht
            }
        }
    }
    $results
}

function Get-SSLNamesObject {
[CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [string]$Target,

        [Parameter(Position = 1)]
        [ValidateRange(1,65535)]
        [int]$Port = 443,

        [Parameter(Position = 2)]
        [int]$Timeout = 3000
    )


    # get the connection
    $ConnectString = "https://$target`:$port"
    $WebRequest = [Net.WebRequest]::Create($ConnectString)
    $WebRequest.Timeout = $Timeout
    #$WebRequest.AllowAutoRedirect = $true
    [Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    try {$Response = $WebRequest.GetResponse()}
    catch {}

    # attempt to get the cert
    if ($WebRequest.ServicePoint.Certificate -ne $null) {
        $Cert = [Security.Cryptography.X509Certificates.X509Certificate2]$WebRequest.ServicePoint.Certificate.Handle
        try {$SAN = ($Cert.Extensions | Where-Object {$_.Oid.Value -eq "2.5.29.17"}).Format(0) -split ", "}
        catch {$SAN = $null}

        # make the CN pretty
        $Subject = $WebRequest.ServicePoint.Certificate.Subject
        # set the $Matches object
        $Subject -match'(?<=CN=)[^,]+' | Out-Null
        $CN = $Matches[0]

        $AllNames = @($CN)

        # fix the SAN
        if ($SAN) {
            $SANPretty = $SAN | % { $_ -replace "DNS Name=", "" }
            $AllNames += $SANPretty
            $AllNames = $AllNames | select -uniq
        }

        New-Object -TypeName PSObject -Property @{
            CommonName = $CN;
            SubjectAlternativeNames = $SANPretty;
            AllNames = $AllNames;
        }

        [Net.ServicePointManager]::ServerCertificateValidationCallback = $null

    } else {
         Write-Error $Error[0]
    }
}
0
