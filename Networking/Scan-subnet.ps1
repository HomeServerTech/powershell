
$Subnet = read-host "Input First 3 octets of Subnet (example 192.168.1)"

workflow Scan-Subnet {
[cmdletbinding()]
    param(
        [int]$ThrottleLimit = 10
        )
$IPAddresses = @()
foreach -parallel -throttlelimit $ThrottleLimit ($ip in 1..254){
    $ping = New-Object System.Net.Networkinformation.Ping
    
      if(Test-Connection $ip -Quiet -count 1 -EA SilentlyContinue){
        $IPSuccess
        $WORKFLOW:IPAddresses = $WORKFLOW:IPAddresses + $IPSuccess
      }
    } # end foreach -parallel
$IPAddresses
} # end workflow Scan-Subnet

Scan-Subnet
