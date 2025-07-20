function Set-StaticIP {
    param ($IPAddress, $DNS, $Gateway)
    $adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    New-NetIPAddress -InterfaceAlias $adapter.Name -IPAddress $IPAddress -PrefixLength 24 -DefaultGateway $Gateway
    Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses $DNS
}