$hostname = (Invoke-RestMethod -Uri http://169.254.169.254/latest/meta-data/local-hostname).Split(".")[0]
$config = Get-Content "$PSScriptRoot\`$hostname-config.json" | ConvertFrom-Json

. "$PSScriptRoot\Modules\InitializeAndFormatDisks.ps1"
Rename-ComputerSafely -NewName $config.ComputerName

. "$PSScriptRoot\Modules\Rename-Computer.ps1"
Rename-ComputerSafely -NewName $config.ComputerName

. "$PSScriptRoot\Modules\Set-Network.ps1"
Set-StaticIP -IPAddress $config.IPAddress -DNS $config.DNS -Gateway $config.Gateway

. "$PSScriptRoot\Modules\Join-Domain.ps1"
Join-DomainSafely -Domain $config.Domain -OU $config.OU

New-Item "C:\Bootstrap\RunSQL.flag" -Force | Out-Null
Restart-Computer -Force