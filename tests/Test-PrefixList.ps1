$PSModulesPath = "C:\github\psmodules"  # Adjust this path to your actual PSModulesPath
# Import necessary AWS Tools modules

Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.Common") -ErrorAction Stop
Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.EC2") -ErrorAction Stop
Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.SecurityToken") -ErrorAction Stop

# ----------- Configuration ------------
$awsprofile = "sso-production-AdministratorAccess"
$region         = "eu-west-1"                   # Replace with your region
$securityGroupId = "sg-0954c4547395dcc21"       # Replace with your Security Group ID
$prefixListId    = "pl-02ca05d2dd6e24be8"       # Replace with your Prefix List ID
$fromPort        = 5723
$toPort          = 5723
$protocol        = "tcp"





# ----------- Add Prefix List Rule (AWS CLI fallback for reliability) ------------
$env:AWS_PROFILE = $awsprofile
$env:AWS_REGION = $region
$json = @"
[
  {
    "IpProtocol": "$protocol",
    "FromPort": $fromPort,
    "ToPort": $toPort,
    "PrefixListIds": [
      { "PrefixListId": "$prefixListId" }
    ]
  }
]
"@

aws ec2 authorize-security-group-ingress --group-id $securityGroupId --ip-permissions "$json"

Write-Host "✅ Ingress rule added: $protocol $fromPort-$toPort from Prefix List $prefixListId (via AWS CLI)"
