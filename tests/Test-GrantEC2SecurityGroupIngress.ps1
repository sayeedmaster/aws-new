# Test-GrantEC2SecurityGroupIngress.ps1
# Minimal test for Grant-EC2SecurityGroupIngress using IpPermission object
# Replace the values below with your actual AWS details before running

param(
    [Parameter(Mandatory=$false)]
    [string]$GroupId = "sg-02397806d1e7c6345",  # Replace with your actual security group ID
    [Parameter(Mandatory=$false)]
    [string]$ProfileName = "sso-production-AdministratorAccess",  # Replace with your actual AWS profile name
    [Parameter(Mandatory=$false)]
    [string]$Region = "eu-west-1"  # Replace with your actual AWS region
)

$PSModulesPath = "C:\github\psmodules"  # Adjust this path to your actual PSModulesPath
# Import necessary AWS Tools modules

Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.Common") -ErrorAction Stop
Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.EC2") -ErrorAction Stop
Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.SecurityToken") -ErrorAction Stop


# Test direct parameter approach for Grant-EC2SecurityGroupIngress
Write-Host "Testing Grant-EC2SecurityGroupIngress with:"
Write-Host "GroupId: $GroupId"
Write-Host "ProfileName: $ProfileName"
Write-Host "Region: $Region"
Write-Host "IpProtocol: tcp, FromPort: 80, ToPort: 80, CidrIp: 10.0.0.0/16"
#create IpPermission object
$ipPermission = @{
    IpProtocol = "tcp"
    FromPort   = 5123
    ToPort     = 5123
    # CidrIp is replaced with Ipv4Ranges for better compatibility
    Ipv4Ranges = @(
        @{
            CidrIp = "10.0.0.0/16"
            Description = "SCOM Ports Description"
        }
    )
}

Grant-EC2SecurityGroupIngress -GroupId $GroupId -IpPermission $ipPermission -ProfileName $ProfileName -Region $Region -ErrorAction Stop

Write-Host "Ingress rule added (if no error above)."
