#Requires -Version 5.1
<#
.SYNOPSIS
    Test script to verify the interactive security group selection functionality.
    
.DESCRIPTION
    This test script validates that the Select-SecurityGroups function works correctly
    by creating mock security group data and testing the selection logic.
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$PSModulesPath = "D:\psmodules"
)

# Import the function from the main script
$scriptContent = Get-Content ".\Get-SecurityGroupUtlisation.ps1" -Raw

# Extract just the function we want to test
$functionStart = $scriptContent.IndexOf("# Function for interactive security group selection")
$functionEnd = $scriptContent.IndexOf("# Import AWS Tools modules with detailed error handling")
$functionCode = $scriptContent.Substring($functionStart, $functionEnd - $functionStart)

# Execute the function definition
Invoke-Expression $functionCode

# Create mock security group data for testing
Write-Host "=== Testing Security Group Selection Function ===" -ForegroundColor Cyan

$mockSecurityGroups = @(
    [PSCustomObject]@{
        GroupId = "sg-1234567890abcdef0"
        GroupName = "web-servers-sg"
        Description = "Security group for web servers"
        VpcId = "vpc-abcdef1234567890"
        IpPermissions = @(@{}, @{}, @{})  # 3 ingress rules
        IpPermissionsEgress = @(@{})      # 1 egress rule
        Tags = @(
            @{ Key = "Environment"; Value = "Production" },
            @{ Key = "Application"; Value = "WebApp" }
        )
    },
    [PSCustomObject]@{
        GroupId = "sg-0987654321fedcba0"
        GroupName = "database-sg"
        Description = "Security group for database servers"
        VpcId = "vpc-abcdef1234567890"
        IpPermissions = @(@{}, @{})       # 2 ingress rules
        IpPermissionsEgress = @(@{})      # 1 egress rule
        Tags = @(
            @{ Key = "Environment"; Value = "Production" },
            @{ Key = "Tier"; Value = "Database" }
        )
    },
    [PSCustomObject]@{
        GroupId = "sg-abcdef0123456789"
        GroupName = "app-servers-sg"
        Description = "Security group for application servers"
        VpcId = "vpc-123456789abcdef0"
        IpPermissions = @(@{}, @{}, @{}, @{})  # 4 ingress rules
        IpPermissionsEgress = @(@{}, @{})      # 2 egress rules
        Tags = @(
            @{ Key = "Environment"; Value = "Staging" },
            @{ Key = "Application"; Value = "AppServer" }
        )
    }
)

Write-Host "Created $($mockSecurityGroups.Count) mock security groups for testing" -ForegroundColor Green

# Test the function with manual confirmation (comment this out for automated testing)
# $selectedSGs = Select-SecurityGroups -SecurityGroups $mockSecurityGroups -AccountId "123456789012" -Region "us-east-1"

Write-Host "`nFunction definition loaded successfully!" -ForegroundColor Green
Write-Host "To test interactively, uncomment the last line in this script and run it again." -ForegroundColor Yellow
Write-Host "The function 'Select-SecurityGroups' is now available for testing." -ForegroundColor Cyan
