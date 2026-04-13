#Requires -Version 5.1
<#
.SYNOPSIS
    Test script to verify the ENI status function works correctly.
    
.DESCRIPTION
    This test script validates that the Get-ENIStatusInfo function correctly
    extracts ENI attachment and status information.
#>

# Import the function from the main script
$scriptContent = Get-Content ".\Get-SecurityGroupUtlisation.ps1" -Raw

# Extract the ENI status function
$functionStart = $scriptContent.IndexOf("# Function to get ENI attachment and status information")
$functionEnd = $scriptContent.IndexOf("# Import AWS Tools modules with detailed error handling")
$functionCode = $scriptContent.Substring($functionStart, $functionEnd - $functionStart)

# Execute the function definition
Invoke-Expression $functionCode

Write-Host "=== Testing ENI Status Function ===" -ForegroundColor Cyan

# Test with null ENI
Write-Host "`nTest 1: Null ENI" -ForegroundColor Yellow
$result1 = Get-ENIStatusInfo -ENI $null
$result1 | Format-List

# Test with mock attached ENI (EC2 instance)
Write-Host "`nTest 2: Attached ENI (EC2 Instance)" -ForegroundColor Yellow
$mockAttachedENI = [PSCustomObject]@{
    NetworkInterfaceId = "eni-1234567890abcdef0"
    Status = "in-use"
    Attachment = [PSCustomObject]@{
        Status = "attached"
        InstanceId = "i-1234567890abcdef0"
    }
    Description = "Primary network interface"
}
$result2 = Get-ENIStatusInfo -ENI $mockAttachedENI
$result2 | Format-List

# Test with mock unattached ENI
Write-Host "`nTest 3: Unattached ENI" -ForegroundColor Yellow
$mockUnattachedENI = [PSCustomObject]@{
    NetworkInterfaceId = "eni-0987654321fedcba0"
    Status = "available"
    Attachment = $null
    Description = "Unused network interface"
}
$result3 = Get-ENIStatusInfo -ENI $mockUnattachedENI
$result3 | Format-List

# Test with mock AWS service ENI (Load Balancer)
Write-Host "`nTest 4: AWS Service ENI (Load Balancer)" -ForegroundColor Yellow
$mockServiceENI = [PSCustomObject]@{
    NetworkInterfaceId = "eni-abcdef0123456789"
    Status = "in-use"
    Attachment = [PSCustomObject]@{
        Status = "attached"
        InstanceId = $null
    }
    Description = "ELB app/my-load-balancer/1234567890abcdef"
}
$result4 = Get-ENIStatusInfo -ENI $mockServiceENI
$result4 | Format-List

Write-Host "`nENI Status Function testing completed!" -ForegroundColor Green
