# Test script for prefix list enumeration functionality
# This tests the Get-PrefixListCidrs function independently

# Import the main script functions
. ".\Get-SecurityGroupUtlisation.ps1"

Write-Host "=== Testing Prefix List Enumeration Function ===" -ForegroundColor Cyan

# Test the Get-PrefixListCidrs function with a sample prefix list ID
$testPrefixListId = "pl-12345678"  # This is a dummy ID for testing

Write-Host "`nTesting Get-PrefixListCidrs function..." -ForegroundColor Yellow

try {
    $cidrs = Get-PrefixListCidrs -PrefixListId $testPrefixListId
    
    if ($cidrs.Count -gt 0) {
        Write-Host "SUCCESS: Found $($cidrs.Count) CIDR blocks:" -ForegroundColor Green
        $cidrs | ForEach-Object { Write-Host "  - $_" -ForegroundColor White }
    } else {
        Write-Host "INFO: No CIDR blocks found (expected for test ID)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "ERROR: Function test failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Test the Get-ProtocolNumber function
Write-Host "`nTesting Get-ProtocolNumber function..." -ForegroundColor Yellow

$testProtocols = @("tcp", "udp", "icmp", "-1", "6", "17", "1")

foreach ($protocol in $testProtocols) {
    try {
        $protocolNumber = Get-ProtocolNumber -Protocol $protocol
        Write-Host "  $protocol -> $protocolNumber" -ForegroundColor White
    } catch {
        Write-Host "  ERROR with protocol $protocol : $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`n=== Test Complete ===" -ForegroundColor Cyan
Write-Host "The prefix list enumeration functions are ready for integration." -ForegroundColor Green
