# Test script for "all traffic" rule query generation
# This validates that protocol -1 (all traffic) rules don't include port filters

Write-Host "=== Testing All Traffic Rule Query Generation ===" -ForegroundColor Cyan

# Test scenarios
$testScenarios = @(
    @{ Protocol = "-1"; FromPort = -1; ToPort = -1; Description = "All Traffic (protocol -1)" },
    @{ Protocol = "tcp"; FromPort = 80; ToPort = 80; Description = "TCP port 80" },
    @{ Protocol = "tcp"; FromPort = 80; ToPort = 443; Description = "TCP port range 80-443" },
    @{ Protocol = "udp"; FromPort = 53; ToPort = 53; Description = "UDP port 53" }
)

foreach ($scenario in $testScenarios) {
    Write-Host "`nTesting: $($scenario.Description)" -ForegroundColor Yellow
    
    $protocol = $scenario.Protocol
    $fromPort = $scenario.FromPort
    $toPort = $scenario.ToPort
    
    # Handle special cases for ports (same logic as main script)
    $queryFromPort = if ($null -eq $fromPort -or $fromPort -eq -1) { 0 } else { $fromPort }
    $queryToPort = if ($null -eq $toPort -or $toPort -eq -1) { 65535 } else { $toPort }
    
    # Build port filter logic (same as updated script)
    $portFilter = ""
    # Only apply port filtering if not "all traffic" (protocol -1)
    if ($protocol -ne "-1") {
        if ($queryFromPort -eq $queryToPort) {
            $portFilter = "and @message like / $queryFromPort /"
        } else {
            # For port ranges, we'll need to be more flexible
            $portFilter = ""
        }
    }
    
    # Example source address filter
    $srcAddrFilter = "and @message like / 192.168.0.189 /"
    $eni = "eni-020c3ea1c4d88ba04"
    
    $query = @"
fields @timestamp, @message
| filter @message like / $eni /
  and @message like / ACCEPT /
  $portFilter
  $srcAddrFilter
| stats count() as matchCount
"@

    Write-Host "Generated Query:" -ForegroundColor White
    Write-Host $query -ForegroundColor Gray
    
    # Verify correctness
    if ($protocol -eq "-1") {
        if ($portFilter -eq "") {
            Write-Host "✅ CORRECT: No port filter for all traffic rule" -ForegroundColor Green
        } else {
            Write-Host "❌ ERROR: Port filter should be empty for all traffic rule" -ForegroundColor Red
        }
    } else {
        if ($portFilter -ne "") {
            Write-Host "✅ CORRECT: Port filter applied for specific protocol" -ForegroundColor Green
        } else {
            Write-Host "⚠️  WARNING: No port filter for specific protocol" -ForegroundColor Yellow
        }
    }
}

Write-Host "`n=== Test Complete ===" -ForegroundColor Cyan
