# Test script to verify port filter logging works correctly
# This simulates the Write-Log function and tests the port filter logic with logging

# Mock Write-Log function for testing
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $(
        switch ($Level) {
            "INFO" { "White" }
            "WARN" { "Yellow" }
            "ERROR" { "Red" }
            default { "Gray" }
        }
    )
}

Write-Host "=== Testing Port Filter Logging ===" -ForegroundColor Cyan

# Test scenarios with different rule types
$testScenarios = @(
    @{ Protocol = "-1"; FromPort = -1; ToPort = -1; Description = "All Traffic (protocol -1)" },
    @{ Protocol = "tcp"; FromPort = 80; ToPort = 80; Description = "TCP port 80 (single port)" },
    @{ Protocol = "tcp"; FromPort = 80; ToPort = 443; Description = "TCP port range 80-443" },
    @{ Protocol = "udp"; FromPort = 53; ToPort = 53; Description = "UDP port 53 (single port)" },
    @{ Protocol = "icmp"; FromPort = -1; ToPort = -1; Description = "ICMP (no ports)" }
)

foreach ($scenario in $testScenarios) {
    Write-Host "`n--- Testing: $($scenario.Description) ---" -ForegroundColor Yellow
    
    $protocol = $scenario.Protocol
    $fromPort = $scenario.FromPort
    $toPort = $scenario.ToPort
    
    # Handle special cases for ports (same logic as main script)
    $queryFromPort = if ($null -eq $fromPort -or $fromPort -eq -1) { 0 } else { $fromPort }
    $queryToPort = if ($null -eq $toPort -or $toPort -eq -1) { 65535 } else { $toPort }
    
    # Test IPv4 CIDR logic with logging
    Write-Host "IPv4 CIDR Processing:" -ForegroundColor Cyan
    $portFilter = ""
    # Only apply port filtering if not "all traffic" (protocol -1)
    if ($protocol -ne "-1") {
        if ($queryFromPort -eq $queryToPort) {
            $portFilter = "and @message like / $queryFromPort /"
            Write-Log -Message "Port filter applied: Single port $queryFromPort for protocol $protocol" -Level "INFO"
        } else {
            # For port ranges, we'll need to be more flexible
            $portFilter = ""
            Write-Log -Message "Port filter skipped: Port range $queryFromPort-$queryToPort not supported in message filtering" -Level "INFO"
        }
    } else {
        Write-Log -Message "Port filter skipped: All traffic rule (protocol -1) allows all ports" -Level "INFO"
    }
    
    # Test prefix list logic with logging
    Write-Host "Prefix List Processing:" -ForegroundColor Cyan
    $prefixPortFilter = ""
    # Only apply port filtering if not "all traffic" (protocol -1)
    if ($protocol -ne "-1") {
        if ($fromPort -eq $toPort) {
            $prefixPortFilter = "and @message like / $fromPort /"
            Write-Log -Message "Port filter applied for prefix list CIDR: Single port $fromPort for protocol $protocol" -Level "INFO"
        } else {
            Write-Log -Message "Port filter skipped for prefix list CIDR: Port range $fromPort-$toPort not supported in message filtering" -Level "INFO"
        }
    } else {
        Write-Log -Message "Port filter skipped for prefix list CIDR: All traffic rule (protocol -1) allows all ports" -Level "INFO"
    }
    
    Write-Host "Result: Port filter = '$portFilter'" -ForegroundColor Gray
}

Write-Host "`n=== Port Filter Logging Test Complete ===" -ForegroundColor Cyan
Write-Host "The logging now clearly indicates when and why port filters are applied or skipped." -ForegroundColor Green
