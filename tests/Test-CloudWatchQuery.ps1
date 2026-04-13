#Requires -Version 5.1
<#
.SYNOPSIS
    Simple helper script to test CloudWatch Logs Insights queries against VPC Flow Logs.
    
.DESCRIPTION
    This script helps debug CloudWatch Logs Insights queries by testing them against
    specific log groups. It's designed to help troubleshoot VPC Flow Logs query issues.
    
.PARAMETER PSModulesPath
    Path to the directory containing AWS.Tools modules (required).
    
.PARAMETER LogGroupName
    Name of the CloudWatch Log Group to query (required).
    
.PARAMETER AwsProfile
    AWS profile to use (optional).
    
.PARAMETER Region
    AWS region to use (optional).
    
.PARAMETER LookbackHours
    Number of hours to look back (default: 24).
    
.PARAMETER TestQuery
    Custom query to test (optional - uses default if not provided).
    
.EXAMPLE
    .\Test-CloudWatchQuery.ps1 -PSModulesPath "C:\ProgramFiles\AWS Tools\PowerShell" -LogGroupName "StackSet-AWSControlTowerBP-VPC-ACCOUNT-FACTORY-V1-d0d3cf0d-fa1a-4141-b09d-a0c68db385b5-VPCFlowLogsLogGroup-fabb2OlInRka"
    
.EXAMPLE
    .\Test-CloudWatchQuery.ps1 -PSModulesPath "C:\ProgramFiles\AWS Tools\PowerShell" -LogGroupName "your-log-group" -AwsProfile "your-profile" -LookbackHours 1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, HelpMessage="Path to the directory containing AWS.Tools modules.")]
    [string]$PSModulesPath,
    [Parameter(Mandatory=$true, HelpMessage="Name of the CloudWatch Log Group to query.")]
    [string]$LogGroupName,
    [Parameter()]
    [string]$AwsProfile,
    [Parameter()]
    [string]$Region,
    [Parameter()]
    [int]$LookbackHours = 24,
    [Parameter()]
    [string]$TestQuery
)

# Initialize script variables
$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }

# Function to write logs with colors
function Write-TestLog {
    param ([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    switch ($Level.ToUpper()) {
        "INFO"  { Write-Host $logMessage -ForegroundColor Cyan }
        "WARN"  { Write-Host $logMessage -ForegroundColor Yellow }
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
        default { Write-Host $logMessage }
    }
}

Write-Host "=== CloudWatch Logs Insights Query Tester ===" -ForegroundColor Magenta
Write-TestLog -Message "Starting CloudWatch query test" -Level "INFO"

# Import AWS Tools modules
try {
    $modulePaths = @(
        (Join-Path $PSModulesPath "AWS.Tools.Common"),
        (Join-Path $PSModulesPath "AWS.Tools.CloudWatchLogs"),
        (Join-Path $PSModulesPath "AWS.Tools.SecurityToken")
    )
    foreach ($path in $modulePaths) {
        if (-not (Test-Path $path)) {
            throw "Module path ${path} does not exist"
        }
        Import-Module -Name $path -ErrorAction Stop
    }
    Write-TestLog -Message "Successfully imported AWS Tools modules" -Level "SUCCESS"
} catch {
    Write-TestLog -Message "Failed to import AWS Tools modules: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}

# Set AWS profile and region
try {
    if ($AwsProfile) {
        Set-AWSCredential -ProfileName $AwsProfile
        Write-TestLog -Message "Set AWS profile: $AwsProfile" -Level "INFO"
    }
    if ($Region) {
        Set-DefaultAWSRegion -Region $Region
        Write-TestLog -Message "Set AWS region: $Region" -Level "INFO"
    }
    
    # Get current identity
    $identity = Get-STSCallerIdentity
    $accountId = $identity.Account
    $currentRegion = Get-DefaultAWSRegion
    Write-TestLog -Message "Connected to Account: $accountId, Region: $currentRegion" -Level "SUCCESS"
} catch {
    Write-TestLog -Message "Failed to set AWS credentials: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}

# Test log group existence
Write-TestLog -Message "Testing log group existence: $LogGroupName" -Level "INFO"
Write-TestLog -Message "Log group name length: $($LogGroupName.Length) characters" -Level "INFO"

try {
    # First, try to find log groups with a shorter prefix to see what's available
    $shortPrefix = $LogGroupName.Substring(0, [Math]::Min(50, $LogGroupName.Length))
    Write-TestLog -Message "Searching with prefix: $shortPrefix" -Level "INFO"
    
    $allLogGroups = Get-CWLLogGroup -LogGroupNamePrefix $shortPrefix
    Write-TestLog -Message "Found $($allLogGroups.Count) log groups with prefix '$shortPrefix'" -Level "INFO"
    
    # List the first few for debugging
    if ($allLogGroups.Count -gt 0) {
        Write-TestLog -Message "Available log groups:" -Level "INFO"
        foreach ($lg in $allLogGroups | Select-Object -First 5) {
            Write-TestLog -Message "  - $($lg.LogGroupName)" -Level "INFO"
        }
        if ($allLogGroups.Count -gt 5) {
            Write-TestLog -Message "  ... and $($allLogGroups.Count - 5) more" -Level "INFO"
        }
    }
    
    # Try exact match
    $logGroup = $allLogGroups | Where-Object { $_.LogGroupName -eq $LogGroupName }
    if ($logGroup) {
        Write-TestLog -Message "✓ Log group found with exact match" -Level "SUCCESS"
        Write-TestLog -Message "  - Full name: $($logGroup.LogGroupName)" -Level "INFO"
        Write-TestLog -Message "  - Creation time: $($logGroup.CreationTime)" -Level "INFO"
        Write-TestLog -Message "  - Stored bytes: $($logGroup.StoredBytes)" -Level "INFO"
        Write-TestLog -Message "  - Retention days: $($logGroup.RetentionInDays)" -Level "INFO"
    } else {
        # Try partial match for troubleshooting
        $partialMatches = $allLogGroups | Where-Object { $_.LogGroupName -like "*VPCFlowLogsLogGroup*" }
        if ($partialMatches.Count -gt 0) {
            Write-TestLog -Message "✗ Exact match failed, but found partial matches:" -Level "WARN"
            foreach ($pm in $partialMatches) {
                Write-TestLog -Message "  - $($pm.LogGroupName)" -Level "WARN"
            }
            
            # Use the first partial match for testing
            $logGroup = $partialMatches[0]
            $LogGroupName = $logGroup.LogGroupName
            Write-TestLog -Message "Using partial match for testing: $LogGroupName" -Level "WARN"
        } else {
            Write-TestLog -Message "✗ Log group not found with exact or partial match" -Level "ERROR"
            exit 1
        }
    }
    
    # Test log streams
    Write-TestLog -Message "Checking log streams in the log group..." -Level "INFO"
    $logStreams = Get-CWLLogStream -LogGroupName $LogGroupName -Limit 5
    Write-TestLog -Message "Found $($logStreams.Count) log streams (showing first 5)" -Level "INFO"
    foreach ($stream in $logStreams) {
        Write-TestLog -Message "  - Stream: $($stream.LogStreamName)" -Level "INFO"
        Write-TestLog -Message "    Last event: $($stream.LastEventTime)" -Level "INFO"
    }
    
} catch {
    Write-TestLog -Message "Failed to check log group: $($_.Exception.Message)" -Level "ERROR"
    Write-TestLog -Message "Exception type: $($_.Exception.GetType().FullName)" -Level "ERROR"
    exit 1
}

# Set time range
$startTime = (Get-Date).AddHours(-$LookbackHours)
$endTime = Get-Date
Write-TestLog -Message "Query time range: $startTime to $endTime" -Level "INFO"

# Define test queries
$queries = @()

# Use custom query if provided
if ($TestQuery) {
    $queries += @{
        Name = "Custom Query"
        Query = $TestQuery
    }
} else {
    # Default test queries
    $queries += @{
        Name = "Basic Data Check"
        Query = @"
fields @timestamp, @message
| limit 5
"@
    }

    $queries += @{
        Name = "Sample VPC Flow Log Entries"
        Query = @"
fields @timestamp, @message
| filter @message like /ACCEPT/ or @message like /REJECT/
| limit 3
"@
    }

    $queries += @{
        Name = "Interface ID Pattern Check"
        Query = @"
fields @timestamp, @message
| filter @message like /eni-/
| limit 3
"@
    }

    $queries += @{
        Name = "Count Total Entries"
        Query = @"
fields @timestamp, @message
| stats count() as totalEntries
"@
    }

    $queries += @{
        Name = "Count ACCEPT Entries"
        Query = @"
fields @timestamp, @message
| filter @message like /ACCEPT/
| stats count() as acceptEntries
"@
    }
}

# Test each query
foreach ($testCase in $queries) {
    Write-Host "`n" + "="*60 -ForegroundColor Magenta
    Write-TestLog -Message "Testing: $($testCase.Name)" -Level "INFO"
    Write-Host "Query:" -ForegroundColor Yellow
    Write-Host $testCase.Query -ForegroundColor Gray
    Write-Host ""

    try {
        # Start the query
        Write-TestLog -Message "Starting CloudWatch Logs Insights query..." -Level "INFO"
        $startQuery = Start-CWLQuery `
            -LogGroupName $LogGroupName `
            -StartTime (Get-Date $startTime -UFormat %s) `
            -EndTime (Get-Date $endTime -UFormat %s) `
            -QueryString $testCase.Query

        if (-not $startQuery) {
            Write-TestLog -Message "✗ Start-CWLQuery returned null" -Level "ERROR"
            continue
        }

        # Handle different response formats from Start-CWLQuery
        $queryId = $null
        if ($startQuery -is [string]) {
            # Direct string response (newer AWS Tools version)
            $queryId = $startQuery
            Write-TestLog -Message "✓ Query started successfully with ID: $queryId (string format)" -Level "SUCCESS"
        } elseif ($startQuery.QueryId) {
            # Object with QueryId property (older format)
            $queryId = $startQuery.QueryId
            Write-TestLog -Message "✓ Query started successfully with ID: $queryId (object format)" -Level "SUCCESS"
        } else {
            Write-TestLog -Message "✗ Start-CWLQuery returned object but no QueryId" -Level "ERROR"
            Write-TestLog -Message "Response: $($startQuery | ConvertTo-Json -Depth 2)" -Level "ERROR"
            continue
        }

        # Wait for query completion
        $maxWaitSeconds = 30
        $elapsedSeconds = 0
        do {
            Start-Sleep -Seconds 2
            $elapsedSeconds += 2
            try {
                $queryResult = Get-CWLQueryResult -QueryId $queryId
                $queryStatus = $queryResult.Status
                Write-TestLog -Message "Query status: $queryStatus (elapsed: ${elapsedSeconds}s)" -Level "INFO"
            } catch {
                Write-TestLog -Message "Error checking query status: $($_.Exception.Message)" -Level "WARN"
                $queryStatus = "Failed"
                break
            }
            
            if ($elapsedSeconds -ge $maxWaitSeconds) {
                Write-TestLog -Message "Query timeout after ${maxWaitSeconds} seconds" -Level "WARN"
                $queryStatus = "Timeout"
                break
            }
        } while ($queryStatus -eq "Running")

        # Display results
        if ($queryStatus -eq "Complete") {
            Write-TestLog -Message "✓ Query completed successfully" -Level "SUCCESS"
            Write-TestLog -Message "Results count: $($queryResult.Results.Count)" -Level "INFO"
            
            if ($queryResult.Results.Count -gt 0) {
                Write-Host "`nResults Preview:" -ForegroundColor Yellow
                $maxResultsToShow = 3
                for ($i = 0; $i -lt [Math]::Min($queryResult.Results.Count, $maxResultsToShow); $i++) {
                    $result = $queryResult.Results[$i]
                    Write-Host "  Row $($i + 1):" -ForegroundColor Cyan
                    foreach ($field in $result) {
                        if ($field.Field -eq "@message" -and $field.Value.Length -gt 100) {
                            $truncated = $field.Value.Substring(0, 100) + "..."
                            Write-Host "    $($field.Field): $truncated" -ForegroundColor Gray
                        } else {
                            Write-Host "    $($field.Field): $($field.Value)" -ForegroundColor Gray
                        }
                    }
                }
                if ($queryResult.Results.Count -gt $maxResultsToShow) {
                    Write-Host "    ... and $($queryResult.Results.Count - $maxResultsToShow) more results" -ForegroundColor Gray
                }
            } else {
                Write-TestLog -Message "No results returned (empty dataset or no matches)" -Level "WARN"
            }
        } else {
            Write-TestLog -Message "✗ Query failed with status: $queryStatus" -Level "ERROR"
        }

    } catch {
        Write-TestLog -Message "✗ Query execution failed: $($_.Exception.Message)" -Level "ERROR"
    }
}

Write-Host "`n" + "="*60 -ForegroundColor Magenta
Write-TestLog -Message "CloudWatch query testing completed" -Level "SUCCESS"

# Provide troubleshooting suggestions
Write-Host "`nTroubleshooting Tips:" -ForegroundColor Yellow
Write-Host "1. If queries return no results, check if VPC Flow Logs are actually being generated" -ForegroundColor Gray
Write-Host "2. Verify the time range - VPC Flow Logs may have a delay" -ForegroundColor Gray
Write-Host "3. Check if the log group has recent entries with: Get-CWLLogStream -LogGroupName '$LogGroupName'" -ForegroundColor Gray
Write-Host "4. VPC Flow Logs format: account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes windowstart windowend action flowlogstatus" -ForegroundColor Gray
Write-Host "5. Use AWS Console CloudWatch Logs Insights to test queries interactively" -ForegroundColor Gray
