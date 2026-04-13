#Requires -Version 5.1
<#
.SYNOPSIS
    Security Group Utilization Analysis with VPC Flow Logs integration.
    
.DESCRIPTION
    This script analyzes AWS EC2 Security Group ingress rules to determine if they have been used recently,
    based on VPC-level Flow Logs in CloudWatch Logs. It supports multiple AWS accounts and profiles with
    interactive selection capabilities.
    
    The script automatically discovers VPC-level Flow Logs configurations and applies them to all network
    interfaces within each VPC. Only CloudWatch Logs destinations are supported for analysis.
    
.PARAMETER PSModulesPath
    Path to the directory containing AWS.Tools modules (required).
    
.PARAMETER VpcFlowLogGroupName
    DEPRECATED: Default CloudWatch Log Group name for VPC Flow Logs (default: "/vpc/flowlogs").
    The script now automatically discovers actual VPC-level flow log configurations.
    This parameter is kept for backward compatibility but is no longer used.
    
.PARAMETER LookbackDays
    Number of days to look back for usage analysis (default: 7).
    
.PARAMETER Region
    Specifies a single AWS region to query (optional; if omitted, uses profile-configured or default region).
    
.PARAMETER AwsProfiles
    List of AWS profiles to query (optional; if omitted, prompts for selection).
    
.PARAMETER OutputFile
    Path for the output CSV file (optional; defaults to a timestamped file in the output directory).
    
.PARAMETER InteractiveSelection
    Enables interactive profile selection if no profiles are specified (default: $true).
    
.PARAMETER TestProfilesFirst
    Tests profile connectivity before processing (default: $true).
    
.EXAMPLE
    .\Get-SecurityGroupUtlisation.ps1 -PSModulesPath "C:\ProgramFiles\AWS Tools\PowerShell"
    Runs analysis with default settings and interactive profile selection.
    
.EXAMPLE
    .\Get-SecurityGroupUtlisation.ps1 -PSModulesPath "C:\ProgramFiles\AWS Tools\PowerShell" -Region us-east-1 -AwsProfiles "profile1","profile2"
    Runs analysis for specific profiles and region.
    
.NOTES
    Version: 3.1 (Simplified to use VPC-level CloudWatch flow logs only)
    Requires: AWS.Tools.EC2, AWS.Tools.CloudWatchLogs, AWS.Tools.Common, AWS.Tools.SecurityToken
    
    Key Features:
    - Automatic discovery of VPC-level Flow Logs configurations
    - CloudWatch Logs Insights analysis for IPv4 CIDR rules
    - Support for AWS Control Tower managed flow logs
    - Simplified architecture using only VPC-level flow logs
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, HelpMessage="Path to the directory containing AWS.Tools modules.")]
    [string]$PSModulesPath,
    [Parameter()]
    [string]$VpcFlowLogGroupName = "/vpc/flowlogs",
    [Parameter()]
    [int]$LookbackDays = 7,
    [Parameter()]
    [string]$Region,
    [Parameter()]
    [string[]]$AwsProfiles,
    [Parameter()]
    [string]$OutputFile,
    [Parameter()]
    [bool]$InteractiveSelection = $true,
    [Parameter()]
    [bool]$TestProfilesFirst = $true
)

# Initialize script variables
$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
$OutputDir = Join-Path $ScriptDir "output"
$LogFilePath = Join-Path $OutputDir "SecurityGroup_Utilisation_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Create output directory if it doesn't exist
if (-not (Test-Path $OutputDir)) {
    try {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    } catch {
        Write-Error "Failed to create output directory ${OutputDir}: $($_.Exception.Message)"
        exit 1
    }
}

# Function to write logs
function Write-Log {
    param ([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    switch ($Level.ToUpper()) {
        "INFO"  { Write-Host $logMessage -ForegroundColor Blue }
        "WARN"  { Write-Host $logMessage -ForegroundColor Yellow }
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        default { Write-Host $logMessage }
    }
    Add-Content -Path $LogFilePath -Value $logMessage -ErrorAction SilentlyContinue
}

# Function to test AWS profile connectivity
function Test-AwsProfileConnectivity {
    param([string]$ProfileName, [string]$Region)
    try {
        Get-STSCallerIdentity -ProfileName $ProfileName -Region $Region -ErrorAction Stop | Out-Null
        Write-Log -Message "Successfully validated connectivity for profile ${ProfileName}" -Level "INFO"
        return $true
    } catch {
        Write-Log -Message "Failed to validate connectivity for profile ${ProfileName}: $($_.Exception.Message)" -Level "WARN"
        return $false
    }
}

# Function to discover VPC Flow Logs configurations
function Get-VpcFlowLogsConfiguration {
    param([string]$VpcId, [string]$NetworkInterfaceId)
    
    try {
        # Get all flow logs for the VPC and specific ENI
        $flowLogs = @()
        
        # Check VPC-level flow logs first (most common)
        if ($VpcId) {
            $vpcFlowLogs = Get-EC2FlowLog | Where-Object { 
                $_.ResourceIds -contains $VpcId -and $_.ResourceType -eq "VPC" -and $_.FlowLogStatus -eq "ACTIVE"
            }
            $flowLogs += $vpcFlowLogs
            Write-Log -Message "Found $($vpcFlowLogs.Count) VPC-level flow logs for VPC $VpcId" -Level "INFO"
        }
        
        # Check ENI-specific flow logs
        if ($NetworkInterfaceId) {
            $eniFlowLogs = Get-EC2FlowLog | Where-Object { 
                $_.ResourceIds -contains $NetworkInterfaceId -and $_.ResourceType -eq "NetworkInterface" -and $_.FlowLogStatus -eq "ACTIVE"
            }
            $flowLogs += $eniFlowLogs
            Write-Log -Message "Found $($eniFlowLogs.Count) ENI-level flow logs for ENI $NetworkInterfaceId" -Level "INFO"
        }
        
        # Check subnet-level flow logs (get subnet from ENI)
        if ($NetworkInterfaceId) {
            $eni = Get-EC2NetworkInterface -NetworkInterfaceId $NetworkInterfaceId -ErrorAction SilentlyContinue
            if ($eni -and $eni.SubnetId) {
                $subnetFlowLogs = Get-EC2FlowLog | Where-Object { 
                    $_.ResourceIds -contains $eni.SubnetId -and $_.ResourceType -eq "Subnet" -and $_.FlowLogStatus -eq "ACTIVE"
                }
                $flowLogs += $subnetFlowLogs
                Write-Log -Message "Found $($subnetFlowLogs.Count) Subnet-level flow logs for subnet $($eni.SubnetId)" -Level "INFO"
            }
        }
        
        # Process and return flow log configurations
        $configurations = @()
        foreach ($flowLog in $flowLogs) {
            Write-Log -Message "Processing flow log $($flowLog.FlowLogId) with status $($flowLog.FlowLogStatus)" -Level "INFO"
            
            $config = [pscustomobject]@{
                FlowLogId = $flowLog.FlowLogId
                ResourceType = $flowLog.ResourceType
                ResourceId = $flowLog.ResourceIds[0]
                LogDestinationType = $flowLog.LogDestinationType
                LogDestination = $flowLog.LogDestination
                LogGroupName = $null
                S3BucketName = $null
                S3Prefix = $null
                DeliverLogsStatus = $flowLog.DeliverLogsStatus
            }
            
            # Parse destination based on type
            if ($flowLog.LogDestinationType -eq "cloud-watch-logs") {
                # CloudWatch Logs format: arn:aws:logs:region:account:log-group:log-group-name
                if ($flowLog.LogDestination -match "log-group:(.+)$") {
                    $config.LogGroupName = $matches[1]
                    Write-Log -Message "CloudWatch log group identified: $($config.LogGroupName)" -Level "INFO"
                }
            } elseif ($flowLog.LogDestinationType -eq "s3") {
                # S3 format: arn:aws:s3:::bucket-name/prefix/ or just bucket-name
                if ($flowLog.LogDestination -match "arn:aws:s3:::([^/]+)/?(.*)") {
                    $config.S3BucketName = $matches[1]
                    $config.S3Prefix = $matches[2]
                } elseif ($flowLog.LogDestination -notmatch "^arn:") {
                    # Sometimes just the bucket name is provided
                    $config.S3BucketName = $flowLog.LogDestination
                    $config.S3Prefix = ""
                }
                Write-Log -Message "S3 destination identified: bucket=$($config.S3BucketName), prefix=$($config.S3Prefix)" -Level "INFO"
            }
            
            $configurations += $config
        }
        
        Write-Log -Message "Returning $($configurations.Count) flow log configurations for VPC $VpcId, ENI $NetworkInterfaceId" -Level "INFO"
        return $configurations
    } catch {
        Write-Log -Message "Failed to discover flow logs for VPC ${VpcId}, ENI ${NetworkInterfaceId}: $($_.Exception.Message)" -Level "WARN"
        return @()
    }
}

# Import AWS Tools modules with detailed error handling
try {
    $modulePaths = @(
        (Join-Path $PSModulesPath "AWS.Tools.Common"),
        (Join-Path $PSModulesPath "AWS.Tools.EC2"),
        (Join-Path $PSModulesPath "AWS.Tools.CloudWatchLogs"),
        (Join-Path $PSModulesPath "AWS.Tools.SecurityToken")
    )
    foreach ($path in $modulePaths) {
        if (-not (Test-Path $path)) {
            throw "Module path ${path} does not exist"
        }
        Import-Module -Name $path -ErrorAction Stop
    }
    Write-Log -Message "Successfully imported AWS Tools modules from ${PSModulesPath}" -Level "INFO"
} catch {
    $errorMsg = "Failed to import AWS Tools modules from ${PSModulesPath}: $($_.Exception.Message)"
    Write-Log -Message $errorMsg -Level "ERROR"
    Write-Error $errorMsg
    exit 1
}

# Get AWS profiles with interactive or manual selection
if (-not $AwsProfiles) {
    $profileList = Get-AWSCredential -ListProfile | Select-Object -ExpandProperty ProfileName
    if ($profileList.Count -eq 0) {
        $AwsProfiles = @("")
    } elseif ($InteractiveSelection) {
        $selected = $profileList | Out-GridView -Title "Select AWS Profiles" -OutputMode Multiple
        $AwsProfiles = if ($selected) { $selected } else { @() }
        if ($AwsProfiles.Count -eq 0) { 
            Write-Log -Message "No profiles selected. Exiting." -Level "INFO"
            exit 0 
        }
    } else {
        Write-Host "`nAvailable AWS Profiles:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $profileList.Count; $i++) {
            Write-Host "  $($i + 1). $($profileList[$i])$(if ($env:AWS_PROFILE -eq $profileList[$i]) { ' (current)' })" -ForegroundColor Gray
        }
        Write-Host "  0. Use default profile" -ForegroundColor Gray
        do {
            $Selection = Read-Host "`nSelect AWS profile (0-$($profileList.Count))"
            if ($Selection -eq "0") { $AwsProfiles = @(""); break }
            elseif ($Selection -match '^\d+$' -and [int]$Selection -ge 1 -and [int]$Selection -le $profileList.Count) {
                $AwsProfiles = @($profileList[[int]$Selection - 1]); break
            } else {
                Write-Host "Invalid selection. Please enter a number between 0 and $($profileList.Count)." -ForegroundColor Yellow
            }
        } while ($true)
    }
}

# Set output file with timestamp
if (-not $OutputFile) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $regionSafe = if ($Region) { $Region -replace '[^a-zA-Z0-9]', '_' } else { "multiregion" }
    $accountCount = if ($AwsProfiles -and $AwsProfiles.Count -gt 0) { $AwsProfiles.Count } else { 0 }
    $baseName = "security_group_utilisation_${accountCount}accounts_${regionSafe}_${timestamp}.csv"
    $OutputFile = Join-Path $OutputDir $baseName
}

# Test profile connectivity if requested
if ($TestProfilesFirst -and $AwsProfiles) {
    $validProfiles = @()
    foreach ($profileName in $AwsProfiles) {
        $currentRegion = $Region ? $Region : "eu-west-1"
        if (Test-AwsProfileConnectivity -ProfileName $profileName -Region $currentRegion) {
            $validProfiles += $profileName
        }
    }
    if ($validProfiles.Count -eq 0) { 
        Write-Log -Message "No valid profiles found. Exiting." -Level "ERROR"
        exit 1 
    }
    $AwsProfiles = $validProfiles
}

Write-Log -Message "Starting Security Group utilisation analysis" -Level "INFO"
Write-Log -Message "Profiles to process: $($AwsProfiles -join ', ')" -Level "INFO"

$startTime = (Get-Date).AddDays(-$LookbackDays)
$endTime   = Get-Date

Write-Host "Checking SG ingress rule usage from $startTime to $endTime ..." -ForegroundColor Cyan

$allResults = @()

# Process each AWS profile
foreach ($profileName in $AwsProfiles) {
    try {
        Write-Log -Message "Processing profile: $profileName" -Level "INFO"
        
        # Set profile and region context
        if ($profileName -and $profileName -ne "") {
            Set-AWSCredential -ProfileName $profileName
        }
        if ($Region) {
            Set-DefaultAWSRegion -Region $Region
        }

        # Get account info for logging
        try {
            $identity = Get-STSCallerIdentity
            $accountId = $identity.Account
            $currentRegion = Get-DefaultAWSRegion
            Write-Log -Message "Processing Account: $accountId, Region: $currentRegion" -Level "INFO"
        } catch {
            Write-Log -Message "Failed to get account identity for profile $profileName" -Level "WARN"
            continue
        }

        # Get all security groups for this profile/region
        $securityGroups = Get-EC2SecurityGroup
        Write-Log -Message "Found $($securityGroups.Count) security groups in account $accountId" -Level "INFO"

        # Get all ENIs once to improve performance
        $allEnis = Get-EC2NetworkInterface
        Write-Log -Message "Found $($allEnis.Count) network interfaces in account $accountId" -Level "INFO"

        # Discover VPC-level Flow Logs configurations only
        Write-Log -Message "Discovering VPC-level Flow Logs configurations..." -Level "INFO"
        $vpcFlowLogConfigs = @{}
        $uniqueVpcs = $allEnis | Select-Object -ExpandProperty VpcId -Unique
        
        # Get ALL flow logs once for efficiency
        $allFlowLogsInAccount = Get-EC2FlowLog
        Write-Log -Message "Total flow logs in account: $($allFlowLogsInAccount.Count)" -Level "INFO"
        
        # Get available CloudWatch Log Groups for pattern matching
        try {
            $allLogGroups = Get-CWLLogGroup
            Write-Log -Message "Available CloudWatch Log Groups: $($allLogGroups.Count) total" -Level "INFO"
        } catch {
            Write-Log -Message "Failed to retrieve CloudWatch Log Groups: $($_.Exception.Message)" -Level "WARN"
            $allLogGroups = @()
        }
        
        # Get VPC-level flow logs only (simplified approach)
        foreach ($vpc in $uniqueVpcs) {
            Write-Log -Message "Checking VPC-level flow logs for VPC $vpc" -Level "INFO"
            
            # Filter for this specific VPC
            $vpcFlowLogs = $allFlowLogsInAccount | Where-Object { 
                $_.ResourceType -eq "VPC" -and 
                $_.ResourceIds -and $_.ResourceIds.Count -gt 0 -and $_.ResourceIds[0] -eq $vpc -and 
                $_.FlowLogStatus -eq "ACTIVE"
            }
            
            # If no VPC-specific flow logs found, check for account-level flow logs that might cover this VPC
            if ($vpcFlowLogs.Count -eq 0) {
                Write-Log -Message "No direct VPC flow logs found. Checking for account-level flow logs..." -Level "INFO"
                
                # Look for active flow logs without specific ResourceIds (account-level)
                $accountLevelFlowLogs = $allFlowLogsInAccount | Where-Object { 
                    $_.FlowLogStatus -eq "ACTIVE" -and
                    ((-not $_.ResourceIds) -or $_.ResourceIds.Count -eq 0 -or ($_.ResourceIds -and $_.ResourceIds[0] -eq ""))
                }
                
                if ($accountLevelFlowLogs.Count -gt 0) {
                    Write-Log -Message "Found $($accountLevelFlowLogs.Count) account-level flow logs that cover VPC $vpc" -Level "INFO"
                    $vpcFlowLogs = $accountLevelFlowLogs
                }
            }
            
            Write-Log -Message "Found $($vpcFlowLogs.Count) flow logs for VPC $vpc" -Level "INFO"
            
            if ($vpcFlowLogs.Count -gt 0) {
                $vpcFlowLogConfigs[$vpc] = @()
                foreach ($flowLog in $vpcFlowLogs) {
                    # Only process CloudWatch Logs flow logs (skip S3)
                    if ($flowLog.LogDestinationType -ne "cloud-watch-logs") {
                        Write-Log -Message "Skipping non-CloudWatch flow log $($flowLog.FlowLogId) (type: $($flowLog.LogDestinationType))" -Level "INFO"
                        continue
                    }
                    
                    $config = [pscustomobject]@{
                        FlowLogId = $flowLog.FlowLogId
                        ResourceType = $flowLog.ResourceType
                        ResourceId = if ($flowLog.ResourceIds -and $flowLog.ResourceIds.Count -gt 0) { $flowLog.ResourceIds[0] } else { $vpc }
                        LogDestinationType = $flowLog.LogDestinationType
                        LogDestination = $flowLog.LogDestination
                        LogGroupName = $null
                        DeliverLogsStatus = $flowLog.DeliverLogsStatus
                    }
                    
                    # Parse CloudWatch log group name
                    if ($flowLog.LogDestination -and $flowLog.LogDestination -match "log-group:(.+)$") {
                        $config.LogGroupName = $matches[1]
                        Write-Log -Message "CloudWatch log group identified: $($config.LogGroupName)" -Level "INFO"
                    } elseif (-not $flowLog.LogDestination -or $flowLog.LogDestination -eq "") {
                        # Handle case where LogDestination is empty - search for VPC Flow Logs groups
                        Write-Log -Message "CloudWatch flow log $($flowLog.FlowLogId) has empty LogDestination - searching for VPC Flow Logs groups" -Level "WARN"
                        
                        # Search for VPC Flow Logs log groups using pattern matching
                        $vpcFlowLogGroups = $allLogGroups | Where-Object { 
                            $_.LogGroupName -match "vpc.*flow|flow.*vpc|VPCFlow" -or 
                            $_.LogGroupName -like "*VPCFlowLogsLogGroup*" -or
                            $_.LogGroupName -like "*flowlogs*"
                        }
                        
                        if ($vpcFlowLogGroups.Count -gt 0) {
                            # Use the first matching VPC Flow Logs group
                            $config.LogGroupName = $vpcFlowLogGroups[0].LogGroupName
                            Write-Log -Message "Found VPC Flow Logs log group: $($config.LogGroupName) for flow log $($flowLog.FlowLogId)" -Level "INFO"
                        } else {
                            # Fall back to common default log group names
                            $defaultLogGroups = @("/aws/vpc/flowlogs", "/vpc/flowlogs", "VPCFlowLogs", "vpc-flow-logs")
                            foreach ($defaultGroup in $defaultLogGroups) {
                                try {
                                    $logGroupTest = Get-CWLLogGroup -LogGroupNamePrefix $defaultGroup -ErrorAction SilentlyContinue
                                    if ($logGroupTest) {
                                        $config.LogGroupName = $defaultGroup
                                        Write-Log -Message "Found existing default log group: $defaultGroup for flow log $($flowLog.FlowLogId)" -Level "INFO"
                                        break
                                    }
                                } catch {
                                    # Continue to next default
                                }
                            }
                        }
                        
                        if (-not $config.LogGroupName) {
                            Write-Log -Message "No valid log group found for CloudWatch flow log $($flowLog.FlowLogId)" -Level "WARN"
                            continue
                        }
                    }
                    
                    # Only add configs with valid log group names
                    if ($config.LogGroupName) {
                        $vpcFlowLogConfigs[$vpc] += $config
                    }
                }
                Write-Log -Message "VPC $vpc has $($vpcFlowLogConfigs[$vpc].Count) usable CloudWatch flow log configurations" -Level "INFO"
            } else {
                Write-Log -Message "VPC $vpc has no flow logs configured" -Level "WARN"
            }
        }
        
        # Create ENI flow log mapping from VPC-level configurations
        $eniFlowLogConfigs = @{}
        foreach ($eni in $allEnis) {
            # Assign VPC-level flow logs to this ENI
            if ($vpcFlowLogConfigs.ContainsKey($eni.VpcId) -and $vpcFlowLogConfigs[$eni.VpcId].Count -gt 0) {
                $eniFlowLogConfigs[$eni.NetworkInterfaceId] = $vpcFlowLogConfigs[$eni.VpcId]
                
                $logGroupNames = $vpcFlowLogConfigs[$eni.VpcId] | ForEach-Object { $_.LogGroupName }
                Write-Log -Message "ENI $($eni.NetworkInterfaceId): Using VPC-level CloudWatch logs: $($logGroupNames -join ', ')" -Level "INFO"
            } else {
                Write-Log -Message "ENI $($eni.NetworkInterfaceId): No VPC-level flow logs available" -Level "WARN"
            }
        }
        
        $eniWithFlowLogs = $eniFlowLogConfigs.Keys.Count
        Write-Log -Message "Assigned VPC-level flow logs to $eniWithFlowLogs out of $($allEnis.Count) ENIs" -Level "INFO"

        # Debug: Show flow log summary
        if ($eniWithFlowLogs -eq 0) {
            Write-Log -Message "=== FLOW LOG DISCOVERY DEBUG ===" -Level "WARN"
            Write-Log -Message "No ENIs have flow logs configured. Checking overall flow log status..." -Level "WARN"
            
            # Check if there are ANY flow logs in this account/region
            $allFlowLogs = Get-EC2FlowLog
            Write-Log -Message "Total flow logs in account: $($allFlowLogs.Count)" -Level "WARN"
            
            $activeFlowLogs = $allFlowLogs | Where-Object { $_.FlowLogStatus -eq "ACTIVE" }
            Write-Log -Message "Active flow logs: $($activeFlowLogs.Count)" -Level "WARN"
            
            foreach ($flowLog in $activeFlowLogs) {
                $resourceId = if ($flowLog.ResourceIds -and $flowLog.ResourceIds.Count -gt 0) { $flowLog.ResourceIds[0] } else { "NULL" }
                Write-Log -Message "  - FlowLog $($flowLog.FlowLogId): $($flowLog.ResourceType) $resourceId -> $($flowLog.LogDestinationType) $($flowLog.LogDestination)" -Level "WARN"
            }
            Write-Log -Message "=== END FLOW LOG DEBUG ===" -Level "WARN"
        }

        $sgWithIngressCount = 0
        $totalIngressRules = 0
        $rulesWithEnis = 0
        $rulesWithIpv4Cidrs = 0
        $rulesWithIpv6Cidrs = 0
        $rulesWithSgRefs = 0
        $rulesWithPrefixLists = 0

        foreach ($sg in $securityGroups) {
            $ingressCount = $sg.IpPermissions.Count
            if ($ingressCount -gt 0) {
                $sgWithIngressCount++
                $totalIngressRules += $ingressCount
                Write-Log -Message "SG $($sg.GroupId) ($($sg.GroupName)) has $ingressCount ingress rules" -Level "INFO"
            }

            foreach ($ingress in $sg.IpPermissions) {
                $protocol = $ingress.IpProtocol
                $fromPort = $ingress.FromPort
                $toPort   = $ingress.ToPort

                # Simple, direct detection
                $hasIpv4 = $false
                $hasIpv6 = $false
                $hasSgRefs = $false
                $hasPrefixLists = $false

                # Check IPv4 ranges
                if ($ingress.Ipv4Ranges -and $ingress.Ipv4Ranges.Count -gt 0) {
                    $hasIpv4 = $true
                    $rulesWithIpv4Cidrs++
                    Write-Log -Message "✓ IPv4 CIDR detected in SG $($sg.GroupId): $($ingress.Ipv4Ranges.Count) ranges" -Level "INFO"
                }

                # Check IPv6 ranges  
                if ($ingress.Ipv6Ranges -and $ingress.Ipv6Ranges.Count -gt 0) {
                    $hasIpv6 = $true
                    $rulesWithIpv6Cidrs++
                    Write-Log -Message "✓ IPv6 CIDR detected in SG $($sg.GroupId): $($ingress.Ipv6Ranges.Count) ranges" -Level "INFO"
                }

                # Check SG references
                if ($ingress.UserIdGroupPairs -and $ingress.UserIdGroupPairs.Count -gt 0) {
                    $hasSgRefs = $true
                    $rulesWithSgRefs++
                    Write-Log -Message "✓ SG Reference detected in SG $($sg.GroupId): $($ingress.UserIdGroupPairs.Count) refs" -Level "INFO"
                }

                # Check Prefix Lists
                if ($ingress.PrefixListIds -and $ingress.PrefixListIds.Count -gt 0) {
                    $hasPrefixLists = $true
                    $rulesWithPrefixLists++
                    Write-Log -Message "✓ Prefix List detected in SG $($sg.GroupId): $($ingress.PrefixListIds.Count) lists" -Level "INFO"
                }

                # Get ENIs using this SG from cached results
                $enis = $allEnis | Where-Object { $_.Groups.GroupId -contains $sg.GroupId }
                
                if ($enis.Count -gt 0) {
                    $rulesWithEnis++
                }

                # Process IPv4 CIDR ranges with CloudWatch analysis
                if ($hasIpv4) {
                    Write-Log -Message "Processing IPv4 CIDR rule for SG $($sg.GroupId) with $($enis.Count) ENIs" -Level "INFO"
                    foreach ($eni in $enis) {
                        foreach ($ipRange in $ingress.Ipv4Ranges) {
                            $cidr = $ipRange.CidrIp
                            if (-not $cidr) { continue }
                            Write-Log -Message "Analyzing CIDR $cidr on ENI $($eni.NetworkInterfaceId)" -Level "INFO"
                            
                            # Handle special cases for ports
                            $queryFromPort = if ($null -eq $fromPort -or $fromPort -eq -1) { 0 } else { $fromPort }
                            $queryToPort = if ($null -eq $toPort -or $toPort -eq -1) { 65535 } else { $toPort }
                            
                            # Handle CIDR range for CloudWatch query
                            $queryFilter = ""
                            if ($cidr.EndsWith("/32")) {
                                # Single IP address - can use direct comparison
                                $singleIp = $cidr.Replace("/32", "")
                                $queryFilter = "and srcAddr = '$singleIp'"
                            } elseif ($cidr.Contains("/")) {
                                # CIDR range - use prefix matching where possible
                                $parts = $cidr.Split("/")
                                $network = $parts[0]
                                $prefixLength = [int]$parts[1]
                                
                                if ($prefixLength -ge 24) {
                                    # For /24 and smaller, we can use prefix matching
                                    $networkPrefix = $network.Substring(0, $network.LastIndexOf("."))
                                    $queryFilter = "and srcAddr like '$networkPrefix.%'"
                                } else {
                                    # For larger networks, skip CIDR filtering and just check port/interface
                                    Write-Log -Message "CIDR $cidr is too large for efficient CloudWatch filtering - checking all traffic on ENI" -Level "WARN"
                                    $queryFilter = ""
                                }
                            } else {
                                # Not a CIDR, treat as single IP
                                $queryFilter = "and srcAddr = '$cidr'"
                            }
                            
                            # Check if this ENI has flow logs configured
                            $eniFlowLogs = $eniFlowLogConfigs[$eni.NetworkInterfaceId]
                            if (-not $eniFlowLogs -or $eniFlowLogs.Count -eq 0) {
                                Write-Log -Message "No VPC-level flow logs found for ENI $($eni.NetworkInterfaceId) - skipping analysis" -Level "WARN"
                                
                                $allResults += [pscustomobject]@{
                                    AccountId = $accountId
                                    Region = $currentRegion
                                    ProfileName = $profileName
                                    SecurityGroupId = $sg.GroupId
                                    SecurityGroupName = $sg.GroupName
                                    VpcId = $sg.VpcId
                                    Protocol = $protocol
                                    FromPort = $fromPort
                                    ToPort = $toPort
                                    SourceType = "IPv4_CIDR"
                                    Source = $cidr
                                    ENI = $eni.NetworkInterfaceId
                                    ENICount = $enis.Count
                                    MatchesFound = "NO_VPC_FLOW_LOGS"
                                    IsUnused = $false
                                    QueryTimestamp = Get-Date
                                    FlowLogConfig = "None"
                                }
                                continue
                            }
                            
                            # Process each VPC-level flow log configuration for this ENI
                            foreach ($flowLogConfig in $eniFlowLogs) {
                                # Use the CloudWatch Log Group (we only have CloudWatch configs now)
                                $logGroupName = $flowLogConfig.LogGroupName
                                if (-not $logGroupName) {
                                    Write-Log -Message "No CloudWatch Log Group found for ENI $($eni.NetworkInterfaceId)" -Level "WARN"
                                    continue
                                }
                                
                                Write-Log -Message "Using VPC-level log group '$logGroupName' for ENI $($eni.NetworkInterfaceId)" -Level "INFO"
                            
                            # Start with a simple test query to see if the log group has data
                            $testQuery = @"
fields @timestamp, @message
| limit 1
"@

                            Write-Log -Message "Testing log group accessibility with simple query" -Level "INFO"
                            try {
                                $testStartQuery = Start-CWLQuery `
                                    -LogGroupName $logGroupName `
                                    -StartTime (Get-Date $startTime -UFormat %s) `
                                    -EndTime (Get-Date $endTime -UFormat %s) `
                                    -QueryString $testQuery
                                
                                # Handle different response formats from Start-CWLQuery
                                $testQueryId = $null
                                if ($testStartQuery -is [string]) {
                                    # Direct string response (newer AWS Tools version)
                                    $testQueryId = $testStartQuery
                                } elseif ($testStartQuery.QueryId) {
                                    # Object with QueryId property (older format)
                                    $testQueryId = $testStartQuery.QueryId
                                }
                                    
                                if ($testQueryId) {
                                    Write-Log -Message "Test query started successfully with ID: $testQueryId" -Level "INFO"
                                    
                                    # Wait briefly for test query to complete
                                    Start-Sleep -Seconds 3
                                    $testResult = Get-CWLQueryResult -QueryId $testQueryId
                                    Write-Log -Message "Test query status: $($testResult.Status)" -Level "INFO"
                                    
                                    if ($testResult.Status -eq "Complete") {
                                        Write-Log -Message "Log group has data - proceeding with actual query" -Level "INFO"
                                    } else {
                                        Write-Log -Message "Test query did not complete successfully" -Level "WARN"
                                    }
                                } else {
                                    Write-Log -Message "Test query failed to start" -Level "WARN"
                                    throw "Test query failed - cannot proceed with analysis"
                                }
                            } catch {
                                Write-Log -Message "Test query failed: $($_.Exception.Message)" -Level "WARN"
                                throw "Test query failed - log group may be empty or inaccessible"
                            }

                            # CloudWatch Logs Insights query to check ACCEPT traffic
                            # VPC Flow Logs format: account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes windowstart windowend action flowlogstatus
                            # Build a more flexible query that works with VPC Flow Logs
                            $portFilter = ""
                            if ($queryFromPort -eq $queryToPort) {
                                $portFilter = "and @message like / $queryFromPort /"
                            } else {
                                # For port ranges, we'll need to be more flexible
                                $portFilter = ""
                            }
                            
                            $srcAddrFilter = ""
                            if ($queryFilter -and $cidr.EndsWith("/32")) {
                                $singleIp = $cidr.Replace("/32", "")
                                $srcAddrFilter = "and @message like / $singleIp /"
                            }
                            
                            $query = @"
fields @timestamp, @message
| filter @message like / $($eni.NetworkInterfaceId) /
  and @message like / ACCEPT /
  $portFilter
  $srcAddrFilter
| stats count() as matchCount
"@

                            try {
                                # Validate log group exists before querying
                                try {
                                    $logGroupExists = Get-CWLLogGroup -LogGroupNamePrefix $logGroupName | Where-Object { $_.LogGroupName -eq $logGroupName }
                                    if (-not $logGroupExists) {
                                        Write-Log -Message "Log group '$logGroupName' does not exist or is not accessible" -Level "WARN"
                                        throw "Log group not found: $logGroupName"
                                    }
                                } catch {
                                    Write-Log -Message "Failed to validate log group '$logGroupName': $($_.Exception.Message)" -Level "WARN"
                                    throw "Log group validation failed: $($_.Exception.Message)"
                                }

                                Write-Log -Message "Starting CloudWatch Logs Insights query for log group: $logGroupName" -Level "INFO"
                                Write-Log -Message "Query: $query" -Level "INFO"
                                Write-Log -Message "Time range: $(Get-Date $startTime) to $(Get-Date $endTime)" -Level "INFO"
                                
                                $startQuery = Start-CWLQuery `
                                    -LogGroupName $logGroupName `
                                    -StartTime (Get-Date $startTime -UFormat %s) `
                                    -EndTime (Get-Date $endTime -UFormat %s) `
                                    -QueryString $query

                                # Handle different response formats from Start-CWLQuery
                                $queryId = $null
                                if ($startQuery -is [string]) {
                                    # Direct string response (newer AWS Tools version)
                                    $queryId = $startQuery
                                } elseif ($startQuery.QueryId) {
                                    # Object with QueryId property (older format)
                                    $queryId = $startQuery.QueryId
                                }

                                # Validate that query was started successfully
                                if (-not $queryId) {
                                    if (-not $startQuery) {
                                        Write-Log -Message "Start-CWLQuery returned null" -Level "ERROR"
                                        throw "Query start failed - Start-CWLQuery returned null"
                                    } else {
                                        Write-Log -Message "Start-CWLQuery returned object but no QueryId: $($startQuery | ConvertTo-Json -Depth 2)" -Level "ERROR"
                                        throw "Query start failed - no QueryId returned"
                                    }
                                }

                                Write-Log -Message "CloudWatch query started with ID: $queryId" -Level "INFO"

                                # Wait for query completion and get results
                                $maxWaitSeconds = 60
                                $elapsedSeconds = 0
                                do {
                                    Start-Sleep -Seconds 2
                                    $elapsedSeconds += 2
                                    try {
                                        $queryResult = Get-CWLQueryResult -QueryId $queryId
                                        $queryStatus = $queryResult.Status
                                        Write-Log -Message "Query status: $queryStatus (elapsed: ${elapsedSeconds}s)" -Level "INFO"
                                    } catch {
                                        Write-Log -Message "Error checking query status: $($_.Exception.Message)" -Level "WARN"
                                        $queryStatus = "Failed"
                                        break
                                    }
                                    
                                    if ($elapsedSeconds -ge $maxWaitSeconds) {
                                        Write-Log -Message "CloudWatch query timeout after ${maxWaitSeconds} seconds" -Level "WARN"
                                        $queryStatus = "Timeout"
                                        break
                                    }
                                } while ($queryStatus -eq "Running")

                                $matchCount = 0
                                if ($queryStatus -eq "Complete" -and $queryResult.Results.Count -gt 0) {
                                    # Find the matchCount field in the results
                                    foreach ($resultRow in $queryResult.Results) {
                                        foreach ($field in $resultRow) {
                                            if ($field.Field -eq "matchCount" -and $null -ne $field.Value) {
                                                $matchCount = [int]$field.Value
                                                break
                                            }
                                        }
                                        if ($matchCount -gt 0) { break }
                                    }
                                    Write-Log -Message "CloudWatch query completed successfully - found $matchCount matches" -Level "INFO"
                                } elseif ($queryStatus -eq "Complete") {
                                    Write-Log -Message "CloudWatch query completed with no results" -Level "INFO"
                                } else {
                                    Write-Log -Message "CloudWatch query failed with status: $queryStatus" -Level "WARN"
                                }

                                $allResults += [pscustomobject]@{
                                    AccountId = $accountId
                                    Region = $currentRegion
                                    ProfileName = $profileName
                                    SecurityGroupId = $sg.GroupId
                                    SecurityGroupName = $sg.GroupName
                                    VpcId = $sg.VpcId
                                    Protocol = $protocol
                                    FromPort = $fromPort
                                    ToPort = $toPort
                                    SourceType = "IPv4_CIDR"
                                    Source = $cidr
                                    ENI = $eni.NetworkInterfaceId
                                    ENICount = $enis.Count
                                    MatchesFound = if ($queryStatus -eq "Complete") { $matchCount } elseif ($queryStatus -eq "Timeout") { "QUERY_TIMEOUT" } else { "QUERY_FAILED" }
                                    IsUnused = ($queryStatus -eq "Complete" -and $matchCount -eq 0)
                                    QueryTimestamp = Get-Date
                                    FlowLogConfig = "VPC-CWL:$logGroupName"
                                }
                            } catch {
                                Write-Log -Message "Failed to execute CloudWatch Logs Insights query for SG $($sg.GroupId), ENI $($eni.NetworkInterfaceId), LogGroup $logGroupName : $($_.Exception.Message)" -Level "WARN"
                                # Add entry with error indication
                                $allResults += [pscustomobject]@{
                                    AccountId = $accountId
                                    Region = $currentRegion
                                    ProfileName = $profileName
                                    SecurityGroupId = $sg.GroupId
                                    SecurityGroupName = $sg.GroupName
                                    VpcId = $sg.VpcId
                                    Protocol = $protocol
                                    FromPort = $fromPort
                                    ToPort = $toPort
                                    SourceType = "IPv4_CIDR"
                                    Source = $cidr
                                    ENI = $eni.NetworkInterfaceId
                                    ENICount = $enis.Count
                                    MatchesFound = "ERROR"
                                    IsUnused = $false
                                    QueryTimestamp = Get-Date
                                    FlowLogConfig = "VPC-CWL:$logGroupName"
                                }
                            }
                            } # End of flow log config loop
                        }
                    }
                } else {
                    # For non-analyzable rules, create ONE entry per rule (not per ENI)
                    
                    # Process IPv6 CIDR ranges (one entry per range)
                    if ($hasIpv6) {
                        foreach ($ipv6Range in $ingress.Ipv6Ranges) {
                            if (-not $ipv6Range.CidrIpv6) { continue }
                            
                            $allResults += [pscustomobject]@{
                                AccountId = $accountId
                                Region = $currentRegion
                                ProfileName = $profileName
                                SecurityGroupId = $sg.GroupId
                                SecurityGroupName = $sg.GroupName
                                VpcId = $sg.VpcId
                                Protocol = $protocol
                                FromPort = $fromPort
                                ToPort = $toPort
                                SourceType = "IPv6_CIDR"
                                Source = $ipv6Range.CidrIpv6
                                ENI = "N/A (Rule-based)"
                                ENICount = $enis.Count
                                MatchesFound = "IPv6_NOT_SUPPORTED"
                                IsUnused = $false
                                QueryTimestamp = Get-Date
                                FlowLogConfig = "N/A"
                            }
                        }
                    }
                    
                    # Process Security Group references (one entry per reference)
                    if ($hasSgRefs) {
                        foreach ($sgRef in $ingress.UserIdGroupPairs) {
                            if (-not $sgRef.GroupId) { continue }
                            
                            $allResults += [pscustomobject]@{
                                AccountId = $accountId
                                Region = $currentRegion
                                ProfileName = $profileName
                                SecurityGroupId = $sg.GroupId
                                SecurityGroupName = $sg.GroupName
                                VpcId = $sg.VpcId
                                Protocol = $protocol
                                FromPort = $fromPort
                                ToPort = $toPort
                                SourceType = "SecurityGroup"
                                Source = $sgRef.GroupId
                                ENI = "N/A (Rule-based)"
                                ENICount = $enis.Count
                                MatchesFound = "SG_REF_NOT_SUPPORTED"
                                IsUnused = $false
                                QueryTimestamp = Get-Date
                                FlowLogConfig = "N/A"
                            }
                        }
                    }
                    
                    # Process Prefix Lists (one entry per prefix list)
                    if ($hasPrefixLists) {
                        foreach ($prefixList in $ingress.PrefixListIds) {
                            if (-not $prefixList.PrefixListId) { continue }
                            
                            $allResults += [pscustomobject]@{
                                AccountId = $accountId
                                Region = $currentRegion
                                ProfileName = $profileName
                                SecurityGroupId = $sg.GroupId
                                SecurityGroupName = $sg.GroupName
                                VpcId = $sg.VpcId
                                Protocol = $protocol
                                FromPort = $fromPort
                                ToPort = $toPort
                                SourceType = "PrefixList"
                                Source = $prefixList.PrefixListId
                                ENI = "N/A (Rule-based)"
                                ENICount = $enis.Count
                                MatchesFound = "PREFIX_LIST_NOT_SUPPORTED"
                                IsUnused = $false
                                QueryTimestamp = Get-Date
                                FlowLogConfig = "N/A"
                            }
                        }
                    }
                }
            }
        }
        
        Write-Log -Message "Debug Summary for account ${accountId}:" -Level "INFO"
        Write-Log -Message "  - Security groups with ingress rules: $sgWithIngressCount" -Level "INFO"
        Write-Log -Message "  - Total ingress rules: $totalIngressRules" -Level "INFO"
        Write-Log -Message "  - Rules with associated ENIs: $rulesWithEnis" -Level "INFO"
        Write-Log -Message "  - Rules with IPv4 CIDR ranges: $rulesWithIpv4Cidrs" -Level "INFO"
        Write-Log -Message "  - Rules with IPv6 CIDR ranges: $rulesWithIpv6Cidrs" -Level "INFO"
        Write-Log -Message "  - Rules with Security Group references: $rulesWithSgRefs" -Level "INFO"
        Write-Log -Message "  - Rules with Prefix Lists: $rulesWithPrefixLists" -Level "INFO"
        Write-Log -Message "Completed processing profile: $profileName" -Level "INFO"
    } catch {
        Write-Log -Message "Error processing profile ${profileName}: $($_.Exception.Message)" -Level "ERROR"
        continue
    }
}

# Export consolidated results to CSV
Write-Log -Message "Exporting results to: $OutputFile" -Level "INFO"
$allResults | Export-Csv -Path $OutputFile -NoTypeInformation

# Show summary statistics
$totalRules = $allResults.Count
$ipv4Rules = ($allResults | Where-Object { $_.SourceType -eq "IPv4_CIDR" }).Count
$ipv6Rules = ($allResults | Where-Object { $_.SourceType -eq "IPv6_CIDR" }).Count
$sgRefRules = ($allResults | Where-Object { $_.SourceType -eq "SecurityGroup" }).Count
$prefixListRules = ($allResults | Where-Object { $_.SourceType -eq "PrefixList" }).Count
$unusedRules = ($allResults | Where-Object { $_.IsUnused -eq $true }).Count
$errorRules = ($allResults | Where-Object { $_.MatchesFound -eq "ERROR" -or $_.MatchesFound -eq "QUERY_FAILED" -or $_.MatchesFound -eq "QUERY_TIMEOUT" }).Count

# Calculate flow log configuration statistics
$flowLogStats = $allResults | Where-Object { $_.FlowLogConfig -ne "N/A" } | Group-Object FlowLogConfig
$noFlowLogsCount = ($allResults | Where-Object { $_.MatchesFound -eq "NO_VPC_FLOW_LOGS" }).Count

Write-Host "`n=== Security Group Utilisation Analysis Results ===" -ForegroundColor Cyan
Write-Host "Total rule entries: $totalRules" -ForegroundColor White
Write-Host "  - IPv4 CIDR rules (analyzed): $ipv4Rules" -ForegroundColor Green
Write-Host "  - IPv6 CIDR rules (documented): $ipv6Rules" -ForegroundColor Yellow
Write-Host "  - Security Group references (documented): $sgRefRules" -ForegroundColor Yellow
Write-Host "  - Prefix List rules (documented): $prefixListRules" -ForegroundColor Yellow
Write-Host "Unused IPv4 rules found: $unusedRules" -ForegroundColor $(if ($unusedRules -gt 0) { "Red" } else { "Green" })
Write-Host "Rules with analysis errors: $errorRules" -ForegroundColor $(if ($errorRules -gt 0) { "Red" } else { "Green" })

# Show flow log configuration summary
Write-Host "`n=== VPC-Level Flow Logs Configuration Summary ===" -ForegroundColor Cyan
if ($flowLogStats.Count -gt 0) {
    $flowLogStats | ForEach-Object {
        $configType = if ($_.Name.StartsWith("VPC-CWL:")) { "VPC CloudWatch Logs" } 
                     else { "Other" }
        Write-Host "  - $configType ($($_.Name)): $($_.Count) rules" -ForegroundColor White
    }
}
if ($noFlowLogsCount -gt 0) {
    Write-Host "  - No VPC flow logs configured: $noFlowLogsCount rules" -ForegroundColor Yellow
}

Write-Host "`nResults exported to: $OutputFile" -ForegroundColor Green

# Show unused rules summary
if ($unusedRules -gt 0) {
    Write-Host "`n=== Unused IPv4 CIDR Rules Summary ===" -ForegroundColor Yellow
    $allResults | Where-Object { $_.IsUnused -eq $true } | 
        Select-Object AccountId, SecurityGroupId, SecurityGroupName, Protocol, FromPort, ToPort, Source, ENICount | 
        Format-Table -AutoSize
} else {
    Write-Host "`nNo unused IPv4 CIDR rules found!" -ForegroundColor Green
}

# Show documentation summary for non-analyzable rules
$nonAnalyzableRules = ($allResults | Where-Object { $_.SourceType -ne "IPv4_CIDR" }).Count
if ($nonAnalyzableRules -gt 0) {
    Write-Host "`n=== Non-Analyzable Rules (Documented Only) ===" -ForegroundColor Cyan
    $allResults | Where-Object { $_.SourceType -ne "IPv4_CIDR" } | 
        Group-Object SourceType | 
        Select-Object Name, Count | 
        Format-Table -AutoSize -Property @{Name="Rule Type"; Expression={$_.Name}}, @{Name="Count"; Expression={$_.Count}}
}

Write-Log -Message "Security Group utilisation analysis completed successfully" -Level "INFO"