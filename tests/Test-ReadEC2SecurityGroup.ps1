# Test-SecurityGroupRule.ps1
# PowerShell script to test the logic for checking if a security group rule exists
# Uses AWS.Tools.EC2 module to query the security group and compare rules
# Supports dry run mode to simulate the check without querying AWS
# Ignores Description for rule uniqueness, but logs description mismatches
# Handles CIDR (Ipv4Ranges), security group, IPv6, and prefix list sources, and the default egress rule
# Outputs all existing ingress and egress rules found in the security group
# Fixed to use Ipv4Ranges instead of IpRanges for correct CIDR detection
# Enhanced with case-insensitive protocol comparison, robust port handling, and detailed debugging

param(
    [Parameter(Mandatory=$false)]
    [string]$GroupId = "sg-05248fe4ae7bf3b48",  # Replace with your actual security group ID
    [Parameter(Mandatory=$false)]
    [string]$ProfileName = "sso-production-AdministratorAccess",  # Replace with your actual AWS profile name
    [Parameter(Mandatory=$false)]
    [string]$Region = "eu-west-1",  # Replace with your actual AWS region
    [Parameter(Mandatory=$false)]
    [string]$PSModulesPath = "C:\github\psmodules",  # Adjust to your actual PSModulesPath
    [Parameter(Mandatory=$false)]
    [switch]$DryRun
)

# Determine the script's root directory for reliable path resolution
$ScriptPath = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
$LogFilePath = (Join-Path $ScriptPath "logs\Test_SG_Rule_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log")

# Function to write logs
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $prefix = if ($DryRun) { "[DRYRUN] " } else { "" }
    $logMessage = "[$timestamp] [$Level] $prefix$Message"
    Write-Host $logMessage
    Add-Content -Path $LogFilePath -Value $logMessage
}

# Function to format rule output
function Format-RuleOutput {
    param (
        $Rule,
        [string]$RuleType
    )
    $output = @()
    $protocol = if ($null -eq $Rule.IpProtocol -or $Rule.IpProtocol -eq "-1") { "all" } else { $Rule.IpProtocol }
    $ports = if ($null -eq $Rule.FromPort -or $null -eq $Rule.ToPort) { "-" } else { "$($Rule.FromPort)-$($Rule.ToPort)" }

    if ($Rule.Ipv4Ranges -and $Rule.Ipv4Ranges.Count -gt 0) {
        foreach ($ipRange in $Rule.Ipv4Ranges) {
            $output += "${RuleType}: Protocol=$protocol, Ports=$ports, Source=$($ipRange.CidrIp), Description='$($ipRange.Description)'"
        }
    }
    if ($Rule.Ipv6Ranges -and $Rule.Ipv6Ranges.Count -gt 0) {
        foreach ($ipv6Range in $Rule.Ipv6Ranges) {
            $output += "${RuleType}: Protocol=$protocol, Ports=$ports, Source=$($ipv6Range.CidrIpv6), Description='$($ipv6Range.Description)'"
        }
    }
    if ($Rule.PrefixListIds -and $Rule.PrefixListIds.Count -gt 0) {
        foreach ($prefixList in $Rule.PrefixListIds) {
            $output += "${RuleType}: Protocol=$protocol, Ports=$ports, Source=$($prefixList.PrefixListId), Description='$($prefixList.Description)'"
        }
    }
    if ($Rule.UserIdGroupPairs -and $Rule.UserIdGroupPairs.Count -gt 0) {
        foreach ($groupPair in $Rule.UserIdGroupPairs) {
            $output += "${RuleType}: Protocol=$protocol, Ports=$ports, Source=$($groupPair.GroupId), Description='$($groupPair.Description)'"
        }
    }
    if (-not $output) {
        $output += "${RuleType}: Protocol=$protocol, Ports=$ports, Source=None, Description='None'"
    }
    return $output
}

try {
    # Ensure the log directory exists
    $logDir = Split-Path -Path $LogFilePath -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -ErrorAction Stop > $null
    }

    # Import required AWS.Tools modules
    try {
        Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.Common") -ErrorAction Stop
        Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.EC2") -ErrorAction Stop
        Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.SecurityToken") -ErrorAction Stop
        $moduleVersion = (Get-Module -Name AWS.Tools.EC2).Version.ToString()
        Write-Log "Loaded AWS.Tools.EC2 version: $moduleVersion" "INFO"
        if ($moduleVersion -eq "5.0.11") {
            Write-Log "AWS.Tools.EC2 version 5.0.11 detected. Consider updating to the latest version to avoid potential bugs: Install-Module -Name AWS.Tools.EC2 -Scope CurrentUser -Force" "WARN"
        }
    } catch {
        Write-Log "Failed to import modules from $PSModulesPath. Error: $($_.Exception.Message)" "ERROR"
        exit 1
    }

    # Set AWS credentials and region
    if (-not $DryRun) {
        try {
            Set-AWSCredential -ProfileName $ProfileName -ErrorAction Stop
            Set-DefaultAWSRegion -Region $Region -ErrorAction Stop
            Get-STSCallerIdentity -ProfileName $ProfileName -Region $Region -ErrorAction Stop > $null
            Write-Log "Successfully set credentials and region ($Region) for profile: $ProfileName"
        } catch {
            Write-Log "Failed to set credentials for profile: $ProfileName. Error: $($_.Exception.Message)" "ERROR"
            exit 1
        }
    } else {
        Write-Log "Dry run: Skipping credential and region setup for profile: $ProfileName" "INFO"
    }

    # Define a sample rule configuration (simulating Excel input)
    $config = [PSCustomObject]@{
        GroupName    = "cloudwickprod-webserver"
        RuleType     = "ingress"  # Can be 'ingress' or 'egress'
        Protocol     = "tcp"
        FromPort     = 22
        ToPort       = 22
        Source       = "10.0.0.0/16"  # Can be CIDR, security group ID, or prefix list ID
        Description  = "SSH access from VPC"
    }

    Write-Log "Testing rule existence for group ID: $GroupId, Rule: $($config.RuleType) $($config.Protocol) $($config.FromPort)-$($config.ToPort) $($config.Source)"

    # Check for existing rule
    $ruleExists = $false
    $descriptionMismatch = $false
    $existingDescription = $null

    if ($DryRun) {
        Write-Log "Dry run: Skipping rule existence check for group ID: $GroupId" "INFO"
        Write-Log "Dry run: Assuming rule does not exist and would be added: $($config.RuleType) $($config.Protocol) $($config.FromPort)-$($config.ToPort) $($config.Source) with description '$($config.Description)'" "INFO"
    } else {
        try {
            # Retrieve the security group
            $sg = Get-EC2SecurityGroup -GroupId $GroupId -ProfileName $ProfileName -Region $Region -ErrorAction Stop
            Write-Log "Retrieved security group with ID: $GroupId" "DEBUG"

            # Log raw security group response for debugging
            $rawSgJson = $sg | ConvertTo-Json -Depth 5 -Compress
            Write-Log "Raw security group response: $rawSgJson" "DEBUG"

            # Output all existing rules
            Write-Log "Existing rules for group ID: $GroupId" "DEBUG"
            $ingressRules = $sg.IpPermissions
            $egressRules = $sg.IpPermissionsEgress

            if ($ingressRules.Count -eq 0) {
                Write-Log "No ingress rules found for group ID: $GroupId" "DEBUG"
            } else {
                foreach ($rule in $ingressRules) {
                    $ruleOutputs = Format-RuleOutput -Rule $rule -RuleType "Ingress"
                    foreach ($output in $ruleOutputs) {
                        Write-Log $output "DEBUG"
                    }
                }
            }

            if ($egressRules.Count -eq 0) {
                Write-Log "No egress rules found for group ID: $GroupId" "DEBUG"
            } else {
                foreach ($rule in $egressRules) {
                    $ruleOutputs = Format-RuleOutput -Rule $rule -RuleType "Egress"
                    foreach ($output in $ruleOutputs) {
                        Write-Log $output "DEBUG"
                    }
                }
            }

            # Select the relevant rule set (ingress or egress) for checking the specific rule
            $rules = if ($config.RuleType -eq 'ingress') { $sg.IpPermissions } else { $sg.IpPermissionsEgress }
            Write-Log "Checking $($config.RuleType) rules for group ID: $GroupId. Found $($rules.Count) rules." "DEBUG"

            # Iterate through rules to find a match
            foreach ($rule in $rules) {
                # Log detailed rule properties for debugging
                $ruleJson = $rule | ConvertTo-Json -Depth 5 -Compress
                $protocolType = if ($null -eq $rule.IpProtocol) { "null" } else { $rule.IpProtocol.GetType().Name }
                $fromPortType = if ($null -eq $rule.FromPort) { "null" } else { $rule.FromPort.GetType().Name }
                $toPortType = if ($null -eq $rule.ToPort) { "null" } else { $rule.ToPort.GetType().Name }
                Write-Log "Evaluating rule: Protocol=$($rule.IpProtocol) (Type=$protocolType), FromPort=$($rule.FromPort) (Type=$fromPortType), ToPort=$($rule.ToPort) (Type=$toPortType), Ipv4Ranges=$($rule.Ipv4Ranges | ConvertTo-Json -Compress -Depth 3), Ipv6Ranges=$($rule.Ipv6Ranges | ConvertTo-Json -Compress -Depth 3), PrefixListIds=$($rule.PrefixListIds | ConvertTo-Json -Compress -Depth 3), RawRule=$ruleJson" "DEBUG"

                $configProtocol = $config.Protocol.ToLower()
                $ruleProtocol = if ($null -eq $rule.IpProtocol -or $rule.IpProtocol -eq "-1") { "all" } else { $rule.IpProtocol.ToLower() }
                $configFromPort = [int]($config.FromPort ?? -1)
                $configToPort = [int]($config.ToPort ?? -1)
                $ruleFromPort = [int]($rule.FromPort ?? -1)
                $ruleToPort = [int]($rule.ToPort ?? -1)

                if ($ruleProtocol -eq $configProtocol -and
                    $ruleFromPort -eq $configFromPort -and
                    $ruleToPort -eq $configToPort) {
                    if ($config.Source -match '^sg-') {
                        # Check for security group source
                        foreach ($groupPair in $rule.UserIdGroupPairs) {
                            Write-Log "Checking UserIdGroupPair: GroupId=$($groupPair.GroupId), Description='$($groupPair.Description)'" "DEBUG"
                            if ($groupPair.GroupId -eq $config.Source) {
                                $ruleExists = $true
                                $existingDescription = $groupPair.Description
                                if ($groupPair.Description -ne $config.Description) {
                                    $descriptionMismatch = $true
                                }
                                break
                            }
                        }
                    } elseif ($config.Source -match '^pl-') {
                        # Check for prefix list source
                        foreach ($prefixList in $rule.PrefixListIds) {
                            Write-Log "Checking PrefixListId: PrefixListId=$($prefixList.PrefixListId), Description='$($prefixList.Description)'" "DEBUG"
                            if ($prefixList.PrefixListId -eq $config.Source) {
                                $ruleExists = $true
                                $existingDescription = $prefixList.Description
                                if ($prefixList.Description -ne $config.Description) {
                                    $descriptionMismatch = $true
                                }
                                break
                            }
                        }
                    } else {
                        # Check for CIDR source (IPv4 or IPv6)
                        foreach ($ipRange in $rule.Ipv4Ranges) {
                            $normalizedCidr = $ipRange.CidrIp ? $ipRange.CidrIp.Trim() : $null
                            Write-Log "Checking Ipv4Range: CidrIp=$normalizedCidr, Description='$($ipRange.Description)'" "DEBUG"
                            if ($normalizedCidr -eq $config.Source.Trim()) {
                                # Special handling for default egress rule
                                if ($config.RuleType -eq 'egress' -and 
                                    $config.Protocol -eq 'all' -and 
                                    $config.FromPort -eq -1 -and 
                                    $config.ToPort -eq -1 -and 
                                    $config.Source -eq '0.0.0.0/0') {
                                    $ruleExists = $true
                                    $existingDescription = $ipRange.Description
                                    if ($ipRange.Description -ne $config.Description) {
                                        $descriptionMismatch = $true
                                    }
                                    Write-Log "Default egress rule (all -1 -1 0.0.0.0/0) exists for group ID: $GroupId with description '$($ipRange.Description)'." "INFO"
                                    break
                                }
                                $ruleExists = $true
                                $existingDescription = $ipRange.Description
                                if ($ipRange.Description -ne $config.Description) {
                                    $descriptionMismatch = $true
                                }
                                break
                            }
                        }
                        foreach ($ipv6Range in $rule.Ipv6Ranges) {
                            $normalizedCidr = $ipv6Range.CidrIpv6 ? $ipv6Range.CidrIpv6.Trim() : $null
                            Write-Log "Checking Ipv6Range: CidrIpv6=$normalizedCidr, Description='$($ipv6Range.Description)'" "DEBUG"
                            if ($normalizedCidr -eq $config.Source.Trim()) {
                                $ruleExists = $true
                                $existingDescription = $ipv6Range.Description
                                if ($ipv6Range.Description -ne $config.Description) {
                                    $descriptionMismatch = $true
                                }
                                break
                            }
                        }
                    }
                }
                if ($ruleExists) { break }
            }

            # Log the result
            if ($ruleExists) {
                Write-Log "Rule already exists for group ID: ${GroupId}: $($config.RuleType) $($config.Protocol) $($config.FromPort)-$($config.ToPort) $($config.Source)." "INFO"
                if ($descriptionMismatch) {
                    Write-Log "Description mismatch for rule in group ID: ${GroupId}: Excel description '$($config.Description)' does not match existing description '$existingDescription'." "WARN"
                }
            } else {
                Write-Log "Rule does not exist for group ID: ${GroupId}: $($config.RuleType) $($config.Protocol) $($config.FromPort)-$($config.ToPort) $($config.Source). Would be added in normal operation." "INFO"
            }

        } catch {
            Write-Log "Failed to check existing rules for group ID: $GroupId. Error: $($_.Exception.Message)" "ERROR"
            exit 1
        }
    }

    Write-Log "Rule existence check completed"

} catch {
    Write-Log "Fatal error: $($_.Exception.Message)" "ERROR"
    exit 1
} finally {
    # Clear credentials
    if (-not $DryRun) {
        Clear-AWSCredential -ErrorAction SilentlyContinue
        Clear-DefaultAWSRegion -ErrorAction SilentlyContinue
    }
}