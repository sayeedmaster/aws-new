# Create-SecurityGroupsFromExcel.ps1
# PowerShell script to create and manage AWS security groups and rules from Excel configuration using AWS.Tools modules with multiple SSO profiles
# Supports dry run mode to simulate actions without modifying AWS resources
# Skips adding egress rule (all -1 -1 0.0.0.0/0) if it already exists as the default egress rule
# Uses -IpPermission (singular) for Grant-EC2SecurityGroupIngress/Egress to match module compatibility
# Fixed CIDR validation in Test-CidrBlock to correctly handle valid network addresses like 10.0.0.0/16
# Enhanced debugging to log module version, IpPermission object, and equivalent direct command

param (
    [Parameter(Mandatory=$true, HelpMessage="Path to the directory containing AWS.Tools and ImportExcel modules.")]
    [string]$PSModulesPath,
    [Parameter(Mandatory=$false, HelpMessage="Run in dry run mode to simulate actions without modifying AWS resources.")]
    [switch]$DryRun
)

# Determine the script's root directory for reliable path resolution
$ScriptPath = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
$ExcelFilePath = (Join-Path $ScriptPath "EC2_Config.xlsx")
$LogFilePath = (Join-Path $ScriptPath "logs\SG_Create_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log")

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

# Helper function to convert a value to a normalized string
function Convert-ToNormalizedString {
    param (
        $Value
    )
    if ($Value -is [string]) {
        return $Value.Trim()
    }
    return $null
}

# Function to validate CIDR notation
function Test-CidrBlock {
    param (
        [string]$Cidr
    )
    try {
        $parts = $Cidr -split '/'
        if ($parts.Count -ne 2) { return $false }
        $ip = $parts[0]
        $prefixLength = [int]$parts[1]
        if ($prefixLength -lt 0 -or $prefixLength -gt 32) { return $false }
        $ipParts = $ip -split '\.'
        if ($ipParts.Count -ne 4) { return $false }
        foreach ($part in $ipParts) {
            $num = [int]$part
            if ($num -lt 0 -or $num -gt 255) { return $false }
        }
        # Calculate network address
        $ipBytes = [System.Net.IPAddress]::Parse($ip).GetAddressBytes()
        $maskBytes = @([byte]0, [byte]0, [byte]0, [byte]0)
        $fullBytes = [math]::Floor($prefixLength / 8)
        $remainderBits = $prefixLength % 8
        for ($i = 0; $i -lt $fullBytes; $i++) {
            $maskBytes[$i] = 255
        }
        if ($remainderBits -gt 0) {
            $maskBytes[$fullBytes] = [byte](256 - [math]::Pow(2, 8 - $remainderBits))
        }
        $networkBytes = @([byte]0, [byte]0, [byte]0, [byte]0)
        for ($i = 0; $i -lt 4; $i++) {
            $networkBytes[$i] = $ipBytes[$i] -band $maskBytes[$i]
        }
        $networkAddress = [System.Net.IPAddress]::new($networkBytes).ToString()
        if ($networkAddress -eq $ip) {
            return $true
        }
        return $false
    } catch {
        return $false
    }
}

# Function to validate SSO session and prompt for login if needed
function Test-SSOSession {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ProfileName,
        [Parameter(Mandatory=$true)]
        [string]$Region
    )
    try {
        if ($DryRun) {
            Write-Log "Dry run: Skipping SSO session validation for profile: $ProfileName in region: $Region" "INFO"
            return $true
        }
        Set-DefaultAWSRegion -Region $Region -ErrorAction Stop
        Write-Log "Region set to $Region for profile: $ProfileName"
        Get-STSCallerIdentity -ProfileName $ProfileName -Region $Region -ErrorAction Stop > $null
        Write-Log "SSO session is valid for profile: $ProfileName in region: $Region"
        return $true
    } catch {
        Write-Log "SSO session is invalid or expired for profile: $ProfileName. Error: $($_.Exception.Message)" "ERROR"
        Write-Log "Please run 'aws sso login --profile $ProfileName' to authenticate, then retry the script." "ERROR"
        try {
            Write-Log "Attempting to trigger SSO login for profile: $ProfileName"
            $process = Start-Process -FilePath "aws" -ArgumentList "sso login --profile $ProfileName" -NoNewWindow -Wait -PassThru
            if ($process.ExitCode -eq 0) {
                Write-Log "SSO login successful for profile: $ProfileName"
                Set-DefaultAWSRegion -Region $Region -ErrorAction Stop
                Get-STSCallerIdentity -ProfileName $ProfileName -Region $Region -ErrorAction Stop > $null
                Write-Log "SSO session validated after login for profile: $ProfileName"
                return $true
            } else {
                Write-Log "SSO login failed for profile: $ProfileName. Exit code: $($process.ExitCode)" "ERROR"
                return $false
            }
        } catch {
            Write-Log "Failed to trigger SSO login for profile: $ProfileName. Error: $($_.Exception.Message)" "ERROR"
            return $false
        }
    }
}

# Function for preflight checks before creating or modifying a security group
function Invoke-PreflightChecks {
    param(
        [Parameter(Mandatory=$true)]
        $Config,
        [Parameter(Mandatory=$true)]
        [string]$ProfileName,
        [Parameter(Mandatory=$true)]
        [string]$Region
    )

    Write-Log "Running preflight checks for security group $($Config.GroupName)..."

    # --- GroupName Check ---
    if (-not $Config.GroupName) {
        Write-Log "No GroupName specified. This is a required field." "ERROR"
        return @{ Success = $false }
    }

    # --- GroupDescription Check ---
    if (-not $Config.GroupDescription) {
        Write-Log "No GroupDescription specified for group $($Config.GroupName). This is a required field." "ERROR"
        return @{ Success = $false }
    }

    # --- VpcId Check ---
    if (-not $Config.VpcId) {
        Write-Log "No VpcId specified for group $($Config.GroupName). This is a required field." "ERROR"
        return @{ Success = $false }
    }
    if ($DryRun) {
        Write-Log "Dry run: Assuming VPC '$($Config.VpcId)' exists in region $Region." "INFO"
    } else {
        try {
            $vpc = Get-EC2Vpc -VpcId $Config.VpcId -ProfileName $ProfileName -Region $Region -ErrorAction Stop
            Write-Log "VPC '$($Config.VpcId)' is valid for group $($Config.GroupName)."
        } catch {
            Write-Log "Invalid VpcId '$($Config.VpcId)' for group $($Config.GroupName). Error: $($_.Exception.Message)" "ERROR"
            return @{ Success = $false }
        }
    }

    # --- RuleType Check ---
    if ($Config.RuleType -notin @('ingress', 'egress')) {
        Write-Log "Invalid RuleType '$($Config.RuleType)' for group $($Config.GroupName). Must be 'ingress' or 'egress'." "ERROR"
        return @{ Success = $false }
    }

    # --- Protocol Check ---
    $validProtocols = @('tcp', 'udp', 'icmp', 'all')
    if ($Config.Protocol -notin $validProtocols) {
        Write-Log "Invalid Protocol '$($Config.Protocol)' for group $($Config.GroupName). Must be one of: $($validProtocols -join ', ')." "ERROR"
        return @{ Success = $false }
    }

    # --- Port Checks ---
    if ($Config.Protocol -ne 'all') {
        if ($null -eq $Config.FromPort -or $null -eq $Config.ToPort) {
            Write-Log "FromPort and ToPort are required for protocol '$($Config.Protocol)' in group $($Config.GroupName)." "ERROR"
            return @{ Success = $false }
        }
        try {
            $fromPort = [int]$Config.FromPort
            $toPort = [int]$Config.ToPort
            if ($fromPort -lt -1 -or $fromPort -gt 65535 -or $toPort -lt -1 -or $toPort -gt 65535) {
                Write-Log "Invalid port range ($fromPort-$toPort) for group $($Config.GroupName). Ports must be between -1 and 65535." "ERROR"
                return @{ Success = $false }
            }
            if ($fromPort -gt $toPort) {
                Write-Log "FromPort ($fromPort) must be less than or equal to ToPort ($toPort) for group $($Config.GroupName)." "ERROR"
                return @{ Success = $false }
            }
            Write-Log "Port range $fromPort-$toPort is valid for group $($Config.GroupName)."
        } catch {
            Write-Log "Invalid FromPort '$($Config.FromPort)' or ToPort '$($Config.ToPort)' for group $($Config.GroupName). Must be integers. Error: $($_.Exception.Message)" "ERROR"
            return @{ Success = $false }
        }
    } else {
        if ($Config.FromPort -ne -1 -or $Config.ToPort -ne -1) {
            Write-Log "For protocol 'all', FromPort and ToPort must be -1 for group $($Config.GroupName)." "ERROR"
            return @{ Success = $false }
        }
    }

    # --- Source Check ---
    if (-not $Config.Source) {
        Write-Log "No Source specified for rule in group $($Config.GroupName). This is a required field." "ERROR"
        return @{ Success = $false }
    }
    if ($DryRun) {
        Write-Log "Dry run: Assuming Source '$($Config.Source)' is valid for group $($Config.GroupName)." "INFO"
    } else {
        # Validate CIDR or Security Group ID
        if ($Config.Source -match '^sg-') {
            try {
                Get-EC2SecurityGroup -GroupId $Config.Source -ProfileName $ProfileName -Region $Region -ErrorAction Stop > $null
                Write-Log "Source security group '$($Config.Source)' is valid for group $($Config.GroupName)."
            } catch {
                Write-Log "Invalid Source security group '$($Config.Source)' for group $($Config.GroupName). Error: $($_.Exception.Message)" "ERROR"
                return @{ Success = $false }
            }
        } else {
            # Enhanced CIDR validation
            if (-not (Test-CidrBlock -Cidr $Config.Source)) {
                Write-Log "Source '$($Config.Source)' for group $($Config.GroupName) is not a valid CIDR block." "ERROR"
                return @{ Success = $false }
            }
            Write-Log "Source CIDR '$($Config.Source)' is valid for group $($Config.GroupName)."
        }
    }

    # --- Description Check ---
    if (-not $Config.Description) {
        Write-Log "No Description specified for rule in group $($Config.GroupName). This is a required field." "ERROR"
        return @{ Success = $false }
    }

    return @{ Success = $true }
}

try {
    # Ensure the log directory exists
    $logDir = Split-Path -Path $LogFilePath -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -ErrorAction Stop > $null
    }

    # Import required AWS.Tools modules and ImportExcel
    try {
        Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.Common") -ErrorAction Stop
        Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.EC2") -ErrorAction Stop
        Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.SecurityToken") -ErrorAction Stop
        Import-Module -Name (Join-Path $PSModulesPath "ImportExcel") -ErrorAction Stop
        $moduleVersion = (Get-Module -Name AWS.Tools.EC2).Version.ToString()
        $availableParams = (Get-Command Grant-EC2SecurityGroupIngress).Parameters.Keys -join ", "
        Write-Log "Loaded AWS.Tools.EC2 version: $moduleVersion" "INFO"
        Write-Log "Available parameters for Grant-EC2SecurityGroupIngress: $availableParams" "DEBUG"
    } catch {
        Write-Log "Failed to import modules from $PSModulesPath. Error: $($_.Exception.Message)" "ERROR"
        exit 1
    }

    Write-Log "Starting security group creation script (DryRun: $DryRun)"

    # Read Excel file
    Write-Log "Reading Excel file: $ExcelFilePath"
    if (-not (Test-Path $ExcelFilePath)) {
        throw "Excel file not found: $ExcelFilePath"
    }
    
    $sgConfigs = Import-Excel -Path $ExcelFilePath -WorksheetName "sg_rules" -ErrorAction Stop
    if ($sgConfigs.Count -eq 0) {
        throw "No security group configurations found in Excel file"
    }
    Write-Log "Found $($sgConfigs.Count) security group rule configurations in Excel"

    # Path to AWS config file
    $awsConfigPath = "$env:USERPROFILE\.aws\config"
    if (-not (Test-Path $awsConfigPath)) {
        throw "AWS config file not found: $awsConfigPath"
    }

    # Read config file into lines
    $configLines = Get-Content -Path $awsConfigPath

    # Group configurations by GroupName, AccountId, and VpcId
    $groupedConfigs = $sgConfigs | Group-Object -Property AccountId, GroupName, VpcId

    # Process each security group
    foreach ($group in $groupedConfigs) {
        $accountId = $group.Group[0].AccountId
        $accountName = $group.Group[0].AccountName
        $ssoRole = $group.Group[0].SSORole
        $groupName = $group.Group[0].GroupName
        $groupDescription = $group.Group[0].GroupDescription
        $vpcId = $group.Group[0].VpcId

        # Clean names to match the profile format
        $cleanAccountName = $accountName -replace '[^\w\-]', ''
        $cleanSsoRole = $ssoRole -replace '[^\w\-]', ''
        $profileName = "sso-$cleanAccountName-$cleanSsoRole"

        Write-Log "Processing security group configuration for Account: $accountId ($accountName), Group: $groupName, VPC: $vpcId, Profile: $profileName"

        # Find profile section
        $profileHeaderPattern = "^\[profile\s+$([regex]::Escape($profileName))\s*\]$"
        $profileLine = $configLines | Select-String -Pattern $profileHeaderPattern

        if (-not $profileLine) {
            Write-Log "Profile section not found in AWS config for: $profileName. Please ensure it exists in '$awsConfigPath'." "ERROR"
            continue
        }

        $profileStart = $profileLine.LineNumber
        $nextHeader = $configLines[($profileStart)..($configLines.Count-1)] | Select-String -Pattern "^\[(profile|sso-session)\s+"
        $profileEnd = if ($nextHeader) { $profileStart + $nextHeader[0].LineNumber - 2 } else { $configLines.Count - 1 }
        $profileBlock = $configLines[($profileStart - 1)..$profileEnd]

        # Parse required fields from profile block
        $ssoStartUrl = ($profileBlock | Where-Object { $_ -match '^sso_start_url\s*=\s*(.+)$' }) -replace '^sso_start_url\s*=\s*', ''
        $region = ($profileBlock | Where-Object { $_ -match '^region\s*=\s*(.+)$' }) -replace '^region\s*=\s*', ''
        $ssoAccountId = ($profileBlock | Where-Object { $_ -match '^sso_account_id\s*=\s*(.+)$' }) -replace '^sso_account_id\s*=\s*', ''
        $ssoRoleName = ($profileBlock | Where-Object { $_ -match '^sso_role_name\s*=\s*(.+)$' }) -replace '^sso_role_name\s*=\s*', ''
        $ssoSession = ($profileBlock | Where-Object { $_ -match '^sso_session\s*=\s*(.+)$' }) -replace '^sso_session\s*=\s*', ''

        if (-not $ssoStartUrl -or -not $region -or -not $ssoAccountId -or -not $ssoRoleName -or -not $ssoSession) {
            Write-Log "Incomplete SSO profile configuration for: $profileName. Required fields: sso_start_url, region, sso_account_id, sso_role_name, sso_session." "ERROR"
            continue
        }

        # Validate AccountId and SSORole
        if ($ssoAccountId -ne $accountId) {
            Write-Log "AccountId ($accountId) in Excel does not match sso_account_id ($ssoAccountId) in profile: $profileName." "ERROR"
            continue
        }
        if ($ssoRoleName -ne $ssoRole) {
            Write-Log "SSORole ($ssoRole) in Excel does not match sso_role_name ($ssoRoleName) in profile: $profileName." "ERROR"
            continue
        }

        # Validate region
        $validRegions = if ($DryRun) { @($region) } else { Get-AWSRegion -ErrorAction Stop | Select-Object -ExpandProperty Region }
        if ($region -notin $validRegions) {
            Write-Log "Region '$region' is not a valid AWS region for profile: $profileName. Valid regions: $($validRegions -join ', ')" "ERROR"
            continue
        }

        # Set AWS credentials and region
        Write-Log "Setting AWS credentials for profile: $profileName"
        try {
            if (-not $DryRun) {
                Set-AWSCredential -ProfileName $profileName -ErrorAction Stop
                if (-not (Test-SSOSession -ProfileName $profileName -Region $region)) {
                    Write-Log "Skipping security group creation for $groupName due to invalid SSO session." "ERROR"
                    continue
                }
                Set-DefaultAWSRegion -Region $region -ErrorAction Stop
            }
            Write-Log "Successfully set credentials and region ($region) for profile: $profileName"
        } catch {
            Write-Log "Failed to set credentials for profile: $profileName. Error: $($_.Exception.Message)" "ERROR"
            continue
        }

        # Check if security group exists
        $securityGroupId = $null
        $isNewGroup = $false
        if ($DryRun) {
            Write-Log "Dry run: Assuming security group '$groupName' exists or will be created in VPC $vpcId." "INFO"
            $securityGroupId = "sg-dryrun-$(Get-Random -Minimum 1000000000 -Maximum 9999999999)"
            $isNewGroup = $true
        } else {
            try {
                $existingGroups = Get-EC2SecurityGroup -Filter @(
                    @{Name="group-name";Values=$groupName},
                    @{Name="vpc-id";Values=$vpcId}
                ) -ProfileName $profileName -Region $region -ErrorAction Stop
                if ($existingGroups.Count -gt 0) {
                    $securityGroupId = $existingGroups[0].GroupId
                    Write-Log "Found existing security group '$groupName' with ID: $securityGroupId in VPC $vpcId."
                } else {
                    Write-Log "Security group '$groupName' does not exist in VPC $vpcId. Creating new security group."
                    $securityGroupId = (New-EC2SecurityGroup -GroupName $groupName -Description $groupDescription -VpcId $vpcId -ProfileName $profileName -Region $region -ErrorAction Stop).GroupId
                    Write-Log "Successfully created security group '$groupName' with ID: $securityGroupId"
                    $isNewGroup = $true
                }
            } catch {
                Write-Log "Failed to check or create security group '$groupName'. Error: $($_.Exception.Message)" "ERROR"
                continue
            }
        }

        # Process rules for the security group
        foreach ($config in $group.Group) {
            try {
                # Run preflight checks for each rule
                $preflightResult = Invoke-PreflightChecks -Config $config -ProfileName $profileName -Region $region
                if (-not $preflightResult.Success) {
                    Write-Log "Preflight checks failed for rule in group $($config.GroupName). Skipping rule." "ERROR"
                    continue
                }

                # Check rule count (max 60 rules per security group)
                if (-not $DryRun) {
                    try {
                        $sg = Get-EC2SecurityGroup -GroupId $securityGroupId -ProfileName $profileName -Region $region -ErrorAction Stop
                        $ingressRuleCount = ($sg.IpPermissions | Measure-Object).Count
                        $egressRuleCount = ($sg.IpPermissionsEgress | Measure-Object).Count
                        $totalRuleCount = $ingressRuleCount + $egressRuleCount
                        if ($totalRuleCount -ge 60) {
                            Write-Log "Security group '$groupName' (ID: $securityGroupId) has $totalRuleCount rules, exceeding the maximum of 60." "ERROR"
                            continue
                        }
                        Write-Log "Security group '$groupName' has $totalRuleCount rules (ingress: $ingressRuleCount, egress: $egressRuleCount). Adding new rule."
                    } catch {
                        Write-Log "Failed to check rule count for group '$groupName'. Error: $($_.Exception.Message)" "ERROR"
                        continue
                    }
                }

                # Check for existing rule to avoid duplicates
                $ruleExists = $false
                if (-not $DryRun) {
                    try {
                        $sg = Get-EC2SecurityGroup -GroupId $securityGroupId -ProfileName $profileName -Region $region -ErrorAction Stop
                        $rules = if ($config.RuleType -eq 'ingress') { $sg.IpPermissions } else { $sg.IpPermissionsEgress }
                        foreach ($rule in $rules) {
                            if ($rule.IpProtocol -eq $config.Protocol -and
                                $rule.FromPort -eq [int]$config.FromPort -and
                                $rule.ToPort -eq [int]$config.ToPort) {
                                if (($config.Source -match '^sg-') -and ($rule.UserIdGroupPairs.GroupId -contains $config.Source)) {
                                    $ruleExists = $true
                                    break
                                } elseif ($rule.IpRanges.CidrIp -contains $config.Source) {
                                    $ruleExists = $true
                                    break
                                }
                            }
                        }
                    } catch {
                        Write-Log "Failed to check existing rules for group '$groupName'. Error: $($_.Exception.Message)" "ERROR"
                        continue
                    }
                }

                if ($ruleExists) {
                    Write-Log "Rule already exists for group '$groupName': $($config.RuleType) $($config.Protocol) $($config.FromPort)-$($config.ToPort) $($config.Source). Skipping." "INFO"
                    continue
                }

                # Add new rule
                Write-Log "Adding $($config.RuleType) rule to group '$groupName': $($config.Protocol) $($config.FromPort)-$($config.ToPort) $($config.Source)"
                if ($DryRun) {
                    Write-Log "Dry run: Would add $($config.RuleType) rule to group '$groupName' (ID: $securityGroupId): $($config.Protocol) $($config.FromPort)-$($config.ToPort) $($config.Source)" "INFO"
                } else {
                    try {
                        # Create IpPermission object as a hashtable for better compatibility
                        $ipPermission = @{
                            IpProtocol = $config.Protocol
                            FromPort   = [int]$config.FromPort
                            ToPort     = [int]$config.ToPort
                        }

                        if ($config.Source -match '^sg-') {
                            $ipPermission.UserIdGroupPairs = @(
                                @{
                                    GroupId = $config.Source
                                    Description = $config.Description
                                }
                            )
                        } else {
                            $ipPermission.Ipv4Ranges = @(
                                @{
                                    CidrIp = $config.Source
                                    Description = $config.Description
                                }
                            )
                        }
                        
                        $params = @{
                            GroupId      = $securityGroupId
                            IpPermission = $ipPermission
                            ProfileName  = $profileName
                            Region       = $region
                            ErrorAction  = 'Stop'
                        }
                        
                        $commandString = if ($config.RuleType -eq 'ingress') { "Grant-EC2SecurityGroupIngress" } else { "Grant-EC2SecurityGroupEgress" }
                        $commandString += " -GroupId $securityGroupId -IpPermission '$((ConvertTo-Json -InputObject $ipPermission -Depth 5 -Compress) -replace "'", "''")' -ProfileName $profileName -Region $region"
                        Write-Log "Executing command: $commandString" "DEBUG"

                        if ($config.RuleType -eq 'ingress') {
                            Grant-EC2SecurityGroupIngress @params
                            Write-Log "Successfully added ingress rule to group '$groupName': $($config.Protocol) $($config.FromPort)-$($config.ToPort) $($config.Source)"
                        } else {
                            Grant-EC2SecurityGroupEgress @params
                            Write-Log "Successfully added egress rule to group '$groupName': $($config.Protocol) $($config.FromPort)-$($config.ToPort) $($config.Source)"
                        }
                    } catch {
                        Write-Log "Failed to add $($config.RuleType) rule to group '$groupName'. Error: $($_.Exception.Message)" "ERROR"
                        continue
                    }
                }
            } catch {
                Write-Log "Error processing rule for group '$groupName' in Account: $accountId ($accountName), VPC: $vpcId. Error: $($_.Exception.Message)" "ERROR"
                continue
            }
        }

        # Apply tags (only for new security groups)
        if ($isNewGroup -and $group.Group[0].Tags) {
            $tags = @()
            $tagPairs = $group.Group[0].Tags -split ',' | ForEach-Object { $_.Trim() }
            foreach ($tagPair in $tagPairs) {
                $keyValue = $tagPair -split '='
                if ($keyValue.Count -eq 2 -and $keyValue[0].Trim() -and $keyValue[1].Trim()) {
                    $tag = New-Object Amazon.EC2.Model.Tag
                    $tag.Key = $keyValue[0].Trim()
                    $tag.Value = $keyValue[1].Trim()
                    $tags += $tag
                    Write-Log "Adding tag: $($tag.Key)=$($tag.Value)" "DEBUG"
                } else {
                    Write-Log "Invalid tag format: '$tagPair'. Expected 'key=value'. Skipping this tag." "WARN"
                }
            }
            if ($tags.Count -gt 0 -and -not $DryRun) {
                try {
                    New-EC2Tag -Resource $securityGroupId -Tag $tags -ProfileName $profileName -Region $region -ErrorAction Stop
                    Write-Log "Applied $($tags.Count) tags to security group $securityGroupId"
                } catch {
                    Write-Log "Failed to apply tags to security group $securityGroupId. Error: $($_.Exception.Message)" "ERROR"
                }
            } elseif ($DryRun) {
                Write-Log "Dry run: Would apply tags: $(ConvertTo-Json -InputObject $tags -Depth 5 -Compress)" "INFO"
            }
        }

        # Clear credentials
        if (-not $DryRun) {
            Clear-AWSCredential -ErrorAction SilentlyContinue
            Clear-DefaultAWSRegion -ErrorAction SilentlyContinue
        }
    }

    Write-Log "Security group creation process completed"

} catch {
    Write-Log "Fatal error: $($_.Exception.Message)" "ERROR"
    exit 1
}
