# Create-SecurityGroupsFromExcel.ps1
# PowerShell script to create and manage AWS security groups and rules from Excel configuration using AWS.Tools modules with multiple SSO profiles
# Supports dry run mode to simulate actions without modifying AWS resources
# Supports -ReplaceSG switch to delete and recreate existing security groups before adding rules
# Supports -SkipPermissionValidation switch to bypass permission checks for administrator roles
# Skips adding egress rule (all -1 -1 0.0.0.0/0) if it already exists as the default egress rule
# Uses -IpPermission (singular) for Grant-EC2SecurityGroupIngress/Egress to match module compatibility
# Fixed CIDR validation in Test-CidrBlock to correctly handle valid network addresses like 10.0.0.0/16
# Enhanced debugging to log module version, IpPermission object, raw security group response, and equivalent direct command
# Updated to check for existing rules using Ipv4Ranges instead of IpRanges, supporting Ipv6Ranges and PrefixListIds, ignoring Description for uniqueness
# Uses -GroupId for rule addition, with robust retrieval for new and existing groups
# Retains 2-second sleep after creating new security groups to allow propagation
# Fixed permission validation to use valid MaxResults value and improved error handling
# Fixed GroupId handling for New-EC2SecurityGroup string response and improved retry logic for duplicate group errors
# Updated ec2:DeleteSecurityGroup permission check to use a randomized valid group ID and handle unexpected errors as warnings
# Enhanced rule addition loop to log detailed errors and continue processing all rules
# Added final verification step to confirm applied rules
# Enhanced Excel handling: module version check, dual-strategy reading (headers then -NoHeader), header validation, placeholder row filtering, and detailed error handling
# Supports prefix list rules (Source starting with 'pl-') with validation and rule addition via AWS CLI to avoid PrefixListId property errors
# Added breakdown of CIDR-based, prefix list-based, and security group-based rules in the log message for valid configurations
# Added functionality to write SecurityGroupIds back to Excel in the SecurityGroupIds column for each processed group

param (
    [Parameter(Mandatory=$true, HelpMessage="Path to the directory containing AWS.Tools and ImportExcel modules.")]
    [string]$PSModulesPath,
    [Parameter(Mandatory=$false, HelpMessage="Run in dry run mode to simulate actions without modifying AWS resources.")]
    [switch]$DryRun,
    [Parameter(Mandatory=$false, HelpMessage="Delete and recreate existing security groups before adding rules.")]
    [switch]$ReplaceSG,
    [Parameter(Mandatory=$false, HelpMessage="Skip permission validation for accounts with full administrator access.")]
    [switch]$SkipPermissionValidation,
    [Parameter(Mandatory=$false, HelpMessage="Show debug messages in output.")]
    [bool]$ScriptDebug = $false
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
    $suppress = $false
    if ($Level.ToUpper() -eq "DEBUG" -and -not $ScriptDebug) {
        $suppress = $true
    }
    switch ($Level.ToUpper()) {
        "INFO" {
            if ($Message -match "^Successfully") {
                $color = "Green"
            } else {
                $color = "Blue"
            }
        }
        "WARN"    { $color = "Yellow" }
        "WARNING" { $color = "Yellow" }
        "ERROR"   { $color = "Red" }
        "DEBUG"   { $color = "Gray" }
        default   { $color = $null }
    }
    if (-not $suppress) {
        if ($color) {
            Write-Host $logMessage -ForegroundColor $color
        } else {
            Write-Host $logMessage
        }
    }
    Add-Content -Path $LogFilePath -Value $logMessage
}

# Helper function to convert a value to a normalized string
function Convert-ToNormalizedString {
    param (
        $Value
    )
    if ($Value -is [string]) {
        return $Value.Trim().ToLower()
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

# Function to generate a random valid security group ID
function New-RandomSecurityGroupId {
    $hexChars = '0123456789abcdef'.ToCharArray()
    $randomHex = -join ((0..16) | ForEach-Object { $hexChars | Get-Random })
    return "sg-$randomHex"
}

# Function to validate SSO session
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
        Write-Log "Region set to $Region for profile: $ProfileName" "DEBUG"
        Get-STSCallerIdentity -ProfileName $ProfileName -Region $Region -ErrorAction Stop > $null
        Write-Log "SSO session is valid for profile: $ProfileName in region: $Region" "INFO"
        return $true
    } catch {
        Write-Log "SSO session is invalid or expired for profile: $ProfileName. Error: $($_.Exception.Message)" "ERROR"
        Write-Log "Please run 'aws sso login --profile $ProfileName' to authenticate, then retry the script." "ERROR"
        try {
            Write-Log "Attempting to trigger SSO login for profile: $ProfileName" "INFO"
            $process = Start-Process -FilePath "aws" -ArgumentList "sso login --profile $ProfileName" -NoNewWindow -Wait -PassThru
            if ($process.ExitCode -eq 0) {
                Write-Log "SSO login successful for profile: $ProfileName" "INFO"
                Set-DefaultAWSRegion -Region $Region -ErrorAction Stop
                Get-STSCallerIdentity -ProfileName $ProfileName -Region $Region -ErrorAction Stop > $null
                Write-Log "SSO session validated after login for profile: $ProfileName" "INFO"
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

# Function to validate IAM permissions
function Test-SecurityGroupPermissions {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ProfileName,
        [Parameter(Mandatory=$true)]
        [string]$Region,
        [Parameter(Mandatory=$false)]
        [bool]$TestDeletePermission = $false
    )
    try {
        if ($DryRun) {
            Write-Log "Dry run: Skipping permission validation for profile: $ProfileName in region: $Region" "INFO"
            return $true
        }
        Get-EC2SecurityGroup -ProfileName $ProfileName -Region $Region -MaxResults 5 -ErrorAction Stop > $null
        Write-Log "Permissions validated for ec2:DescribeSecurityGroups with profile: $ProfileName in region: $Region" "DEBUG"
        
        if ($TestDeletePermission) {
            $testGroupId = New-RandomSecurityGroupId
            Write-Log "Testing ec2:DeleteSecurityGroup permission with group ID: $testGroupId" "DEBUG"
            try {
                Remove-EC2SecurityGroup -GroupId $testGroupId -ProfileName $ProfileName -Region $Region -ErrorAction Stop -Force > $null
            } catch {
                if ($_.Exception.Message -match "InvalidGroup.NotFound") {
                    Write-Log "Permissions validated for ec2:DeleteSecurityGroup with profile: $ProfileName in region: $Region" "DEBUG"
                } else {
                    Write-Log "Unexpected error during ec2:DeleteSecurityGroup permission check with group ID: $testGroupId. Error: $($_.Exception.Message)" "WARN"
                    Write-Log "Assuming ec2:DeleteSecurityGroup permission is available for profile: $ProfileName due to administrator role." "WARN"
                }
            }
        }
        return $true
    } catch {
        $errorMessage = $_.Exception.Message
        $errorCode = $_.Exception.ErrorCode
        Write-Log "Failed to validate permissions for security group operations with profile: $ProfileName in region: $Region. ErrorCode: $errorCode, Error: $errorMessage" "ERROR"
        if ($errorMessage -match "AccessDenied|UnauthorizedOperation") {
            $requiredPermissions = "'ec2:DescribeSecurityGroups', 'ec2:CreateSecurityGroup', 'ec2:AuthorizeSecurityGroupIngress', 'ec2:AuthorizeSecurityGroupEgress', 'ec2:CreateTags'"
            if ($TestDeletePermission) {
                $requiredPermissions += ", 'ec2:DeleteSecurityGroup'"
            }
            Write-Log "Insufficient permissions. Ensure the role has $requiredPermissions permissions." "ERROR"
            return $false
        } else {
            Write-Log "Non-permission-related error occurred. Assuming permissions are sufficient for profile: $ProfileName due to administrator role." "WARN"
            return $true
        }
    }
}

# Function to validate AWS CLI installation
function Test-AwsCli {
    try {
        $awsVersion = aws --version 2>&1
        Write-Log "AWS CLI is installed: $awsVersion" "DEBUG"
        return $true
    } catch {
        Write-Log "AWS CLI is not installed or not found in PATH. Please install AWS CLI to use prefix list rules." "ERROR"
        return $false
    }
}

# Function for preflight checks
function Invoke-PreflightChecks {
    param(
        [Parameter(Mandatory=$true)]
        $Config,
        [Parameter(Mandatory=$true)]
        [string]$ProfileName,
        [Parameter(Mandatory=$true)]
        [string]$Region
    )

    Write-Log "Running preflight checks for security group $($Config.GroupName)..." "INFO"

    # --- GroupName Check ---
    if (-not $Config.GroupName -or $Config.GroupName -eq 'GroupName') {
        Write-Log "No valid GroupName specified. This is a required field." "ERROR"
        return @{ Success = $false }
    }

    # --- GroupDescription Check ---
    if (-not $Config.GroupDescription -or $Config.GroupDescription -eq 'GroupDescription') {
        Write-Log "No valid GroupDescription specified for group $($Config.GroupName). This is a required field." "ERROR"
        return @{ Success = $false }
    }

    # --- VpcId Check ---
    if (-not $Config.VpcId -or $Config.VpcId -eq 'VpcId') {
        Write-Log "No valid VpcId specified for group $($Config.GroupName). This is a required field." "ERROR"
        return @{ Success = $false }
    }
    if ($DryRun) {
        Write-Log "Dry run: Assuming VPC '$($Config.VpcId)' exists in region $Region." "INFO"
    } else {
        try {
            Get-EC2Vpc -VpcId $Config.VpcId -ProfileName $ProfileName -Region $Region -ErrorAction Stop > $null
            Write-Log "VPC '$($Config.VpcId)' is valid for group $($Config.GroupName)." "DEBUG"
        } catch {
            Write-Log "Invalid VpcId '$($Config.VpcId)' for group $($Config.GroupName). Error: $($_.Exception.Message)" "ERROR"
            return @{ Success = $false }
        }
    }

    # --- RuleType Check ---
    if ($Config.RuleType -notin @('ingress', 'egress') -or $Config.RuleType -eq 'RuleType') {
        Write-Log "Invalid RuleType '$($Config.RuleType)' for group $($Config.GroupName). Must be 'ingress' or 'egress'." "ERROR"
        return @{ Success = $false }
    }

    # --- Protocol Check ---
    $validProtocols = @('tcp', 'udp', 'icmp', 'all')
    if ($Config.Protocol -notin $validProtocols -or $Config.Protocol -eq 'Protocol') {
        Write-Log "Invalid Protocol '$($Config.Protocol)' for group $($Config.GroupName). Must be one of: $($validProtocols -join ', ')." "ERROR"
        return @{ Success = $false }
    }

    # --- Port Checks ---
    if ($Config.Protocol -ne 'all') {
        if ($null -eq $Config.FromPort -or $null -eq $Config.ToPort -or $Config.FromPort -eq 'FromPort' -or $Config.ToPort -eq 'ToPort') {
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
            Write-Log "Port range $fromPort-$toPort is valid for group $($Config.GroupName)." "DEBUG"
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
    if (-not $Config.Source -or $Config.Source -eq 'Source') {
        Write-Log "No valid Source specified for rule in group $($Config.GroupName). This is a required field." "ERROR"
        return @{ Success = $false }
    }
    if ($DryRun) {
        Write-Log "Dry run: Assuming Source '$($Config.Source)' is valid for group $($Config.GroupName)." "INFO"
    } else {
        if ($Config.Source -match '^sg-') {
            try {
                Get-EC2SecurityGroup -GroupId $Config.Source -ProfileName $ProfileName -Region $Region -ErrorAction Stop > $null
                Write-Log "Source security group '$($Config.Source)' is valid for group $($Config.GroupName)." "DEBUG"
            } catch {
                Write-Log "Invalid Source security group '$($Config.Source)' for group $($Config.GroupName). Error: $($_.Exception.Message)" "ERROR"
                return @{ Success = $false }
            }
        } elseif ($Config.Source -match '^pl-') {
            try {
                Get-EC2ManagedPrefixList -PrefixListId $Config.Source -ProfileName $ProfileName -Region $Region -ErrorAction Stop > $null
                Write-Log "Source prefix list '$($Config.Source)' is valid for group $($Config.GroupName)." "DEBUG"
            } catch {
                Write-Log "Invalid Source prefix list '$($Config.Source)' for group $($Config.GroupName). Error: $($_.Exception.Message)" "ERROR"
                return @{ Success = $false }
            }
        } else {
            if (-not (Test-CidrBlock -Cidr $Config.Source)) {
                Write-Log "Source '$($Config.Source)' for group $($Config.GroupName) is not a valid IPv4 CIDR block." "ERROR"
                return @{ Success = $false }
            }
            Write-Log "Source CIDR '$($Config.Source)' is valid for group $($Config.GroupName)." "DEBUG"
        }
    }

    # --- Description Check ---
    if (-not $Config.Description -or $Config.Description -eq 'Description') {
        Write-Log "No valid Description specified for rule in group $($Config.GroupName). This is a required field." "ERROR"
        return @{ Success = $false }
    }

    return @{ Success = $true }
}

# Function to verify security group rules
function Confirm-SecurityGroupRules {
    param(
        [Parameter(Mandatory=$true)]
        [string]$GroupId,
        [Parameter(Mandatory=$true)]
        [string]$GroupName,
        [Parameter(Mandatory=$true)]
        [string]$ProfileName,
        [Parameter(Mandatory=$true)]
        [string]$Region
    )
    try {
        $sg = Get-EC2SecurityGroup -GroupId $GroupId -ProfileName $ProfileName -Region $Region -ErrorAction Stop
        $ingressRules = $sg.IpPermissions
        $egressRules = $sg.IpPermissionsEgress
        Write-Log "Verifying rules for security group '$GroupName' (ID: $GroupId):" "INFO"
        Write-Log "Ingress rules ($($ingressRules.Count)): $(ConvertTo-Json -InputObject $ingressRules -Depth 5 -Compress)" "DEBUG"
        Write-Log "Egress rules ($($egressRules.Count)): $(ConvertTo-Json -InputObject $egressRules -Depth 5 -Compress)" "DEBUG"
    } catch {
        Write-Log "Failed to verify rules for security group '$GroupName' (ID: $GroupId). Error: $($_.Exception.Message)" "ERROR"
    }
}

# Function to update Excel with SecurityGroupIds
function Update-ExcelWithSecurityGroupId {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ExcelFilePath,
        [Parameter(Mandatory=$true)]
        [string]$GroupName,
        [Parameter(Mandatory=$true)]
        [string]$AccountId,
        [Parameter(Mandatory=$true)]
        [string]$VpcId,
        [Parameter(Mandatory=$true)]
        [string]$SecurityGroupId
    )
    try {
        Write-Log "Updating Excel file with SecurityGroupId '$SecurityGroupId' for GroupName '$GroupName', AccountId '$AccountId', VpcId '$VpcId'" "INFO"
        $excelData = Import-Excel -Path $ExcelFilePath -WorksheetName "sg_rules" -ErrorAction Stop
        $updated = $false
        $hasSecurityGroupIdsColumn = ($excelData | Get-Member -MemberType NoteProperty | Where-Object { $_.Name -eq 'SecurityGroupIds' }).Count -gt 0

        if (-not $hasSecurityGroupIdsColumn) {
            Write-Log "Adding SecurityGroupIds column to Excel file" "INFO"
            $excelData = $excelData | Select-Object *, @{Name='SecurityGroupIds';Expression={$null}}
        }

        foreach ($row in $excelData) {
            if ($row.GroupName -eq $GroupName -and $row.AccountId -eq $AccountId -and $row.VpcId -eq $VpcId) {
                $row.SecurityGroupIds = $SecurityGroupId
                $updated = $true
            }
        }

        if ($updated) {
            Export-Excel -Path $ExcelFilePath -WorksheetName "sg_rules" -InputObject $excelData -NoHeader:$false -ErrorAction Stop
            Write-Log "Successfully updated Excel file with SecurityGroupId '$SecurityGroupId' for GroupName '$GroupName'" "INFO"
        } else {
            Write-Log "No matching rows found to update SecurityGroupIds for GroupName '$GroupName', AccountId '$AccountId', VpcId '$VpcId'" "WARN"
        }
    } catch {
        Write-Log "Failed to update Excel file with SecurityGroupId '$SecurityGroupId' for GroupName '$GroupName'. Error: $($_.Exception.Message)" "ERROR"
    }
}

try {
    # Ensure the log directory exists
    $logDir = Split-Path -Path $LogFilePath -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -ErrorAction Stop > $null
        Write-Log "Created log directory: $logDir" "INFO"
    }

    # Import required AWS.Tools modules and ImportExcel
    try {
        Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.Common") -ErrorAction Stop
        Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.EC2") -ErrorAction Stop
        Import-Module -Name (Join-Path $PSModulesPath "AWS.Tools.SecurityToken") -ErrorAction Stop
        Import-Module -Name (Join-Path $PSModulesPath "ImportExcel") -ErrorAction Stop
        $awsEc2Version = (Get-Module -Name AWS.Tools.EC2).Version.ToString()
        $importExcelVersion = (Get-Module -Name ImportExcel).Version.ToString()
        Write-Log "Loaded AWS.Tools.EC2 version: $awsEc2Version, ImportExcel version: $importExcelVersion" "INFO"
        if ($awsEc2Version -eq "5.0.11") {
            Write-Log "AWS.Tools.EC2 version 5.0.11 detected. Using AWS CLI for prefix list rules to avoid potential bugs." "WARN"
        }
        if ($importExcelVersion -lt "7.0.0") {
            Write-Log "ImportExcel version $importExcelVersion is outdated. Consider updating to 7.0.0 or later for better compatibility: Install-Module -Name ImportExcel -Scope CurrentUser -Force" "WARN"
        }
        $availableParams = (Get-Command Grant-EC2SecurityGroupIngress).Parameters.Keys -join ", "
        Write-Log "Available parameters for Grant-EC2SecurityGroupIngress: $availableParams" "DEBUG"
    } catch {
        Write-Log "Failed to import modules from $PSModulesPath. Error: $($_.Exception.Message)" "ERROR"
        exit 1
    }

    # Validate AWS CLI installation for prefix list rules
    if (-not (Test-AwsCli)) {
        Write-Log "AWS CLI is required for prefix list rules. Exiting script." "ERROR"
        exit 1
    }

    Write-Log "Starting security group creation script (DryRun: $DryRun, ReplaceSG: $ReplaceSG, SkipPermissionValidation: $SkipPermissionValidation, ScriptDebug: $ScriptDebug)" "INFO"

    # Validate Excel file existence
    Write-Log "Checking Excel file: $ExcelFilePath" "INFO"
    if (-not (Test-Path $ExcelFilePath)) {
        throw "Excel file not found: $ExcelFilePath"
    }

    # Define expected headers
    $headerNames = @(
        'SSORole',
        'AccountId',
        'AccountName',
        'GroupName',
        'GroupDescription',
        'VpcId',
        'RuleType',
        'Protocol',
        'FromPort',
        'ToPort',
        'Source',
        'Description',
        'Tags',
        'SecurityGroupIds'
    )

    # Read Excel file with dual-strategy approach
    Write-Log "Reading Excel file: $ExcelFilePath, Worksheet: sg_rules" "INFO"
    $sgConfigs = $null
    try {
        $sgConfigs = Import-Excel -Path $ExcelFilePath -WorksheetName "sg_rules" -ErrorAction Stop
        Write-Log "Successfully read Excel file with headers" "DEBUG"

        # Validate headers
        $actualHeaders = ($sgConfigs | Get-Member -MemberType NoteProperty).Name
        $missingHeaders = $headerNames | Where-Object { $_ -notin $actualHeaders -and $_ -ne 'SecurityGroupIds' }
        if ($missingHeaders) {
            Write-Log "Missing expected headers in Excel file (excluding SecurityGroupIds): $($missingHeaders -join ', '). Falling back to -NoHeader mode." "WARN"
            throw "Missing headers"
        }

        # Filter out invalid rows
        $sgConfigs = $sgConfigs | Where-Object {
            $_.AccountId -and $_.AccountId -ne 'AccountId' -and
            $_.SSORole -and $_.SSORole -ne 'SSORole' -and
            $_.GroupName -and $_.GroupName -ne 'GroupName'
        }
        Write-Log "Filtered to $($sgConfigs.Count) valid rows after removing placeholders" "DEBUG"
    } catch {
        Write-Log "Failed to read Excel file with headers. Error: $($_.Exception.Message). Attempting to read with -NoHeader and explicit headers." "WARN"
        try {
            $sgConfigs = Import-Excel -Path $ExcelFilePath -WorksheetName "sg_rules" -NoHeader -HeaderName $headerNames -ErrorAction Stop
            $sgConfigs = $sgConfigs | Where-Object {
                $_.P1 -and $_.P1 -ne 'SSORole' -and
                $_.P2 -and $_.P2 -ne 'AccountId' -and
                $_.P4 -and $_.P4 -ne 'GroupName'
            }
            Write-Log "Successfully read Excel file with -NoHeader and explicit headers" "DEBUG"
        } catch {
            Write-Log "Failed to read Excel file with -NoHeader. Error: $($_.Exception.Message)" "ERROR"
            throw "Unable to read Excel file after attempting both header and no-header modes"
        }
    }

    if ($sgConfigs.Count -eq 0) {
        throw "No valid security group configurations found in Excel file after filtering"
    }

    # Count CIDR-based and prefix list-based rules
    $cidrCount = ($sgConfigs | Where-Object { $_.Source -and $_.Source -notmatch '^sg-' -and $_.Source -notmatch '^pl-' -and (Test-CidrBlock -Cidr $_.Source) }).Count
    $prefixListCount = ($sgConfigs | Where-Object { $_.Source -and $_.Source -match '^pl-' }).Count
    $securityGroupCount = ($sgConfigs | Where-Object { $_.Source -and $_.Source -match '^sg-' }).Count
    Write-Log "Found $($sgConfigs.Count) valid security group rule configurations in Excel ($cidrCount CIDR-based, $prefixListCount prefix list-based, $securityGroupCount security group-based)" "INFO"

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
        try {
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

            Write-Log "Processing security group configuration for Account: $accountId ($accountName), Group: $groupName, VPC: $vpcId, Profile: $profileName" "INFO"

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
            Write-Log "Setting AWS credentials for profile: $profileName" "INFO"
            try {
                if (-not $DryRun) {
                    Set-AWSCredential -ProfileName $profileName -ErrorAction Stop
                    if (-not (Test-SSOSession -ProfileName $profileName -Region $region)) {
                        Write-Log "Skipping security group creation for $groupName due to invalid SSO session." "ERROR"
                        continue
                    }
                    Set-DefaultAWSRegion -Region $region -ErrorAction Stop
                    # Set environment variables for AWS CLI
                    $env:AWS_PROFILE = $profileName
                    $env:AWS_REGION = $region
                }
                Write-Log "Successfully set credentials and region ($region) for profile: $profileName" "INFO"
            } catch {
                Write-Log "Failed to set credentials for profile: $profileName. Error: $($_.Exception.Message)" "ERROR"
                continue
            }

            # Validate permissions
            $testDeletePermission = $ReplaceSG
            if (-not $SkipPermissionValidation -and -not (Test-SecurityGroupPermissions -ProfileName $profileName -Region $region -TestDeletePermission $testDeletePermission)) {
                Write-Log "Skipping security group creation for $groupName due to permission validation failure." "ERROR"
                continue
            } elseif ($SkipPermissionValidation) {
                Write-Log "Skipping permission validation for profile: $profileName as requested." "INFO"
            }

            # Check if security group exists and handle deletion if -ReplaceSG is specified
            $securityGroupId = $null
            $isNewGroup = $false
            if ($DryRun) {
                Write-Log "Dry run: Assuming security group '$groupName' exists or will be created in VPC $vpcId." "INFO"
                $securityGroupId = "sg-dryrun-$(Get-Random -Minimum 1000000000 -Maximum 9999999999)"
                if ($ReplaceSG) {
                    Write-Log "Dry run: Would delete existing security group '$groupName' if it exists." "INFO"
                }
                $isNewGroup = $true
            } else {
                try {
                    $existingGroups = Get-EC2SecurityGroup -Filter @(
                        @{Name="group-name";Values=$groupName},
                        @{Name="vpc-id";Values=$vpcId}
                    ) -ProfileName $profileName -Region $region -ErrorAction Stop
                    if ($existingGroups.Count -eq 1) {
                        $securityGroupId = $existingGroups[0].GroupId
                        Write-Log "Found existing security group '$groupName' with ID: $securityGroupId in VPC $vpcId." "INFO"
                        if ($ReplaceSG) {
                            Write-Log "ReplaceSG specified. Attempting to delete security group '$groupName' (ID: $securityGroupId)." "INFO"
                            try {
                                Remove-EC2SecurityGroup -GroupId $securityGroupId -ProfileName $profileName -Region $region -Force -ErrorAction Stop
                                Write-Log "Successfully deleted security group '$groupName' (ID: $securityGroupId)." "INFO"
                                $securityGroupId = $null
                                $isNewGroup = $true
                            } catch {
                                Write-Log "Failed to delete security group '$groupName' (ID: $securityGroupId). Error: $($_.Exception.Message)" "ERROR"
                                if ($_.Exception.Message -match "DependencyViolation") {
                                    Write-Log "Security group '$groupName' is in use (e.g., referenced by another group or attached to a resource). Cannot replace it." "ERROR"
                                }
                                continue
                            }
                        }
                    } elseif ($existingGroups.Count -gt 1) {
                        Write-Log "Multiple security groups found with name '$groupName' in VPC $vpcId. Cannot proceed due to ambiguity." "ERROR"
                        continue
                    }
                    if (-not $securityGroupId) {
                        Write-Log "Security group '$groupName' does not exist in VPC $vpcId or was deleted. Creating new security group." "INFO"
                        $maxRetries = 3
                        $retryCount = 0
                        $newGroup = $null
                        while ($retryCount -lt $maxRetries -and -not $securityGroupId) {
                            try {
                                $retryCount++
                                Write-Log "Attempt $retryCount of $maxRetries to create security group '$groupName'." "DEBUG"
                                $newGroup = New-EC2SecurityGroup -GroupName $groupName -Description $groupDescription -VpcId $vpcId -ProfileName $profileName -Region $region -ErrorAction Stop
                                Write-Log "New-EC2SecurityGroup response: $(ConvertTo-Json -InputObject $newGroup -Depth 3 -Compress)" "DEBUG"
                                Write-Log "New-EC2SecurityGroup response type: $($newGroup.GetType().FullName)" "DEBUG"
                                if ($newGroup -is [string] -and $newGroup -match '^sg-') {
                                    $securityGroupId = $newGroup
                                } elseif ($newGroup.PSObject.Properties['GroupId'] -and $newGroup.GroupId -match '^sg-') {
                                    $securityGroupId = $newGroup.GroupId
                                }
                                if ($securityGroupId) {
                                    Write-Log "Successfully created security group '$groupName' with ID: $securityGroupId" "INFO"
                                    $isNewGroup = $true
                                    break
                                } else {
                                    Write-Log "New-EC2SecurityGroup did not return a valid GroupId for '$groupName' on attempt $retryCount." "WARN"
                                }
                            } catch {
                                Write-Log "Failed to create security group '$groupName' on attempt $retryCount. Error: $($_.Exception.Message)" "ERROR"
                                if ($_.Exception.Message -match "InvalidGroup.Duplicate|already exists") {
                                    Write-Log "Security group '$groupName' already exists. Attempting to retrieve GroupId." "INFO"
                                    break
                                }
                                if ($retryCount -eq $maxRetries) {
                                    Write-Log "Max retries reached for creating security group '$groupName'." "ERROR"
                                    break
                                }
                                Start-Sleep -Seconds 2
                            }
                        }
                        if (-not $securityGroupId) {
                            Write-Log "Attempting to retrieve GroupId for '$groupName' via Get-EC2SecurityGroup." "INFO"
                            try {
                                Start-Sleep -Seconds 2
                                $retrievedGroups = Get-EC2SecurityGroup -Filter @(
                                    @{Name="group-name";Values=$groupName},
                                    @{Name="vpc-id";Values=$vpcId}
                                ) -ProfileName $profileName -Region $region -ErrorAction Stop
                                if ($retrievedGroups.Count -eq 1) {
                                    $securityGroupId = $retrievedGroups[0].GroupId
                                    Write-Log "Successfully retrieved GroupId '$securityGroupId' for security group '$groupName'." "INFO"
                                    $isNewGroup = ($retrievedGroups[0].GroupId -eq $newGroup -or $retrievedGroups[0].GroupId -eq $newGroup.GroupId)
                                } else {
                                    Write-Log "Failed to retrieve GroupId for '$groupName'. Found $($retrievedGroups.Count) groups." "ERROR"
                                    continue
                                }
                            } catch {
                                Write-Log "Failed to retrieve GroupId for '$groupName' via Get-EC2SecurityGroup. Error: $($_.Exception.Message)" "ERROR"
                                continue
                            }
                        }
                        if (-not $securityGroupId) {
                            Write-Log "Failed to retrieve GroupId for security group '$groupName' after retries and fallback." "ERROR"
                            continue
                        }
                        if (-not $DryRun -and $isNewGroup) {
                            Write-Log "Waiting 2 seconds for security group '$groupName' to propagate." "INFO"
                            Start-Sleep -Seconds 2
                        }
                    }
                } catch {
                    Write-Log "Failed to check or create security group '$groupName'. Error: $($_.Exception.Message)" "ERROR"
                    continue
                }
            }

            # Validate securityGroupId
            if (-not $DryRun -and -not $securityGroupId) {
                Write-Log "Security group ID is null for group '$groupName'. Cannot proceed with rule addition." "ERROR"
                continue
            }

            # Update Excel with SecurityGroupId
            if (-not $DryRun -and $securityGroupId) {
                Update-ExcelWithSecurityGroupId -ExcelFilePath $ExcelFilePath -GroupName $groupName -AccountId $accountId -VpcId $vpcId -SecurityGroupId $securityGroupId
            } elseif ($DryRun) {
                Write-Log "Dry run: Would update Excel with SecurityGroupId '$securityGroupId' for GroupName '$groupName', AccountId '$accountId', VpcId '$vpcId'" "INFO"
            }

            # Process rules for the security group
            $rulesProcessed = 0
            $rulesAdded = 0
            foreach ($config in $group.Group) {
                try {
                    # Run preflight checks for each rule
                    $preflightResult = Invoke-PreflightChecks -Config $config -ProfileName $profileName -Region $region
                    if (-not $preflightResult.Success) {
                        Write-Log "Preflight checks failed for rule in group $($config.GroupName). Skipping rule." "ERROR"
                        $rulesProcessed++
                        continue
                    }

                    # Check rule count
                    if (-not $DryRun) {
                        try {
                            $sg = Get-EC2SecurityGroup -GroupId $securityGroupId -ProfileName $profileName -Region $region -ErrorAction Stop
                            $rawSgJson = $sg | ConvertTo-Json -Depth 5 -Compress
                            Write-Log "Raw security group response for '$groupName' (ID: $securityGroupId): $rawSgJson" "DEBUG"
                            $ingressRuleCount = ($sg.IpPermissions | Measure-Object).Count
                            $egressRuleCount = ($sg.IpPermissionsEgress | Measure-Object).Count
                            $totalRuleCount = $ingressRuleCount + $egressRuleCount
                            if ($totalRuleCount -ge 60) {
                                Write-Log "Security group '$groupName' (ID: $securityGroupId) has $totalRuleCount rules, exceeding the maximum of 60." "ERROR"
                                $rulesProcessed++
                                continue
                            }
                            Write-Log "Security group '$groupName' has $totalRuleCount rules (ingress: $ingressRuleCount, egress: $egressRuleCount). Adding new rule." "DEBUG"
                        } catch {
                            Write-Log "Failed to check rule count for group '$groupName'. Error: $($_.Exception.Message)" "ERROR"
                            $rulesProcessed++
                            continue
                        }
                    }

                    # Check for existing rule
                    $ruleExists = $false
                    $descriptionMismatch = $false
                    $existingDescription = $null
                    if (-not $DryRun -and -not $ReplaceSG) {
                        try {
                            $sg = Get-EC2SecurityGroup -GroupId $securityGroupId -ProfileName $profileName -Region $region -ErrorAction Stop
                            $rules = if ($config.RuleType -eq 'ingress') { $sg.IpPermissions } else { $sg.IpPermissionsEgress }
                            Write-Log "Checking $($config.RuleType) rules for group '$groupName' (ID: $securityGroupId). Found $($rules.Count) rules." "DEBUG"
                            foreach ($rule in $rules) {
                                $ruleJson = $rule | ConvertTo-Json -Depth 5 -Compress
                                Write-Log "Evaluating rule: Protocol=$($rule.IpProtocol), FromPort=$($rule.FromPort), ToPort=$($rule.ToPort), Ipv4Ranges=$($rule.Ipv4Ranges | ConvertTo-Json -Compress -Depth 3), Ipv6Ranges=$($rule.Ipv6Ranges | ConvertTo-Json -Compress -Depth 3), PrefixListIds=$($rule.PrefixListIds | ConvertTo-Json -Compress -Depth 3), RawRule=$ruleJson" "DEBUG"

                                $configProtocol = (Convert-ToNormalizedString $config.Protocol)
                                $ruleProtocol = if ($null -eq $rule.IpProtocol -or $rule.IpProtocol -eq "-1") { "all" } else { (Convert-ToNormalizedString $rule.IpProtocol) }
                                $configFromPort = [int]($config.FromPort ?? -1)
                                $configToPort = [int]($config.ToPort ?? -1)
                                $ruleFromPort = [int]($rule.FromPort ?? -1)
                                $ruleToPort = [int]($rule.ToPort ?? -1)

                                if ($ruleProtocol -eq $configProtocol -and
                                    $ruleFromPort -eq $configFromPort -and
                                    $ruleToPort -eq $configToPort) {
                                    if ($config.Source -match '^sg-') {
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
                                        foreach ($ipRange in $rule.Ipv4Ranges) {
                                            $normalizedCidr = $ipRange.CidrIp ? $ipRange.CidrIp.Trim() : $null
                                            Write-Log "Checking Ipv4Range: CidrIp=$normalizedCidr, Description='$($ipRange.Description)'" "DEBUG"
                                            if ($normalizedCidr -eq $config.Source.Trim()) {
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
                                                    Write-Log "Default egress rule (all -1 -1 0.0.0.0/0) exists for group '$groupName' with description '$($ipRange.Description)'. Skipping addition." "INFO"
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
                                    if ($ruleExists) { break }
                                }
                            }
                            if ($ruleExists) {
                                Write-Log "Rule already exists for group '$groupName': $($config.RuleType) $($config.Protocol) $($config.FromPort)-$($config.ToPort) $($config.Source)." "INFO"
                                if ($descriptionMismatch) {
                                    Write-Log "Description mismatch for rule in group '$groupName': Excel description '$($config.Description)' does not match existing description '$existingDescription'." "WARN"
                                }
                                $rulesProcessed++
                                continue
                            }
                        } catch {
                            Write-Log "Failed to check existing rules for group '$groupName'. Error: $($_.Exception.Message)" "ERROR"
                            $rulesProcessed++
                            continue
                        }
                    }

                    # Add new rule
                    Write-Log "Adding $($config.RuleType) rule to group '$groupName': $($config.Protocol) $($config.FromPort)-$($config.ToPort) $($config.Source) with description '$($config.Description)'" "INFO"
                    if ($DryRun) {
                        Write-Log "Dry run: Would add $($config.RuleType) rule to group '$groupName' (ID: $securityGroupId): $($config.Protocol) $($config.FromPort)-$($config.ToPort) $($config.Source) with description '$($config.Description)'" "INFO"
                        $rulesProcessed++
                        $rulesAdded++
                    } else {
                        try {
                            if ($config.Source -match '^pl-') {
                                # Use AWS CLI for prefix list rules
                                $json = @"
[
  {
    "IpProtocol": "$($config.Protocol)",
    "FromPort": $($config.FromPort),
    "ToPort": $($config.ToPort),
    "PrefixListIds": [
      {
        "PrefixListId": "$($config.Source)",
        "Description": "$($config.Description)"
      }
    ]
  }
]
"@
                                $command = if ($config.RuleType -eq 'ingress') { "authorize-security-group-ingress" } else { "authorize-security-group-egress" }
                                $commandString = "aws ec2 $command --group-id $securityGroupId --ip-permissions '$json' --profile $profileName --region $region"
                                Write-Log "Executing AWS CLI command: $commandString" "DEBUG"
                                $result = Invoke-Expression -Command $commandString 2>&1
                                if ($LASTEXITCODE -eq 0) {
                                    Write-Log "Successfully added $($config.RuleType) rule to group '$groupName': $($config.Protocol) $($config.FromPort)-$($config.ToPort) $($config.Source) with description '$($config.Description)' via AWS CLI" "INFO"
                                    Write-Log "AWS CLI output: $result" "DEBUG"
                                    $rulesAdded++
                                } else {
                                    Write-Log "Failed to add $($config.RuleType) rule to group '$groupName': $($config.Protocol) $($config.FromPort)-$($config.ToPort) $($config.Source). AWS CLI error: $result" "ERROR"
                                    $rulesProcessed++
                                    continue
                                }
                            } else {
                                # Use PowerShell module for CIDR and security group rules
                                $ipPermission = New-Object Amazon.EC2.Model.IpPermission
                                $ipPermission.IpProtocol = $config.Protocol
                                $ipPermission.FromPort = [int]$config.FromPort
                                $ipPermission.ToPort = [int]$config.ToPort

                                if ($config.Source -match '^sg-') {
                                    $userIdGroupPair = New-Object Amazon.EC2.Model.UserIdGroupPair
                                    $userIdGroupPair.GroupId = $config.Source
                                    $userIdGroupPair.Description = $config.Description
                                    $ipPermission.UserIdGroupPairs = @($userIdGroupPair)
                                } else {
                                    $ipRange = New-Object Amazon.EC2.Model.IpRange
                                    $ipRange.CidrIp = $config.Source
                                    $ipRange.Description = $config.Description
                                    $ipPermission.Ipv4Ranges = @($ipRange)
                                }
                                
                                Write-Log "IpPermission object: $(ConvertTo-Json -InputObject $ipPermission -Depth 5 -Compress)" "DEBUG"
                                
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
                                    Write-Log "Successfully added ingress rule to group '$groupName': $($config.Protocol) $($config.FromPort)-$($config.ToPort) $($config.Source) with description '$($config.Description)'" "INFO"
                                } else {
                                    Grant-EC2SecurityGroupEgress @params
                                    Write-Log "Successfully added egress rule to group '$groupName': $($config.Protocol) $($config.FromPort)-$($config.ToPort) $($config.Source) with description '$($config.Description)'" "INFO"
                                }
                                $rulesAdded++
                            }
                        } catch {
                            Write-Log "Failed to add $($config.RuleType) rule to group '$groupName': $($config.Protocol) $($config.FromPort)-$($config.ToPort) $($config.Source). Error: $($_.Exception.Message)" "ERROR"
                            Write-Log "Error details: Message=$($_.Exception.Message), Type=$($_.Exception.GetType().FullName)" "DEBUG"
                            if ($config.Source -match '^pl-') {
                                Write-Log "AWS CLI command may have failed. Verifying prefix list ID: $($config.Source)" "DEBUG"
                                try {
                                    $prefixListDetails = Get-EC2ManagedPrefixList -PrefixListId $config.Source -ProfileName $profileName -Region $region -ErrorAction Stop
                                    Write-Log "Prefix list details: $(ConvertTo-Json -InputObject $prefixListDetails -Depth 3 -Compress)" "DEBUG"
                                } catch {
                                    Write-Log "Failed to retrieve prefix list details for '$($config.Source)'. Error: $($_.Exception.Message)" "ERROR"
                                }
                            }
                            $rulesProcessed++
                            continue
                        }
                    }
                    $rulesProcessed++
                } catch {
                    Write-Log "Error processing rule for group '$groupName' in Account: ${accountId} (${accountName}), VPC: ${vpcId}: $($config.RuleType) $($config.Protocol) $($config.FromPort)-$($config.ToPort) $($config.Source). Error: $($_.Exception.Message)" "ERROR"
                    Write-Log "Error details: Message=$($_.Exception.Message), Type=$($_.Exception.GetType().FullName)" "DEBUG"
                    $rulesProcessed++
                    continue
                }
            }

            # Log summary of rules processed
            Write-Log "Processed $rulesProcessed rules for group '$groupName' (ID: $securityGroupId), successfully added $rulesAdded rules." "INFO"

            # Verify applied rules
            if (-not $DryRun -and $rulesProcessed -gt 0) {
                Confirm-SecurityGroupRules -GroupId $securityGroupId -GroupName $groupName -ProfileName $profileName -Region $region
            }

            # Apply tags
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
                        Write-Log "Applied $($tags.Count) tags to security group $securityGroupId" "INFO"
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
                $env:AWS_PROFILE = $null
                $env:AWS_REGION = $null
            }
        } catch {
            Write-Log "Error processing security group for Account: $accountId ($accountName), Group: $groupName, VPC: $vpcId. Error: $($_.Exception.Message)" "ERROR"
            if (-not $DryRun) {
                Clear-AWSCredential -ErrorAction SilentlyContinue
                Clear-DefaultAWSRegion -ErrorAction SilentlyContinue
                $env:AWS_PROFILE = $null
                $env:AWS_REGION = $null
            }
            continue
        }
    }

    Write-Log "Security group creation process completed" "INFO"

} catch {
    Write-Log "Fatal error: $($_.Exception.Message)" "ERROR"
    Write-Log "Error details: Message=$($_.Exception.Message), Type=$($_.Exception.GetType().FullName)" "DEBUG"
    if (-not $DryRun) {
        $env:AWS_PROFILE = $null
        $env:AWS_REGION = $null
    }
    exit 1
}