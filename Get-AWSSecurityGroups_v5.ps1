#Requires -Version 5.1
#Requires -Modules @{ModuleName="AWS.Tools.Common"; ModuleVersion="4.1.0.0"}, @{ModuleName="AWS.Tools.EC2"; ModuleVersion="4.1.0.0"}, @{ModuleName="AWS.Tools.SecurityToken"; ModuleVersion="4.1.0.0"}, @{ModuleName="AWS.Tools.IdentityManagement"; ModuleVersion="4.1.0.0"}, @{ModuleName="AWS.Tools.ElasticLoadBalancingV2"; ModuleVersion="4.1.0.0"}, @{ModuleName="AWS.Tools.FSx"; ModuleVersion="4.1.0.0"}, @{ModuleName="AWS.Tools.RDS"; ModuleVersion="4.1.0.0"}, @{ModuleName="AWS.Tools.ElastiCache"; ModuleVersion="4.1.0.0"}, @{ModuleName="AWS.Tools.Redshift"; ModuleVersion="4.1.0.0"}, @{ModuleName="AWS.Tools.EFS"; ModuleVersion="4.1.0.0"}, @{ModuleName="AWS.Tools.Lambda"; ModuleVersion="4.1.0.0"}

<#
.SYNOPSIS
    Retrieves all security groups in AWS accounts, enumerates services that use security groups, and checks their usage with counts for each service.
.DESCRIPTION
    This script dynamically identifies AWS services that use security groups (e.g., EC2, RDS, ELB, FSx, API Gateway, etc.), queries their resources to count security group attachments, and reports results in a CSV file. It supports profile filtering, pagination, and logging. Output includes dynamic columns for each service's usage count (e.g., EC2Count, RDSCOUNT, etc.).
.PARAMETER PSModulesPath
    Path to the directory containing AWS.Tools modules (required).
.PARAMETER Region
    Specifies a single AWS region to query (optional; if omitted, uses profile-configured or default region).
.PARAMETER AwsProfiles
    List of AWS profiles to query (optional; if omitted, prompts for selection from filtered profiles).
.PARAMETER ProfileFilter
    Regex pattern to filter AWS profiles (optional; applied to profiles retrieved from Get-AWSCredential).
.PARAMETER DebugPlatform
    Included for consistency (not used).
.PARAMETER OutputFile
    Path for the output CSV file (optional; defaults to a timestamped file in the output directory).
.PARAMETER InteractiveSelection
    Enables interactive profile selection if no profiles are specified (default: $true).
.PARAMETER TestProfilesFirst
    Tests profile connectivity before processing (default: $true).
.EXAMPLE
    .\Get-AWSSecurityGroups.ps1 -PSModulesPath "C:\ProgramFiles\AWS Tools\PowerShell"
    Queries security groups using the default profile with interactive selection.
.EXAMPLE
    .\Get-AWSSecurityGroups.ps1 -PSModulesPath "C:\ProgramFiles\AWS Tools\PowerShell" -Region us-east-1 -ProfileFilter "prod.*"
    Queries security groups in us-east-1 for profiles matching the regex "prod.*".
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, HelpMessage="Path to the directory containing AWS.Tools modules.")]
    [string]$PSModulesPath,
    [Parameter()]
    [string]$Region,
    [Parameter()]
    [string[]]$AwsProfiles,
    [Parameter()]
    [string]$ProfileFilter,
    [Parameter()]
    [bool]$DebugPlatform = $false,
    [Parameter()]
    [string]$OutputFile,
    [Parameter()]
    [bool]$InteractiveSelection = $true,
    [Parameter()]
    [bool]$TestProfilesFirst = $true
)

# Get script directory and set relative paths
$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
$OutputDir = Join-Path $ScriptDir "output"
$LogFilePath = Join-Path $OutputDir "SecurityGroup_Analysis_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Function to write logs
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    switch ($Level.ToUpper()) {
        "INFO"  { Write-Host $logMessage -ForegroundColor Blue }
        "WARN"  { Write-Host $logMessage -ForegroundColor Yellow }
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        default { Write-Host $logMessage }
    }
    Add-Content -Path $LogFilePath -Value $logMessage
}

# Function to validate AWS region
function Get-ValidAWSRegion {
    param(
        [string]$Region,
        [string]$ProfileName
    )
    $validRegions = @(
        "us-east-1", "us-east-2", "us-west-1", "us-west-2",
        "ap-south-1", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
        "ap-southeast-1", "ap-southeast-2", "ca-central-1",
        "eu-central-1", "eu-west-1", "eu-west-2", "eu-west-3",
        "eu-north-1", "sa-east-1"
    )
    if ($Region -and $validRegions -contains $Region) {
        Write-Log "Using provided region: ${Region}" "INFO"
        return $Region
    }
    try {
        $configPath = Join-Path $env:USERPROFILE ".aws\config"
        if (Test-Path $configPath) {
            $configContent = Get-Content -Path $configPath -Raw
            $profileSection = if ($ProfileName) { "\[(profile\s+)?${ProfileName}\]" } else { "\[default\]" }
            if ($configContent -match "(?s)$profileSection.*?\nregion\s*=\s*([^\s#]+)") {
                $configRegion = $matches[2]
                if ($validRegions -contains $configRegion) {
                    Write-Log "Using region from profile ${ProfileName} in config: ${configRegion}" "INFO"
                    return $configRegion
                }
            }
        }
    } catch {
        Write-Log "Failed to parse region from config for profile ${ProfileName}: $($_.Exception.Message)" "WARN"
    }
    if ($env:AWS_DEFAULT_REGION -and $validRegions -contains $env:AWS_DEFAULT_REGION) {
        Write-Log "Using region from AWS_DEFAULT_REGION: $env:AWS_DEFAULT_REGION" "INFO"
        return $env:AWS_DEFAULT_REGION
    }
    $defaultRegion = "eu-west-1"
    Write-Log "No valid region found for profile ${ProfileName}. Using default region: ${defaultRegion}" "WARN"
    return $defaultRegion
}

# Function to sanitize strings for filenames and column names
function Sanitize-String {
    param([string]$InputString)
    try {
        $fileName = [System.IO.Path]::GetFileName($InputString)
        $directory = [System.IO.Path]::GetDirectoryName($InputString)
        $sanitizedFileName = $fileName -replace '[^a-zA-Z0-9]', '_'
        $sanitized = if ($directory) { Join-Path $directory $sanitizedFileName } else { $sanitizedFileName }
        Write-Log "Sanitized string '${InputString}' to '${sanitized}' using -replace" "INFO"
        return $sanitized
    } catch {
        Write-Log "Error with -replace on '${InputString}': $($_.Exception.Message). Using regex fallback." "ERROR"
        $sanitizedFileName = [regex]::Replace([System.IO.Path]::GetFileName($InputString), '[^a-zA-Z0-9]', '_')
        $sanitized = if ($directory) { Join-Path $directory $sanitizedFileName } else { $sanitizedFileName }
        Write-Log "Sanitized string '${InputString}' to '${sanitized}' using regex" "INFO"
        return $sanitized
    }
}

# Function to get SSO role name
function Get-SSORoleName {
    param(
        [string]$ProfileName,
        [string]$Region
    )
    try {
        $configPath = Join-Path $env:USERPROFILE ".aws\config"
        if (Test-Path $configPath) {
            $configContent = Get-Content -Path $configPath -Raw
            $profileSection = if ($ProfileName) { "\[(profile\s+)?${ProfileName}\]" } else { "\[default\]" }
            if ($configContent -match "(?s)$profileSection.*?\nsso_role_name\s*=\s*([^\s#]+)") {
                $ssoRoleName = $matches[2]
                Write-Log "Retrieved SSO role name '${ssoRoleName}' from config for profile ${ProfileName}" "INFO"
                return $ssoRoleName
            }
        }
        if ($ProfileName -or $Region) {
            $identity = Get-STSCallerIdentity -ProfileName $ProfileName -Region $Region -ErrorAction Stop
            if ($identity.Arn -match 'assumed-role/([^/]+)/') {
                $ssoRoleName = $matches[1]
                Write-Log "Retrieved SSO role name '${ssoRoleName}' from ARN for profile ${ProfileName}" "INFO"
                return $ssoRoleName
            }
        }
        Write-Log "Could not determine SSO role for profile ${ProfileName}. Using 'Unknown'." "WARN"
        return "Unknown"
    } catch {
        Write-Log "Error retrieving SSO role for profile ${ProfileName}: $($_.Exception.Message). Using 'Unknown'." "WARN"
        return "Unknown"
    }
}

# Function to get profile for a given account ID
function Get-ProfileForAccount {
    param(
        [string]$AccountId,
        [string]$Region,
        [string[]]$AvailableProfiles,
        [hashtable]$AccountProfileCache
    )
    if (-not $AccountId -or $AccountId -eq 'N/A') {
        Write-Log "No valid AccountId provided for profile lookup" "WARN"
        return $null
    }
    $cacheKey = "${AccountId}:${Region}"
    if ($AccountProfileCache.ContainsKey($cacheKey)) {
        Write-Log "Retrieved profile for account ${AccountId} from cache: $($AccountProfileCache[$cacheKey])" "DEBUG"
        return $AccountProfileCache[$cacheKey]
    }
    $configPath = Join-Path $env:USERPROFILE ".aws\config"
    $allProfiles = @()
    if (Test-Path $configPath) {
        try {
            $configContent = Get-Content -Path $configPath -Raw
            $profileMatches = [regex]::Matches($configContent, '(?s)\[(profile\s+)?([^\]]+)\](.*?)(?=\[|$)', 'IgnoreCase')
            foreach ($match in $profileMatches) {
                $profileName = $match.Groups[2].Value.Trim()
                $profileContent = $match.Groups[3].Value
                $allProfiles += [PSCustomObject]@{
                    ProfileName = $profileName
                    Content = $profileContent
                }
            }
            Write-Log "Loaded $($allProfiles.Count) profiles from AWS config file" "INFO"
        } catch {
            Write-Log "Failed to parse AWS config file: $($_.Exception.Message)" "ERROR"
        }
    } else {
        Write-Log "AWS config file not found at ${configPath}" "WARN"
    }
    $profilesToCheck = @($AvailableProfiles + ($allProfiles | Select-Object -ExpandProperty ProfileName) | Sort-Object -Unique)
    Write-Log "Checking profiles for account ${AccountId}: $($profilesToCheck -join ', ')" "DEBUG"
    foreach ($profile in $profilesToCheck) {
        try {
            $identity = Get-STSCallerIdentity -ProfileName $profile -Region $Region -ErrorAction Stop
            if ($identity.Account -eq $AccountId) {
                $AccountProfileCache[$cacheKey] = $profile
                Write-Log "Mapped account ${AccountId} to profile ${profile} via Get-STSCallerIdentity" "INFO"
                return $profile
            }
        } catch {
            Write-Log "Failed to get identity for profile ${profile}: $($_.Exception.Message)" "DEBUG"
            $profileConfig = $allProfiles | Where-Object { $_.ProfileName -eq $profile }
            if ($profileConfig -and $profileConfig.Content -match 'sso_account_id\s*=\s*([^\s#]+)') {
                $ssoAccountId = $matches[1]
                if ($ssoAccountId -eq $AccountId) {
                    Write-Log "Profile ${profile} matches sso_account_id ${AccountId}. Attempting SSO login." "INFO"
                    try {
                        $process = Start-Process -FilePath "aws" -ArgumentList "sso login --profile ${profile}" -NoNewWindow -PassThru -Wait
                        if ($process.ExitCode -eq 0) {
                            Write-Log "SSO login successful for profile ${profile}" "INFO"
                            $identity = Get-STSCallerIdentity -ProfileName $profile -Region $Region -ErrorAction Stop
                            if ($identity.Account -eq $AccountId) {
                                $AccountProfileCache[$cacheKey] = $profile
                                Write-Log "Mapped account ${AccountId} to profile ${profile} after SSO login" "INFO"
                                return $profile
                            } else {
                                Write-Log "SSO login for profile ${profile} did not match account ${AccountId}" "WARN"
                            }
                        } else {
                            Write-Log "SSO login failed for profile ${profile}: Exit code $($process.ExitCode)" "ERROR"
                        }
                    } catch {
                        Write-Log "Failed to perform SSO login for profile ${profile}: $($_.Exception.Message)" "ERROR"
                    }
                }
            }
        }
    }
    Write-Log "No profile found for account ${AccountId} after checking all profiles" "WARN"
    return $null
}

# Function to enumerate AWS services that use security groups
function Get-SecurityGroupServices {
    param(
        [string]$ProfileName,
        [string]$Region
    )
    $services = @{}
    $displayProfileName = if ($ProfileName) { $ProfileName } else { 'Default' }
    Write-Log "Enumerating AWS services that use security groups for profile ${displayProfileName} in region ${Region}" "INFO"

    # Predefined services known to use security groups
    $knownServices = @{
        "EC2" = @{
            Cmdlet = "Get-EC2Instance"
            Module = "AWS.Tools.EC2"
            Permission = "ec2:DescribeInstances"
            GetSecurityGroups = {
                param($resource, $params)
                $resource.Instances | ForEach-Object { $_.SecurityGroups } | Select-Object -ExpandProperty GroupId
            }
            Count = {
                param($resources)
                ($resources.Instances | Measure-Object).Count
            }
        }
        "ENI" = @{
            Cmdlet = "Get-EC2NetworkInterface"
            Module = "AWS.Tools.EC2"
            Permission = "ec2:DescribeNetworkInterfaces"
            GetSecurityGroups = {
                param($resource, $params)
                $resource | ForEach-Object { $_.Groups } | Select-Object -ExpandProperty GroupId
            }
            Count = {
                param($resources)
                ($resources | Measure-Object).Count
            }
        }
        "ELB" = @{
            Cmdlet = "Get-ELB2LoadBalancer"
            Module = "AWS.Tools.ElasticLoadBalancingV2"
            Permission = "elasticloadbalancing:DescribeLoadBalancers"
            GetSecurityGroups = {
                param($resource, $params)
                $resource | ForEach-Object { $_.SecurityGroups }
            }
            Count = {
                param($resources)
                ($resources | Measure-Object).Count
            }
        }
        "FSx" = @{
            Cmdlet = "Get-FSxFileSystem"
            Module = "AWS.Tools.FSx"
            Permission = "fsx:DescribeFileSystems"
            GetSecurityGroups = {
                param($resource, $params)
                $resource | ForEach-Object {
                    $fs = $_
                    $fs.NetworkInterfaceIds | ForEach-Object {
                        $eni = Get-EC2NetworkInterface -NetworkInterfaceId $_ @params -ErrorAction Stop
                        $eni.Groups
                    }
                } | Select-Object -ExpandProperty GroupId
            }
            Count = {
                param($resources)
                ($resources | Measure-Object).Count
            }
        }
        "RDS" = @{
            Cmdlet = "Get-RDSDBInstance"
            Module = "AWS.Tools.RDS"
            Permission = "rds:DescribeDBInstances"
            GetSecurityGroups = {
                param($resource, $params)
                $resource | ForEach-Object { $_.VpcSecurityGroups } | Where-Object { $_.Status -eq "active" } | Select-Object -ExpandProperty VpcSecurityGroupId
            }
            Count = {
                param($resources)
                ($resources | Measure-Object).Count
            }
        }
        "ElastiCache" = @{
            Cmdlet = "Get-ECCluster"
            Module = "AWS.Tools.ElastiCache"
            Permission = "elasticache:DescribeCacheClusters"
            GetSecurityGroups = {
                param($resource, $params)
                $resource | Where-Object { $_.CacheClusterStatus -eq "available" } | ForEach-Object { $_.SecurityGroups } | Select-Object -ExpandProperty SecurityGroupId
            }
            Count = {
                param($resources)
                ($resources | Where-Object { $_.CacheClusterStatus -eq "available" } | Measure-Object).Count
            }
        }
        "Redshift" = @{
            Cmdlet = "Get-RSCluster"
            Module = "AWS.Tools.Redshift"
            Permission = "redshift:DescribeClusters"
            GetSecurityGroups = {
                param($resource, $params)
                $resource | ForEach-Object { $_.VpcSecurityGroups } | Where-Object { $_.Status -eq "active" } | Select-Object -ExpandProperty VpcSecurityGroupId
            }
            Count = {
                param($resources)
                ($resources | Measure-Object).Count
            }
        }
        "EFS" = @{
            Cmdlet = "Get-EFSMountTarget"
            Module = "AWS.Tools.EFS"
            Permission = "elasticfilesystem:DescribeMountTargets"
            GetSecurityGroups = {
                param($resource, $params)
                $resource | ForEach-Object { $_.SecurityGroups }
            }
            Count = {
                param($resources)
                ($resources | Measure-Object).Count
            }
        }
        "Lambda" = @{
            Cmdlet = "Get-LMFunctionList"
            Module = "AWS.Tools.Lambda"
            Permission = "lambda:ListFunctions"
            GetSecurityGroups = {
                param($resource, $params)
                $resource | Where-Object { $_.VpcConfig -and $_.VpcConfig.VpcId } | ForEach-Object { $_.VpcConfig.SecurityGroupIds }
            }
            Count = {
                param($resources)
                ($resources | Where-Object { $_.VpcConfig -and $_.VpcConfig.VpcId } | Measure-Object).Count
            }
        }
        "TransitGateway" = @{
            Cmdlet = "Get-EC2TransitGatewayAttachment"
            Module = "AWS.Tools.EC2"
            Permission = "ec2:DescribeTransitGatewayAttachments"
            GetSecurityGroups = {
                param($resource, $params)
                $sgIds = @()
                foreach ($attachment in $resource) {
                    if ($attachment.ResourceType -eq 'vpc' -and $attachment.ResourceId) {
                        $subnets = Get-EC2Subnet -Filter @{Name="vpc-id";Values=$attachment.ResourceId} @params -ErrorAction Stop
                        foreach ($subnet in $subnets) {
                            $eniParams = @{ Filter = @{Name="subnet-id";Values=$subnet.SubnetId} } + $params
                            $enis = Get-EC2NetworkInterface @eniParams -ErrorAction Stop
                            foreach ($eni in $enis) {
                                if ($eni.Description -match "Transit Gateway") {
                                    $sgIds += $eni.Groups | Select-Object -ExpandProperty GroupId
                                }
                            }
                        }
                    }
                }
                $sgIds
            }
            Count = {
                param($resources)
                $count = 0
                foreach ($attachment in $resources) {
                    if ($attachment.ResourceType -eq 'vpc' -and $attachment.ResourceId) {
                        $subnets = Get-EC2Subnet -Filter @{Name="vpc-id";Values=$attachment.ResourceId} @params -ErrorAction Stop
                        foreach ($subnet in $subnets) {
                            $eniParams = @{ Filter = @{Name="subnet-id";Values=$subnet.SubnetId} } + $params
                            $enis = Get-EC2NetworkInterface @eniParams -ErrorAction Stop
                            $count += ($enis | Where-Object { $_.Description -match "Transit Gateway" } | Measure-Object).Count
                        }
                    }
                }
                $count
            }
        }
    }

    # Add known services to the list
    foreach ($serviceName in $knownServices.Keys) {
        try {
            if (Get-Command -Name $knownServices[$serviceName].Cmdlet -ModuleName $knownServices[$serviceName].Module -ErrorAction Stop) {
                $services[$serviceName] = $knownServices[$serviceName]
                Write-Log "Added service ${serviceName} to check list" "INFO"
            } else {
                Write-Log "Cmdlet $($knownServices[$serviceName].Cmdlet) not found in module $($knownServices[$serviceName].Module). Skipping service ${serviceName}." "WARN"
            }
        } catch {
            Write-Log "Error checking cmdlet for service ${serviceName}: $($_.Exception.Message). Skipping." "WARN"
        }
    }

    # Discover VPC endpoint services
    try {
        $nextToken = $null
        do {
            $params = @{
                ProfileName = $ProfileName
                Region = $Region
                ErrorAction = 'Stop'
            }
            if ($nextToken) { $params.NextToken = $nextToken }
            $vpcEndpoints = Get-EC2VpcEndpoint @params
            foreach ($endpoint in $vpcEndpoints) {
                $serviceName = $endpoint.ServiceName -replace "^com\.amazonaws\.[^\.]+\.", ""
                $sanitizedServiceName = Sanitize-String -InputString $serviceName
                if (-not $services.ContainsKey($sanitizedServiceName)) {
                    $services[$sanitizedServiceName] = @{
                        Cmdlet = "Get-EC2VpcEndpoint"
                        Module = "AWS.Tools.EC2"
                        Permission = "ec2:DescribeVpcEndpoints"
                        GetSecurityGroups = {
                            param($resource, $params)
                            $targetService = $serviceName
                            $resource | Where-Object { $_.ServiceName -eq $targetService } | ForEach-Object { $_.Groups } | Select-Object -ExpandProperty GroupId
                        }
                        Count = {
                            param($resources)
                            ($resources | Where-Object { $_.ServiceName -eq $targetService } | Measure-Object).Count
                        }
                    }
                    Write-Log "Added VPC endpoint service ${sanitizedServiceName} to check list" "INFO"
                }
            }
            $nextToken = $vpcEndpoints.NextToken
        } while ($nextToken)
    } catch {
        Write-Log "Error discovering VPC endpoint services: $($_.Exception.Message)" "ERROR"
        if ($_.Exception.Message -match "is not authorized") {
            Write-Log "Check if the profile has 'ec2:DescribeVpcEndpoints' permission" "WARN"
        }
    }

    Write-Log "Found $($services.Count) services that may use security groups: $($services.Keys -join ', ')" "INFO"
    return $services
}

# Function to build security group attachment cache with counts
function Build-SecurityGroupAttachmentCache {
    param(
        [string]$ProfileName,
        [string]$Region,
        [hashtable]$Services
    )
    $attachmentCache = @{}
    $displayProfileName = if ($ProfileName) { $ProfileName } else { 'Default' }
    
    # Initialize attachment cache for each security group
    function Initialize-SgCache {
        param([string]$sgId)
        if (-not $attachmentCache.ContainsKey($sgId)) {
            $attachmentCache[$sgId] = @{}
            foreach ($service in $Services.Keys) {
                $attachmentCache[$sgId][$service] = 0
            }
        }
    }

    # Common parameters for API calls
    $params = @{
        ProfileName = $ProfileName
        Region = $Region
        ErrorAction = 'Stop'
    }

    foreach ($serviceName in $Services.Keys) {
        try {
            $nextToken = $null
            do {
                $callParams = $params.Clone()
                if ($nextToken) { $callParams.NextToken = $nextToken }
                $resources = & $Services[$serviceName].Cmdlet @callParams
                $sgIds = & $Services[$serviceName].GetSecurityGroups -resource $resources -params $callParams
                foreach ($sgId in $sgIds) {
                    if ($sgId) {
                        Initialize-SgCache -sgId $sgId
                        $attachmentCache[$sgId][$serviceName] += (& $Services[$serviceName].Count -resources $resources)
                    }
                }
                $nextToken = $resources.NextToken
            } while ($nextToken)
            Write-Log "Cached $($attachmentCache.Count) security groups from ${serviceName} for profile ${displayProfileName}" "INFO"
        } catch {
            Write-Log "Error caching security groups from ${serviceName} for profile ${displayProfileName}: $($_.Exception.Message)" "ERROR"
            if ($_.Exception.Message -match "is not authorized") {
                Write-Log "Check if the profile has '$($Services[$serviceName].Permission)' permission" "WARN"
            }
        }
    }

    Write-Log "Built attachment cache with $($attachmentCache.Count) security groups for profile ${displayProfileName}" "INFO"
    return $attachmentCache
}

# Function to process security groups for a single profile
function Get-SecurityGroupsForProfile {
    param(
        [string]$ProfileName,
        [string]$Region,
        [hashtable]$AccountProfileCache,
        [string[]]$AvailableProfiles,
        [hashtable]$Services
    )
    $DisplayProfileName = if ($ProfileName) { $ProfileName } else { 'Default' }
    Write-Log "Processing profile: ${DisplayProfileName}" "INFO"
    try {
        $identity = Get-STSCallerIdentity -ProfileName $ProfileName -Region $Region -ErrorAction Stop
        $accountId = $identity.Account
        try {
            $accountName = (Get-IAMAccountAlias -ProfileName $ProfileName -Region $Region -ErrorAction Stop) | Select-Object -First 1
            if (-not $accountName) {
                if ($ProfileName) {
                    $accountName = $ProfileName -replace '^sso-' -replace '-nonprivFujitsuCSA$', ''
                    Write-Log "No account alias found for profile ${DisplayProfileName}. Derived AccountName '${accountName}' from ProfileName." "INFO"
                } else {
                    $accountName = 'Default'
                    Write-Log "No account alias found for default profile. Using 'Default' as AccountName." "INFO"
                }
            }
        } catch {
            Write-Log "Failed to get account alias for profile ${DisplayProfileName}: $($_.Exception.Message)." "WARN"
            if ($ProfileName) {
                $accountName = $ProfileName -replace '^sso-' -replace '-nonprivFujitsuCSA$', ''
                Write-Log "Derived AccountName '${accountName}' from ProfileName." "INFO"
            } else {
                $accountName = 'Default'
                Write-Log "Using 'Default' as AccountName for default profile." "INFO"
            }
            if (-not $accountName) {
                $accountName = $accountId
                Write-Log "Derived AccountName is empty. Using AccountId '${accountId}' as AccountName." "WARN"
            }
        }
        Write-Log "Account: ${accountName} (${accountId}), ARN: $($identity.Arn)" "INFO"
    } catch {
        Write-Log "Failed to configure credentials for profile ${DisplayProfileName}: $($_.Exception.Message). Skipping." "ERROR"
        return @(), $accountName, $accountId
    }
    $securityGroupsOutput = @()
    try {
        # Build attachment cache
        $attachmentCache = Build-SecurityGroupAttachmentCache -ProfileName $ProfileName -Region $Region -Services $Services
        # Retrieve all security groups in one call with pagination
        $nextToken = $null
        do {
            $params = @{
                ProfileName = $ProfileName
                Region = $Region
                ErrorAction = 'Stop'
            }
            if ($nextToken) { $params.NextToken = $nextToken }
            $securityGroups = Get-EC2SecurityGroup @params
            if (-not $securityGroups) {
                Write-Log "No security groups found for profile ${DisplayProfileName} in region ${Region}" "INFO"
                continue
            }
            Write-Log "Retrieved $($securityGroups.Count) security groups for profile ${DisplayProfileName}" "INFO"
            foreach ($sg in $securityGroups) {
                $counts = $attachmentCache[$sg.GroupId]
                $isAttached = $counts -and ($Services.Keys | ForEach-Object { $counts[$_] -gt 0 } | Where-Object { $_ } | Measure-Object).Count -gt 0
                $outputObject = [PSCustomObject]@{
                    AccountName      = $accountName
                    AccountId        = $accountId
                    SSORole          = Get-SSORoleName -ProfileName $ProfileName -Region $Region
                    Region           = $Region
                    VpcId            = $sg.VpcId
                    SecurityGroupId  = $sg.GroupId
                    GroupName        = $sg.GroupName
                    Description      = $sg.Description
                    IsAttached       = $isAttached
                    Status           = if ($isAttached) { "In Use" } else { "Orphaned" }
                }
                # Dynamically add service count fields
                foreach ($service in $Services.Keys) {
                    $countField = "${service}Count"
                    $outputObject | Add-Member -MemberType NoteProperty -Name $countField -Value (if ($counts) { $counts[$service] } else { 0 })
                }
                $securityGroupsOutput += $outputObject
            }
            $nextToken = $securityGroups.NextToken
        } while ($nextToken)
        return $securityGroupsOutput, $accountName, $accountId
    } catch {
        Write-Log "Error retrieving security groups for profile ${DisplayProfileName}: $($_.Exception.Message)" "ERROR"
        if ($_.Exception.Message -match "is not authorized") {
            Write-Log "Check if the profile has 'ec2:DescribeSecurityGroups' permission" "WARN"
        }
        return @(), $accountName, $accountId
    }
}

# Function for interactive profile selection
function Select-AwsProfilesInteractive {
    param([array]$ProfileList)
    $selectedProfiles = @()
    $currentSelection = 0
    $marked = @{}
    for ($i = 0; $i -lt $ProfileList.Count; $i++) { $marked[$i] = $false }
    function Show-ProfileList {
        param([int]$current, [hashtable]$marked, [array]$profiles)
        Clear-Host
        Write-Host "`nInteractive AWS Profile Selection" -ForegroundColor Cyan
        Write-Host "=================================" -ForegroundColor Cyan
        Write-Host "Use UP/DOWN arrows to navigate, SPACEBAR to select/deselect, ENTER to confirm" -ForegroundColor Yellow
        Write-Host "ESC to cancel, A to select all, C to clear all" -ForegroundColor Yellow
        Write-Host ""
        for ($i = 0; $i -lt $profiles.Count; $i++) {
            $marker = if ($marked[$i]) { "[X]" } else { "[ ]" }
            $arrow = if ($i -eq $current) { ">>>" } else { "   " }
            $color = if ($i -eq $current) { "Yellow" } else { "Gray" }
            Write-Host "$arrow $marker $($i + 1). $($profiles[$i])" -ForegroundColor $color
        }
        $selectedCount = ($marked.Values | Where-Object { $_ }).Count
        Write-Host "`nSelected: $selectedCount profile(s)" -ForegroundColor Green
    }
    do {
        Show-ProfileList -current $currentSelection -marked $marked -profiles $ProfileList
        $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        switch ($key.VirtualKeyCode) {
            38 { $currentSelection = if ($currentSelection -gt 0) { $currentSelection - 1 } else { $ProfileList.Count - 1 } }
            40 { $currentSelection = if ($currentSelection -lt $ProfileList.Count - 1) { $currentSelection + 1 } else { 0 } }
            32 { $marked[$currentSelection] = -not $marked[$currentSelection] }
            65 { for ($i = 0; $i -lt $ProfileList.Count; $i++) { $marked[$i] = $true } }
            67 { for ($i = 0; $i -lt $ProfileList.Count; $i++) { $marked[$i] = $false } }
            13 {
                $selectedIndices = 0..($ProfileList.Count - 1) | Where-Object { $marked[$_] }
                $selectedProfiles = $selectedIndices | ForEach-Object { $ProfileList[$_] }
                if ($selectedProfiles.Count -eq 0) {
                    Write-Host "`nNo profiles selected. Please select at least one profile." -ForegroundColor Red
                    Start-Sleep -Seconds 2
                } else {
                    Clear-Host
                    Write-Host "`nSelected profiles:" -ForegroundColor Green
                    $selectedProfiles | ForEach-Object { Write-Host "  - $_" -ForegroundColor Gray }
                    return $selectedProfiles
                }
            }
            27 { Write-Host "Profile selection cancelled." -ForegroundColor Yellow; exit 0 }
        }
    } while ($true)
}

# Function to test AWS profile connectivity
function Test-AwsProfileConnectivity {
    param([string]$ProfileName, [string]$Region)
    $displayProfileName = if ($ProfileName) { $ProfileName } else { 'Default' }
    Write-Log "Testing profile: ${displayProfileName}" "INFO"
    try {
        if (-not $Region) {
            Write-Log "No region provided for profile ${displayProfileName} during connectivity test" "WARN"
            return $false
        }
        Get-STSCallerIdentity -ProfileName $ProfileName -Region $Region -ErrorAction Stop | Out-Null
        Write-Log "Profile authentication successful for ${displayProfileName}" "INFO"
        return $true
    } catch {
        Write-Log "Profile ${displayProfileName} authentication failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

try {
    # Create output directory
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
        Write-Log "Created output directory: ${OutputDir}" "INFO"
    }

    # Import AWS Tools modules
    try {
        $requiredModules = @(
            "AWS.Tools.Common",
            "AWS.Tools.EC2",
            "AWS.Tools.SecurityToken",
            "AWS.Tools.IdentityManagement",
            "AWS.Tools.ElasticLoadBalancingV2",
            "AWS.Tools.FSx",
            "AWS.Tools.RDS",
            "AWS.Tools.ElastiCache",
            "AWS.Tools.Redshift",
            "AWS.Tools.EFS",
            "AWS.Tools.Lambda"
        )
        foreach ($module in $requiredModules) {
            if (Test-Path (Join-Path $PSModulesPath $module)) {
                Import-Module -Name (Join-Path $PSModulesPath $module) -ErrorAction Stop
                Write-Log "Loaded module ${module}" "INFO"
            } else {
                Write-Log "Module ${module} not found at ${PSModulesPath}. Some services may be skipped." "WARN"
            }
        }
    } catch {
        Write-Log "Failed to import AWS Tools modules from ${PSModulesPath}: $($_.Exception.Message)" "ERROR"
        exit 1
    }

    # Get AWS profiles with filtering
    if (-not $AwsProfiles -or $AwsProfiles.Count -eq 0) {
        $profileList = Get-AWSCredential -ListProfile | Select-Object -ExpandProperty ProfileName
        if ($ProfileFilter) {
            try {
                $profileList = $profileList | Where-Object { $_ -match $ProfileFilter }
                Write-Log "Applied profile filter '$ProfileFilter'. Found $($profileList.Count) matching profiles: $($profileList -join ', ')" "INFO"
            } catch {
                Write-Log "Error applying profile filter '$ProfileFilter': $($_.Exception.Message). Using all profiles." "ERROR"
            }
        }
        if ($profileList.Count -eq 0) {
            Write-Log "No AWS profiles found after filtering. Using default configuration." "WARN"
            $AwsProfiles = @("")
        } elseif ($InteractiveSelection) {
            $AwsProfiles = Select-AwsProfilesInteractive -ProfileList $profileList
        } else {
            Write-Host "`nAvailable AWS Profiles:" -ForegroundColor Cyan
            for ($i = 0; $i -lt $profileList.Count; $i++) {
                $CurrentIndicator = if ($env:AWS_PROFILE -eq $profileList[$i]) { " (current)" } else { "" }
                Write-Host "  $($i + 1). $($profileList[$i])$CurrentIndicator" -ForegroundColor Gray
            }
            Write-Host "  0. Use default profile" -ForegroundColor Gray
            do {
                $Selection = Read-Host "`nSelect AWS profile (0-$($profileList.Count))"
                if ($Selection -eq "0") {
                    $AwsProfiles = @("")
                    Write-Log "Using default AWS profile" "INFO"
                    break
                } elseif ($Selection -match '^\d+$' -and [int]$Selection -ge 1 -and [int]$Selection -le $profileList.Count) {
                    $AwsProfiles = @($profileList[[int]$Selection - 1])
                    Write-Log "Selected profile: $($AwsProfiles[0])" "INFO"
                    break
                } else {
                    Write-Host "Invalid selection. Please enter a number between 0 and $($profileList.Count)." -ForegroundColor Yellow
                }
            } while ($true)
        }
        Write-Log "Found $($profileList.Count) profiles after filtering" "INFO"
    }

    # Test profile connectivity and build account-to-profile mapping
    $accountProfileCache = @{}
    if ($TestProfilesFirst -and $AwsProfiles) {
        Write-Log "Testing AWS profile connectivity and building account-to-profile mapping" "INFO"
        $validProfiles = @()
        foreach ($profile in $AwsProfiles) {
            $currentRegion = Get-ValidAWSRegion -Region $Region -ProfileName $profile
            if (-not $currentRegion) {
                Write-Log "Skipping profile ${profile} due to invalid region" "ERROR"
                continue
            }
            if (Test-AwsProfileConnectivity -ProfileName $profile -Region $currentRegion) {
                $validProfiles += $profile
                try {
                    $identity = Get-STSCallerIdentity -ProfileName $profile -Region $currentRegion -ErrorAction Stop
                    $accountProfileCache["$($identity.Account):$currentRegion"] = $profile
                    Write-Log "Mapped account $($identity.Account) in region ${currentRegion} to profile ${profile}" "INFO"
                } catch {
                    Write-Log "Failed to map account for profile ${profile}: $($_.Exception.Message)" "WARN"
                }
            }
        }
        if ($validProfiles.Count -eq 0) {
            Write-Log "No valid profiles found after connectivity tests. Please check your AWS configuration." "ERROR"
            exit 1
        }
        $AwsProfiles = $validProfiles
        Write-Log "Proceeding with $($validProfiles.Count) valid profiles" "INFO"
    }

    # Initialize output arrays and caches
    $allOutput = @()
    $processedAccounts = @()
    $securityGroupIdsProcessed = @{} # Track processed security groups to avoid duplicates
    $regionsUsed = @() # Track regions used across profiles

    # Process each profile
    foreach ($profileName in $AwsProfiles) {
        $currentRegion = Get-ValidAWSRegion -Region $Region -ProfileName $profileName
        if (-not $currentRegion) {
            Write-Log "No valid region for profile ${profileName}. Skipping." "ERROR"
            continue
        }
        if ($currentRegion -notin $regionsUsed) {
            $regionsUsed += $currentRegion
            Write-Log "Added region ${currentRegion} to regions used" "INFO"
        }
        # Enumerate services for this profile and region
        $services = Get-SecurityGroupServices -ProfileName $profileName -Region $currentRegion
        if (-not $services) {
            Write-Log "No services found that use security groups for profile ${profileName}. Skipping." "WARN"
            continue
        }
        $securityGroups, $accountName, $accountId = Get-SecurityGroupsForProfile -ProfileName $profileName -Region $currentRegion -AccountProfileCache $accountProfileCache -AvailableProfiles $AwsProfiles -Services $services
        if (-not $securityGroups) {
            Write-Log "No security groups or unable to retrieve data for profile ${profileName}" "WARN"
            continue
        }
        $processedAccounts += [PSCustomObject]@{
            SSORole = Get-SSORoleName -ProfileName $profileName -Region $currentRegion
            AccountName = $accountName
            AccountId = $accountId
        }
        foreach ($sg in $securityGroups) {
            if ($securityGroupIdsProcessed.ContainsKey($sg.SecurityGroupId)) {
                Write-Log "Security group $($sg.SecurityGroupId) already processed. Skipping to avoid duplication." "DEBUG"
                continue
            }
            $securityGroupIdsProcessed[$sg.SecurityGroupId] = $true
            $allOutput += $sg
        }
    }

    # Set output file
    if (-not $OutputFile) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        try {
            $regionSafe = if ($regionsUsed.Count -eq 1) { Sanitize-String -InputString $regionsUsed[0] } else { "multiregion" }
            $profileCount = $AwsProfiles.Count
            $OutputFile = Join-Path $OutputDir "security_groups_${profileCount}accounts_${regionSafe}_${timestamp}.csv"
            Write-Log "Generated output filename: ${OutputFile}" "INFO"
        } catch {
            Write-Log "Error generating output filename: $($_.Exception.Message). Using default." "ERROR"
            $OutputFile = Join-Path $OutputDir "security_groups_${timestamp}.csv"
        }
    }

    # Display summary
    Write-Host "`nSecurity Group Analysis Summary" -ForegroundColor Cyan
    Write-Host "==============================" -ForegroundColor Cyan
    Write-Host "Script version: 1.8 (Dynamically enumerate services using security groups)" -ForegroundColor Green
    Write-Host "Profile filter: $(if ($ProfileFilter) { $ProfileFilter } else { 'None' })" -ForegroundColor Green
    Write-Host "Profiles processed: $($AwsProfiles.Count)" -ForegroundColor Green
    Write-Host "Regions used: $($regionsUsed -join ', ')" -ForegroundColor Green
    Write-Host "Total security groups found: $($allOutput.Count)" -ForegroundColor Green
    Write-Host "Unique accounts: $(($allOutput | Select-Object -Unique AccountId).Count)" -ForegroundColor Green
    Write-Host "Log file: ${LogFilePath}" -ForegroundColor Gray
    Write-Host ""

    # Display account summary
    $accountSummary = $allOutput | Group-Object AccountName | Sort-Object Name
    Write-Log "Security Groups by Account:" "INFO"
    foreach ($account in $accountSummary) {
        Write-Log "  $($account.Name): $($account.Count) security groups" "INFO"
    }

    # Display results
    if ($allOutput.Count -eq 0) {
        Write-Log "No security groups were processed successfully across all profiles" "WARN"
        exit 0
    }
    if ($allOutput.Count -le 20) {
        Write-Host "Security Groups Details (All Results):" -ForegroundColor Cyan
        $allOutput | Format-Table -AutoSize
    } else {
        Write-Host "Security Groups Details (First 20 of $($allOutput.Count) results):" -ForegroundColor Cyan
        $allOutput | Select-Object -First 20 | Format-Table -AutoSize
        Write-Host "... and $($allOutput.Count - 20) more security groups. See CSV file for complete results." -ForegroundColor Yellow
    }

    # Export results
    try {
        $allOutput | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Log "Successfully exported security group data to ${OutputFile}" "INFO"
    } catch {
        Write-Log "Failed to export security group data to CSV: $($_.Exception.Message)" "ERROR"
    }

    # Final summary
    Write-Log "FINAL SUMMARY" "INFO"
    Write-Log "Total accounts processed: $($processedAccounts.Count)" "INFO"
    Write-Log "Total security groups found: $($allOutput.Count)" "INFO"
    Write-Log "Regions used: $($regionsUsed -join ', ')" "INFO"
    Write-Log "Output file: ${OutputFile}" "INFO"
    Write-Log "Script completed successfully!" "INFO"

} catch {
    Write-Log "Fatal error: $($_.Exception.Message)" "ERROR"
    exit 1
}